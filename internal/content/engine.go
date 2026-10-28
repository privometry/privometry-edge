package content

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// PreActionLimit is how much of an action's content is scanned before it
// runs (PRD SCAN-11: 5 ms p95 up to 64 KB). Callers scan the rest after the
// action and raise findings instead of blocking.
const PreActionLimit = 64 << 10

// maxFindings caps findings per detector per scan, so one noisy file cannot
// flood the timeline.
const maxFindings = 20

// Engine runs a set of detector packs.
type Engine struct {
	detectors []*Compiled
	salt      []byte
	keywords  *keywordIndex
	fpKey     atomic.Pointer[fingerprintKey]
}

// fingerprintKey keys credential fingerprints instead of the salt.
type fingerprintKey struct {
	key []byte
	id  string
}

// Options configure an engine.
type Options struct {
	// Salt keys credential fingerprints and path hashes. Without one,
	// findings carry no fingerprint.
	Salt []byte
}

// SetFingerprintKey makes credential fingerprints use key, which id names
// (an enrolled device's organization hash key, so the same secret matches on
// every device of the organization). A nil key goes back to the salt. Path
// hashes keep using the salt.
func (e *Engine) SetFingerprintKey(key []byte, id string) {
	if len(key) == 0 {
		e.fpKey.Store(nil)
		return
	}
	e.fpKey.Store(&fingerprintKey{key: append([]byte(nil), key...), id: id})
}

// FingerprintKeyID names the key credential fingerprints use now, "" for the salt.
func (e *Engine) FingerprintKeyID() string {
	if k := e.fpKey.Load(); k != nil {
		return k.id
	}
	return ""
}

// New builds an engine from loaded packs.
func New(packs []*Pack, opts Options) *Engine {
	e := &Engine{salt: opts.Salt}
	for _, p := range packs {
		e.detectors = append(e.detectors, p.Detectors...)
	}
	// Credentials first: under a time budget they are what blocks a leak.
	sort.SliceStable(e.detectors, func(i, j int) bool {
		return e.detectors[i].Category == CategoryCredential && e.detectors[j].Category != CategoryCredential
	})
	e.keywords = newKeywordIndex(e.detectors)
	return e
}

// Detectors returns every detector the engine runs.
func (e *Engine) Detectors() []*Compiled { return e.detectors }

// Finding is one detector hit.
type Finding struct {
	DetectorID     string
	PackVersion    string
	Title          string
	Category       Category
	Severity       DetectorSeverity
	Confidence     DetectorConfidence
	Source         Source
	SecretType     string
	InjectionLevel string // low, medium or high, for injected and safety-weakening findings
	Line           int    // 1-based
	Start, End     int    // byte offsets of the match in the scanned text
	// Excerpt is the matched line with the secret masked and hidden
	// characters revealed. It stays on the device.
	Excerpt     string
	Fingerprint string // credentials, when the engine has a salt: hmac-sha256:<hex>
	// FingerprintKey names the key of Fingerprint when it is not the salt.
	FingerprintKey string

	kind                 DetectorKind
	valueStart, valueEnd int
}

// Scan runs every detector that applies to source over text.
func (e *Engine) Scan(source Source, text string) []Finding {
	fs, _ := e.ScanWithin(source, text, time.Time{})
	return fs
}

// ScanWithin is Scan with a deadline (zero means none). It stops when the
// deadline passes and reports whether every detector ran; credential
// detectors run first. A caller on the hook path decides on what it found and
// scans again after the action, raising findings instead of blocking.
func (e *Engine) ScanWithin(source Source, text string, deadline time.Time) ([]Finding, bool) {
	if text == "" {
		return nil, true
	}
	late := func() bool { return !deadline.IsZero() && time.Now().After(deadline) }
	complete := true
	hits := e.keywords.find(text, len(e.detectors))
	var ls lines
	var out []Finding
	for di, d := range e.detectors {
		if !d.sources[source] {
			continue
		}
		if late() {
			complete = false
			break
		}
		var spans []span
		if len(d.keywords) == 0 {
			spans = d.spans(text, 0, len(text))
		} else if len(hits[di]) > 0 {
			if ls == nil {
				ls = newLines(text)
			}
			for _, w := range windows(hits[di], ls, len(text)) {
				spans = append(spans, d.spans(text, w[0], w[1])...)
				if len(spans) >= maxFindings {
					spans = spans[:maxFindings]
					break
				}
				if late() {
					complete = false
					break
				}
			}
		}
		for _, s := range spans {
			out = append(out, e.finding(d, source, text, s))
		}
	}
	out = dropGenericDuplicates(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, complete
}

// dropGenericDuplicates removes entropy-based credential findings whose value
// overlaps a provider-specific (pattern) credential finding: a GitHub token
// assigned to GITHUB_TOKEN is one github_token, not also a generic secret.
func dropGenericDuplicates(fs []Finding) []Finding {
	out := fs[:0]
	for _, f := range fs {
		dup := false
		if f.Category == CategoryCredential && f.kind == DetectorKindEntropy {
			for _, g := range fs {
				if g.Category == CategoryCredential && g.kind == DetectorKindPattern && g.valueStart < f.valueEnd && f.valueStart < g.valueEnd {
					dup = true
					break
				}
			}
		}
		if !dup {
			out = append(out, f)
		}
	}
	return out
}

// A keyword window reaches this far before and after the keyword, within its
// line: far enough for any shipped pattern's match around its keyword.
const (
	windowBefore = 128
	windowAfter  = 384
)

// windows returns the parts of the text worth running a pattern on: the
// line around each keyword hit, clipped to windowBefore and windowAfter,
// merged. Patterns only run on short windows, so Go's regexp can use its fast
// backtracking matcher and most of a large input is never examined.
func windows(hits []int, ls lines, n int) [][2]int {
	ws := make([][2]int, 0, len(hits))
	for _, i := range hits { // hits are in text order
		start, end := ls.bounds(i, n)
		start, end = max(start, i-windowBefore), min(end, i+windowAfter)
		if k := len(ws) - 1; k >= 0 && start <= ws[k][1] {
			ws[k][1] = max(ws[k][1], end)
			continue
		}
		ws = append(ws, [2]int{start, end})
	}
	return ws
}

// span is one hit: the whole match and the value inside it (the secret
// group, or the match itself).
type span struct {
	start, end           int
	valueStart, valueEnd int
	reveal               string // hidden text made readable, for the excerpt
}

// spans finds hits in text[from:to], with offsets into the whole text.
func (d *Compiled) spans(text string, from, to int) []span {
	switch d.Kind {
	case DetectorKindPattern:
		return d.patternSpans(text, from, to, nil)
	case DetectorKindEntropy:
		return d.patternSpans(text, from, to, func(v string) bool {
			return len(v) >= d.minLength && entropy(v) >= *d.MinEntropy
		})
	case DetectorKindUnicode:
		return d.unicodeSpans(text) // unicode and structure detectors have no keywords
	case DetectorKindStructure:
		return d.structureSpans(text)
	}
	return nil
}

func (d *Compiled) patternSpans(text string, from, to int, keep func(string) bool) []span {
	var out []span
	if !d.re.MatchString(text[from:to]) {
		return nil // a match test without captures is much cheaper than finding them
	}
	for _, m := range d.re.FindAllStringSubmatchIndex(text[from:to], maxFindings*4) {
		for i := range m {
			if m[i] >= 0 {
				m[i] += from
			}
		}
		vs, ve := m[2*d.secretIdx], m[2*d.secretIdx+1]
		if vs < 0 {
			continue
		}
		v := text[vs:ve]
		if d.allow[v] || d.allow[text[m[0]:m[1]]] || (keep != nil && !keep(v)) {
			continue
		}
		out = append(out, span{start: m[0], end: m[1], valueStart: vs, valueEnd: ve})
		if len(out) == maxFindings {
			break
		}
	}
	return out
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// unicodeClass names the hidden-character class of r, or "". The joiners
// (U+200C, U+200D) and the left-to-right and right-to-left marks are left
// out: emoji sequences and right-to-left scripts use them legitimately.
func unicodeClass(r rune) DetectorUnicode {
	switch {
	case r == 0x200B || r == 0x2060 || (r >= 0x2061 && r <= 0x2064) || r == 0xFEFF || r == 0x180E:
		return DetectorUnicodeZeroWidth
	case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
		return DetectorUnicodeBidiControl
	case r >= 0xE0000 && r <= 0xE007F:
		return DetectorUnicodeTag
	case (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF):
		return DetectorUnicodeVariationSelector
	case (r >= 0xE000 && r <= 0xF8FF) || r >= 0xF0000:
		return DetectorUnicodePrivateUse
	}
	return ""
}

// unicodeSpans reports runs of hidden characters. A leading byte order mark
// is ignored, and a single variation selector (as after an emoji) is not a
// run.
func (d *Compiled) unicodeSpans(text string) []span {
	var out []span
	start, count := -1, 0
	var reveal strings.Builder
	var class DetectorUnicode
	flush := func(end int) {
		if start >= 0 && (class != DetectorUnicodeVariationSelector || count > 1) {
			out = append(out, span{start: start, end: end, valueStart: start, valueEnd: end, reveal: reveal.String()})
		}
		start, count = -1, 0
		reveal.Reset()
	}
	for i := 0; i < len(text); {
		// Every hidden character starts with one of a few UTF-8 lead bytes,
		// so ASCII and most other text is skipped without decoding.
		if b := text[i]; b < 0xE1 || (b > 0xE2 && b < 0xEE) || b > 0xF3 {
			if start >= 0 {
				flush(i)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		c := unicodeClass(r)
		if c == "" || !d.unicode[c] || (i == 0 && r == 0xFEFF) {
			flush(i)
			if len(out) == maxFindings {
				return out
			}
			i += size
			continue
		}
		if start < 0 {
			start, class = i, c
		}
		count++
		if c == DetectorUnicodeTag && r >= 0xE0020 && r <= 0xE007E {
			reveal.WriteRune(r - 0xE0000) // tag characters spell ASCII
		} else {
			fmt.Fprintf(&reveal, "<U+%04X>", r)
		}
		i += size
	}
	flush(len(text))
	return out
}

var (
	htmlCommentRE    = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	markdownImageRE  = regexp.MustCompile(`!\[[^\]\n]*\]\(([^)\s]+)[^)]*\)`)
	printableASCIIRE = regexp.MustCompile(`^[\x09\x0a\x0d\x20-\x7e]*$`)
)

// structureSpans finds the shape and, when the detector has a pattern, keeps
// only spans whose content (decoded, for blobs) matches it.
func (d *Compiled) structureSpans(text string) []span {
	var out []span
	add := func(start, end int, inner, reveal string) {
		if len(out) == maxFindings || end-start < d.minLength {
			return
		}
		if d.re != nil && !d.re.MatchString(inner) {
			return
		}
		if d.allow[text[start:end]] {
			return
		}
		out = append(out, span{start: start, end: end, valueStart: start, valueEnd: end, reveal: reveal})
	}
	switch d.Structure {
	case DetectorStructureHTMLComment:
		for _, m := range htmlCommentRE.FindAllStringSubmatchIndex(text, -1) {
			add(m[0], m[1], text[m[2]:m[3]], "")
		}
	case DetectorStructureBase64Blob:
		for _, m := range runs(text, isBase64, d.minLength) {
			end := m[1]
			for end < len(text) && end-m[1] < 2 && text[end] == '=' {
				end++
			}
			if decoded, ok := decodeBase64(text[m[0]:end]); ok {
				add(m[0], end, decoded, "decodes to: "+clip(decoded, 160))
			}
		}
	case DetectorStructureHexBlob:
		for _, m := range runs(text, isHex, d.minLength) {
			if b, err := hex.DecodeString(text[m[0]:m[1]]); err == nil && printableASCIIRE.Match(b) {
				add(m[0], m[1], string(b), "decodes to: "+clip(string(b), 160))
			}
		}
	case DetectorStructureWhitespaceRun:
		for _, m := range runs(text, func(c byte) bool { return c == ' ' || c == '\t' }, d.minLength) {
			gapStart, gapEnd := m[0], m[1]
			// Mid-line only: indentation and trailing spaces hide nothing.
			if gapStart == 0 || text[gapStart-1] == '\n' || gapEnd == len(text) || text[gapEnd] == '\n' || text[gapEnd] == '\r' {
				continue
			}
			lineEnd := strings.IndexByte(text[gapEnd:], '\n')
			if lineEnd < 0 {
				lineEnd = len(text) - gapEnd
			}
			after := text[gapEnd : gapEnd+lineEnd]
			add(gapStart, gapEnd, after, "text after the gap: "+clip(after, 160))
		}
	case DetectorStructureMarkdownImageURL:
		for _, m := range markdownImageRE.FindAllStringSubmatchIndex(text, -1) {
			add(m[0], m[1], text[m[2]:m[3]], "")
		}
	}
	return out
}

func isBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_'
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// runs returns maximal runs of bytes in the class at least minLen long, in
// one pass: blobs are found without a regular expression.
func runs(text string, in func(byte) bool, minLen int) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && in(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= max(minLen, 16) {
			out = append(out, [2]int{start, i})
		}
		start = -1
	}
	return out
}

// decodeBase64 decodes standard or URL-safe base64 that turns into readable
// text; binary blobs such as images are not instructions.
func decodeBase64(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && utf8.Valid(b) && printableASCIIRE.Match(b) {
			return string(b), true
		}
	}
	return "", false
}

func (e *Engine) finding(d *Compiled, source Source, text string, s span) Finding {
	f := Finding{DetectorID: d.QID, PackVersion: d.Version, Title: d.Title, Category: d.Category, Severity: d.Severity,
		Confidence: d.Confidence, Source: source, SecretType: d.SecretType, Start: s.start, End: s.end,
		kind: d.Kind, valueStart: s.valueStart, valueEnd: s.valueEnd,
		Line: 1 + strings.Count(text[:s.start], "\n")}
	if d.Category == CategoryInjectedInstructions || d.Category == CategorySafetyWeakening {
		f.InjectionLevel = string(d.InjectionLevel)
		if f.InjectionLevel == "" {
			f.InjectionLevel = string(d.Confidence)
		}
	}
	value := text[s.valueStart:s.valueEnd]
	if d.Category == CategoryCredential {
		f.Excerpt = excerpt(text, s.valueStart, s.valueEnd, mask(value))
		if k := e.fpKey.Load(); k != nil {
			f.Fingerprint, f.FingerprintKey = hmacHex(k.key, value), k.id
		} else if len(e.salt) > 0 {
			f.Fingerprint = e.Hash(value)
		}
	} else {
		shown := value
		if s.reveal != "" {
			shown = "[" + s.reveal + "]"
		}
		f.Excerpt = excerpt(text, s.valueStart, s.valueEnd, shown)
	}
	return f
}

// Hash is the salted hash used for path hashes, and for fingerprints when
// no fingerprint key is set.
func (e *Engine) Hash(v string) string { return hmacHex(e.salt, v) }

func hmacHex(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// mask keeps a credential's first four characters, enough to recognize its
// provider, and hides the rest.
func mask(v string) string {
	r := []rune(v)
	if len(r) <= 8 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + "…" + fmt.Sprintf("(%d chars)", len(r))
}

// excerpt is the line around a match, with the match replaced and the line
// cut to about 160 characters.
func excerpt(text string, start, end int, replacement string) string {
	ls := strings.LastIndexByte(text[:start], '\n') + 1
	le := strings.IndexByte(text[end:], '\n')
	if le < 0 {
		le = len(text)
	} else {
		le += end
	}
	before, after := text[ls:start], text[end:le]
	if len(before) > 60 {
		before = "…" + before[len(before)-60:]
	}
	if len(after) > 60 {
		after = after[:60] + "…"
	}
	return strings.TrimSpace(strings.ToValidUTF8(before+replacement+after, "�"))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Summary is what a set of findings means for policy: the content facts.
type Summary struct {
	SecretTypes   []string // sorted, unique
	Injection     string   // none, low, medium, high
	HiddenContent bool
}

var levelOrder = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3}

// Summarize turns findings into content facts.
func Summarize(fs []Finding) Summary {
	s := Summary{Injection: "none"}
	for _, f := range fs {
		switch f.Category {
		case CategoryCredential:
			if f.SecretType != "" && !slices.Contains(s.SecretTypes, f.SecretType) {
				s.SecretTypes = append(s.SecretTypes, f.SecretType)
			}
		case CategoryHiddenContent:
			s.HiddenContent = true
		}
		if levelOrder[f.InjectionLevel] > levelOrder[s.Injection] {
			s.Injection = f.InjectionLevel
		}
	}
	sort.Strings(s.SecretTypes)
	return s
}
