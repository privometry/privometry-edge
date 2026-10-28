package content

import (
	"strings"
	"time"
)

// AllowEntry is one allowlist entry from a policy file (PRD SCAN-09): the
// detectors it covers, narrowed by paths, values or both.
type AllowEntry struct {
	// Detectors are qualified IDs (<pack>:<detector>) or <pack>:* for a
	// whole pack.
	Detectors []string
	// Paths are globs where * matches any text, including /. They match
	// display paths: repo-relative for files in the repo, ~/... for files in
	// the home folder.
	Paths []string
	// Values are exact matched texts, such as example credentials.
	Values  []string
	Reason  string
	Expires time.Time // zero means never
	Source  string    // the policy file, for diagnostics
}

// Allowlist ignores content findings people have checked and accepted. A
// nil Allowlist allows nothing.
type Allowlist struct {
	entries []AllowEntry
}

// NewAllowlist builds an allowlist. Entries without paths or values are
// dropped: an allowlist never turns a detector off everywhere.
func NewAllowlist(entries []AllowEntry) *Allowlist {
	a := &Allowlist{}
	for _, e := range entries {
		if len(e.Detectors) > 0 && (len(e.Paths) > 0 || len(e.Values) > 0) {
			a.entries = append(a.entries, e)
		}
	}
	return a
}

// Len is the number of entries.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.entries)
}

// Entries returns the entries, for checks such as unknown detector IDs.
func (a *Allowlist) Entries() []AllowEntry {
	if a == nil {
		return nil
	}
	return a.entries
}

// Allowed reports whether an entry valid at now covers finding f. text is
// what was scanned, so the matched value can be compared; path is where the
// text lives in display form, or "" for commands, URLs and MCP arguments,
// which path entries never cover.
func (a *Allowlist) Allowed(f Finding, text, path string, now time.Time) bool {
	if a == nil {
		return false
	}
	for _, e := range a.entries {
		if !e.Expires.IsZero() && !now.Before(e.Expires) {
			continue
		}
		if !coversDetector(e.Detectors, f.DetectorID) {
			continue
		}
		if len(e.Paths) > 0 && (path == "" || !anyGlob(e.Paths, path)) {
			continue
		}
		if len(e.Values) > 0 && !hasValue(e.Values, f, text) {
			continue
		}
		return true
	}
	return false
}

// Filter drops the findings the allowlist covers and reports how many.
func (a *Allowlist) Filter(fs []Finding, text, path string, now time.Time) ([]Finding, int) {
	if a.Len() == 0 {
		return fs, 0
	}
	out := fs[:0:0]
	for _, f := range fs {
		if !a.Allowed(f, text, path, now) {
			out = append(out, f)
		}
	}
	return out, len(fs) - len(out)
}

func coversDetector(ids []string, qid string) bool {
	for _, id := range ids {
		if id == qid {
			return true
		}
		if pack, ok := strings.CutSuffix(id, ":*"); ok && strings.HasPrefix(qid, pack+":") {
			return true
		}
	}
	return false
}

func hasValue(values []string, f Finding, text string) bool {
	var candidates []string
	if f.valueEnd > f.valueStart && f.valueEnd <= len(text) {
		candidates = append(candidates, text[f.valueStart:f.valueEnd])
	}
	if f.End > f.Start && f.End <= len(text) {
		candidates = append(candidates, text[f.Start:f.End])
	}
	for _, v := range values {
		for _, c := range candidates {
			if v == c {
				return true
			}
		}
	}
	return false
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if Glob(p, s) {
			return true
		}
	}
	return false
}

// Glob matches s against a policy glob: literal text where * matches any
// sequence of characters, including /.
func Glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, last)
}
