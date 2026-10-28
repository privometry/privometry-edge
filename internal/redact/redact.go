// Package redact removes secrets and personal data from command text, paths
// and URLs before an event is stored for upload. Redaction happens on the
// device; the cloud rejects events where a known secret pattern survives.
//
// Rules are applied in a fixed order so placeholders never overlap:
// private keys, URL credentials, known token formats, authorization headers,
// URL query values, sensitive assignments and flags, emails, then paths.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Context describes where the command ran, so paths can be generalized.
type Context struct {
	Home     string // the user's home directory, for example /home/dev
	RepoRoot string // the repository root, or empty outside a repo
}

type rule struct {
	re   *regexp.Regexp
	repl func(m []string) string
}

func fixed(placeholder string) func([]string) string {
	return func([]string) string { return placeholder }
}

// keep returns the first group followed by placeholder, unless the value
// (group 2) is already a placeholder from an earlier rule.
func keep(placeholder string) func([]string) string {
	return func(m []string) string {
		if isPlaceholder(strings.Trim(m[2], `"'`)) {
			return m[0]
		}
		return m[1] + placeholder
	}
}

var placeholderRE = regexp.MustCompile(`^<[a-z_]+>$`)

func isPlaceholder(s string) bool { return placeholderRE.MatchString(s) }

var rules = []rule{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), fixed("<private_key>")},
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:'"]+:[^\s/@'"]+@`), func(m []string) string { return m[1] + "<credentials>@" }},

	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), fixed("<aws_key>")},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), fixed("<github_token>")},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`), fixed("<github_token>")},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), fixed("<gitlab_token>")},
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), fixed("<slack_token>")},
	{regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b`), fixed("<stripe_key>")},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), fixed("<anthropic_key>")},
	{regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}`), fixed("<openai_key>")},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), fixed("<google_api_key>")},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), fixed("<npm_token>")},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), fixed("<jwt>")},

	// Generic rules run after typed tokens, so a known token keeps its type.
	{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)([^\s'"]+)`), keep("<token>")},
	{regexp.MustCompile(`(?i)([?&](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|sig|signature|code|x-amz-signature|x-amz-credential|x-amz-security-token)=)([^&#\s'"]+)`), keep("<redacted>")},

	// NAME=value where NAME looks sensitive. PWD is the working directory, not a password.
	{regexp.MustCompile(`(?i)\b((?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_]*)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s'"&]+)`), keep("<secret>")},
	{regexp.MustCompile(`(?i)("[a-z0-9_]*(?:password|passwd|secret|token|api_?key|access_?key)[a-z0-9_]*"\s*:\s*)("[^"]*")`), func(m []string) string {
		if isPlaceholder(strings.Trim(m[2], `"`)) {
			return m[0]
		}
		return m[1] + `"<secret>"`
	}},
	{regexp.MustCompile(`(?i)(--?(?:password|passwd|pass|token|secret|api-key|apikey|access-key|auth-token|client-secret)(?:=|\s+))("[^"]*"|'[^']*'|[^\s'"]+)`), keep("<secret>")},

	{regexp.MustCompile(`\b([A-Za-z0-9._%+-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), func(m []string) string {
		if m[1] == "git" { // SSH remotes such as git@github.com:acme/api.git
			return m[0]
		}
		return "<email>"
	}},
}

var (
	homePathRE  = regexp.MustCompile(`~[/\\][^\s'";|&<>()]+`)
	otherHomeRE = regexp.MustCompile(`(/Users|/home)/[^/\s'"<>]+`)
	// Windows profiles: C:\Users\<name>.
	otherWinHomeRE = regexp.MustCompile(`(?i)\b([a-z]:\\Users)\\[^\\\s'"<>]+`)
)

// Redact applies every rule to s.
func Redact(s string, ctx Context) string {
	for _, r := range rules {
		s = r.re.ReplaceAllStringFunc(s, func(match string) string {
			return r.repl(r.re.FindStringSubmatch(match))
		})
	}
	return redactPaths(s, ctx)
}

// Secrets applies every rule except path generalization: secrets and
// personal data are removed, paths are kept with the home folder shown as ~
// and other users' names hidden. Diagnostic bundles use it, since paths are
// what make a log useful.
func Secrets(s, home string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllStringFunc(s, func(match string) string {
			return r.repl(r.re.FindStringSubmatch(match))
		})
	}
	if home != "" {
		s = replacePrefix(s, home, "~")
	}
	return otherUsers(s)
}

// redactPaths keeps paths inside the repo as <repo>/..., keeps system paths,
// and hides where else in the home directory the agent went.
func redactPaths(s string, ctx Context) string {
	if ctx.RepoRoot != "" {
		s = replacePrefix(s, ctx.RepoRoot, "<repo>")
	}
	if ctx.Home != "" {
		s = replacePrefix(s, ctx.Home, "~")
	}
	if ctx.RepoRoot != "" && ctx.Home != "" && (strings.HasPrefix(ctx.RepoRoot, ctx.Home+"/") || strings.HasPrefix(ctx.RepoRoot, ctx.Home+`\`)) {
		s = replacePrefix(s, "~"+strings.TrimPrefix(ctx.RepoRoot, ctx.Home), "<repo>")
	}
	s = homePathRE.ReplaceAllString(s, "~/<redacted_path>")
	return otherUsers(s)
}

// otherUsers hides user names in other people's home folders.
func otherUsers(s string) string {
	s = otherHomeRE.ReplaceAllString(s, "$1/<user>")
	return otherWinHomeRE.ReplaceAllString(s, `$1\<user>`)
}

// replacePrefix replaces path at a path boundary: followed by / or \, the
// end, or a character that cannot be part of a path name.
func replacePrefix(s, path, with string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, path)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(path)
		if end == len(s) || strings.ContainsRune("/\\ \t'\";|&)", rune(s[end])) {
			b.WriteString(s[:i] + with)
		} else {
			b.WriteString(s[:end])
		}
		s = s[end:]
	}
}

// Hash returns hmac-sha256:<hex> of the trimmed value under the
// organization's hash key, for fields at the hashed privacy level.
func Hash(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.TrimSpace(value)))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

var foundRE = regexp.MustCompile(`<([a-z_]+)>`)

// SecretKinds reports which kinds of secret s contains, such as aws_key or
// secret, using the same rules as Redact. Emails and paths are not secrets.
// It returns nil when s holds none.
func SecretKinds(s string) []string {
	redacted := Redact(s, Context{})
	if redacted == s {
		return nil
	}
	var kinds []string
	for _, m := range foundRE.FindAllStringSubmatch(redacted, -1) {
		switch m[1] {
		case "email", "user", "repo", "redacted_path":
			continue
		}
		if !strings.Contains(s, m[0]) { // ignore placeholders already in s
			kinds = append(kinds, m[1])
		}
	}
	return kinds
}
