// Package posture checks discovered agent configuration for risky settings.
// Findings name the file and the setting, never a secret's value.
package posture

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/redact"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
	"github.com/privometry/privometry-oss/internal/scanner/parsers"
)

// Finding is one posture issue.
type Finding struct {
	Check    string                `json:"check"`
	Severity contract.Risk         `json:"severity"`
	Agent    contract.AgentProduct `json:"agent"`
	Tier     contract.ConfigTier   `json:"tier,omitempty"`
	Path     string                `json:"path,omitempty"`
	Pointer  string                `json:"pointer,omitempty"`
	Line     int                   `json:"line,omitempty"`
	Message  string                `json:"message"`
	Fix      string                `json:"fix"`
}

// Check describes one posture check, for reports and SARIF rules.
type Check struct {
	ID       string
	Title    string
	Severity contract.Risk
	Help     string
}

// Checks lists every check, in report order. Adapters enable all but
// agent_file_changed, which privometry scan --changed raises for changed
// agent files in a merge or pull request.
var Checks = []Check{
	{"writable_managed_config", "Managed config is writable by other users", contract.RiskCritical,
		"Managed settings override everything a developer configures. If other users can write them, they can install hooks or MCP servers for everyone."},
	{"auto_approve_mode", "Agent runs actions without asking", contract.RiskHigh,
		"The agent is configured to skip permission prompts. Privometry still checks each action, but the agent's own safeguard is off."},
	{"sandbox_disabled", "Agent sandbox is disabled", contract.RiskHigh,
		"The agent runs commands with full access to the machine instead of inside its sandbox."},
	{"secret_in_config", "Secret stored in agent config", contract.RiskHigh,
		"A credential is written in plain text in an agent config file, where agents, MCP servers and anyone with read access can see it."},
	{"project_hook", "Repo defines a hook", contract.RiskMedium,
		"A hook in the repo's config runs a command on your machine when the agent works in this repo. A cloned repo can use this to run code."},
	{"project_mcp_server", "Repo defines an MCP server", contract.RiskMedium,
		"An MCP server declared in the repo starts with the agent's access when you work in this repo."},
	{"unpinned_mcp_server", "MCP server version is not pinned", contract.RiskLow,
		"The server is launched from a package without a fixed version, so a new release, or a hijacked one, runs without review."},
	{"managed_hooks_only_off", "Managed hooks can be bypassed", contract.RiskLow,
		"Managed settings exist but do not restrict hooks to the managed tier, so users and repos can add their own."},
	{"agent_file_changed", "Change to a file coding agents read", contract.RiskMedium,
		"The change adds, edits or deletes a repo file coding agents act on: hooks, permissions or MCP servers (medium), instructions, rules or skills (low), or the repo's Privometry policy (medium). Review it like code, because agents follow it without asking."},
}

// CheckByID returns a check's metadata.
func CheckByID(id string) (Check, bool) {
	for _, c := range Checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// Run applies each adapter's enabled checks to its discovered agent.
func Run(reg *registry.Registry, agents []discover.Agent, env platform.Env, root string) []Finding {
	var out []Finding
	for _, agent := range agents {
		a, ok := reg.Get(agent.Product)
		if !ok {
			continue
		}
		for _, id := range a.PostureChecks {
			fn, ok := checkFuncs[id]
			if !ok {
				continue
			}
			for _, f := range fn(agent, env, root) {
				f.Check, f.Agent = id, agent.Product
				if f.Severity == "" {
					c, _ := CheckByID(id)
					f.Severity = c.Severity
				}
				out = append(out, f)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := rank(out[i].Severity), rank(out[j].Severity); r1 != r2 {
			return r1 > r2
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// Rank orders severities: none 0 to critical 4.
func Rank(r contract.Risk) int { return rank(r) }

func rank(r contract.Risk) int {
	return map[contract.Risk]int{contract.RiskNone: 0, contract.RiskLow: 1, contract.RiskMedium: 2, contract.RiskHigh: 3, contract.RiskCritical: 4}[r]
}

type checkFunc func(discover.Agent, platform.Env, string) []Finding

var checkFuncs = map[string]checkFunc{
	"auto_approve_mode":       autoApprove,
	"sandbox_disabled":        sandboxDisabled,
	"managed_hooks_only_off":  managedHooksOnlyOff,
	"project_mcp_server":      projectMCPServer,
	"unpinned_mcp_server":     unpinnedMCPServer,
	"project_hook":            projectHook,
	"secret_in_config":        secretInConfig,
	"writable_managed_config": writableManagedConfig,
}

func configsHolding(a discover.Agent, kinds ...string) []discover.ConfigFile {
	var out []discover.ConfigFile
	for _, c := range a.Configs {
		if c.Doc == nil {
			continue
		}
		for _, k := range kinds {
			if slices.Contains(c.Holds, k) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func autoApprove(a discover.Agent, _ platform.Env, _ string) []Finding {
	var out []Finding
	for _, c := range configsHolding(a, "settings", "permissions") {
		switch a.Product {
		case contract.AgentProductClaudeCode:
			if parsers.String(parsers.Lookup(c.Doc, "/permissions/defaultMode")) == "bypassPermissions" {
				out = append(out, Finding{Tier: c.Tier, Path: c.Path, Pointer: "/permissions/defaultMode",
					Message: "Claude Code skips every permission prompt (bypassPermissions).",
					Fix:     `Remove "defaultMode": "bypassPermissions", or use "acceptEdits" to auto-approve edits only.`})
			}
			out = append(out, allowsAllShell(c, "/permissions/allow", "Bash", "Claude Code")...)
		case contract.AgentProductCursor:
			out = append(out, allowsAllShell(c, "/permissions/allow", "Shell", "Cursor")...)
		case contract.AgentProductAntigravity:
			// permissions.allow "command(*)" runs every command without asking.
			out = append(out, allowsAllShell(c, "/permissions/allow", "command", "Antigravity")...)
		case contract.AgentProductGeminiCLI:
			// tools.allowed bypasses confirmation; run_shell_command alone covers every command.
			out = append(out, allowsAllShell(c, "/tools/allowed", "run_shell_command", "Gemini CLI")...)
		case contract.AgentProductCodexCLI:
			out = append(out, codexSetting(c, "approval_policy", "never",
				"Codex never asks before running commands (approval_policy = \"never\").",
				`Set approval_policy to "on-request" or "untrusted".`)...)
		}
	}
	return out
}

// allowsAllShell flags an allow rule that approves every shell command.
func allowsAllShell(c discover.ConfigFile, pointer, tool, agent string) []Finding {
	for i, v := range parsers.List(parsers.Lookup(c.Doc, pointer)) {
		switch parsers.String(v) {
		case tool, tool + "(*)", tool + "(*:*)", tool + "(:*)":
			return []Finding{{Tier: c.Tier, Path: c.Path, Pointer: fmt.Sprintf("%s/%d", pointer, i),
				Message: fmt.Sprintf("%s runs every shell command without asking (%s).", agent, parsers.String(v)),
				Fix:     fmt.Sprintf("Replace %q with specific commands, for example %s(npm test:*).", parsers.String(v), tool)}}
		}
	}
	return nil
}

// codexSetting finds key = want at the top level or in any profile.
func codexSetting(c discover.ConfigFile, key, want, message, fix string) []Finding {
	var out []Finding
	if parsers.String(parsers.Lookup(c.Doc, "/"+key)) == want {
		out = append(out, Finding{Tier: c.Tier, Path: c.Path, Pointer: "/" + key, Message: message, Fix: fix})
	}
	profiles := parsers.Map(parsers.Lookup(c.Doc, "/profiles"))
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if parsers.String(parsers.Map(profiles[n])[key]) == want {
			out = append(out, Finding{Tier: c.Tier, Path: c.Path, Pointer: "/profiles/" + n + "/" + key,
				Message: fmt.Sprintf("Profile %q: %s", n, message), Fix: fix})
		}
	}
	return out
}

func sandboxDisabled(a discover.Agent, _ platform.Env, _ string) []Finding {
	if a.Product != contract.AgentProductCodexCLI {
		return nil
	}
	var out []Finding
	for _, c := range configsHolding(a, "settings") {
		out = append(out, codexSetting(c, "sandbox_mode", "danger-full-access",
			"Codex runs commands without its sandbox (sandbox_mode = \"danger-full-access\").",
			`Set sandbox_mode to "workspace-write".`)...)
	}
	return out
}

func managedHooksOnlyOff(a discover.Agent, _ platform.Env, _ string) []Finding {
	if a.Product != contract.AgentProductClaudeCode {
		return nil
	}
	var managed []discover.ConfigFile
	for _, c := range configsHolding(a, "settings") {
		if c.Tier == contract.ConfigTierManaged {
			if v, _ := parsers.Lookup(c.Doc, "/allowManagedHooksOnly").(bool); v {
				return nil
			}
			managed = append(managed, c)
		}
	}
	if len(managed) == 0 {
		return nil
	}
	c := managed[0]
	return []Finding{{Tier: c.Tier, Path: c.Path, Pointer: "/allowManagedHooksOnly",
		Message: "Managed settings exist but users and repos can still add hooks.",
		Fix:     `Set "allowManagedHooksOnly": true in managed settings.`}}
}

func projectMCPServer(a discover.Agent, _ platform.Env, _ string) []Finding {
	var out []Finding
	for _, s := range a.MCPServers {
		if s.Tier == contract.ConfigTierProject {
			out = append(out, Finding{Tier: s.Tier, Path: s.Path, Pointer: s.Pointer,
				Message: fmt.Sprintf("The repo defines MCP server %q (%s).", s.Name, describe(s)),
				Fix:     "Review it before trusting the repo; move servers you rely on to your user config."})
		}
	}
	return out
}

func unpinnedMCPServer(a discover.Agent, _ platform.Env, _ string) []Finding {
	var out []Finding
	for _, s := range a.MCPServers {
		if s.Pinned != nil && !*s.Pinned {
			out = append(out, Finding{Tier: s.Tier, Path: s.Path, Pointer: s.Pointer,
				Message: fmt.Sprintf("MCP server %q runs %s without a pinned version.", s.Name, s.Package),
				Fix:     fmt.Sprintf("Pin a version, for example %s@<version>.", strings.Split(s.Package, "@latest")[0])})
		}
	}
	return out
}

func describe(s discover.MCPServer) string {
	if s.Transport == "http" {
		return s.URL
	}
	return s.Command
}

func projectHook(a discover.Agent, _ platform.Env, _ string) []Finding {
	var out []Finding
	for _, h := range a.Hooks {
		if h.Tier == contract.ConfigTierProject && !h.Privometry {
			out = append(out, Finding{Tier: h.Tier, Path: h.Path, Pointer: "/hooks/" + h.Event,
				Message: fmt.Sprintf("The repo runs a hook on %s: %s", h.Event, h.Command),
				Fix:     "Read the hook before you trust this repo."})
		}
	}
	return out
}

var (
	keyWordRE = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+(?:[^a-z]|$)`)
	dateRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
)

// sensitiveKey reports whether a config key names a credential. Only the last
// word counts, so GITHUB_TOKEN and apiKey match but tokenizer and
// firstTokenDate do not.
func sensitiveKey(key string) bool {
	var words []string
	for _, w := range keyWordRE.FindAllString(key, -1) {
		words = append(words, strings.ToLower(strings.Trim(w, "_-.")))
	}
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	switch last {
	case "password", "passwd", "secret", "token", "credential", "credentials", "apikey", "pat":
		return true
	case "key":
		if len(words) > 1 {
			switch words[len(words)-2] {
			case "api", "access", "private", "secret", "auth", "signing", "client":
				return true
			}
		}
	}
	return false
}

// secretInConfig walks every string in every parsed config. A value is a
// secret when it matches a known token format, or when its key looks
// sensitive and it holds a literal rather than a reference such as ${VAR}.
func secretInConfig(a discover.Agent, _ platform.Env, _ string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, c := range a.Configs {
		if c.Doc == nil || seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		walk(c.Doc, "", func(pointer, key, value string) {
			kinds := redact.SecretKinds(value)
			if len(kinds) == 0 && sensitiveKey(key) && isLiteralSecret(value) {
				kinds = []string{"secret"}
			}
			if len(kinds) == 0 && strings.EqualFold(key, "authorization") {
				// An MCP server's header: "Bearer <token>" with the token written out.
				if scheme, cred, ok := strings.Cut(strings.TrimSpace(value), " "); ok && isLiteralSecret(cred) &&
					(strings.EqualFold(scheme, "bearer") || strings.EqualFold(scheme, "basic") || strings.EqualFold(scheme, "token")) {
					kinds = []string{"token"}
				}
			}
			if len(kinds) == 0 {
				return
			}
			out = append(out, Finding{Tier: c.Tier, Path: c.Path, Pointer: pointer,
				Message: fmt.Sprintf("%s holds %s in plain text.", pointer, secretLabel(kinds[0])),
				Fix:     "Move it to your OS keychain or an environment variable and reference it, for example ${GITHUB_TOKEN}."})
		})
	}
	return out
}

var secretLabels = map[string]string{ //nolint:gosec // labels for secret kinds, not credentials
	"aws_key": "an AWS access key", "github_token": "a GitHub token", "gitlab_token": "a GitLab token",
	"slack_token": "a Slack token", "stripe_key": "a Stripe key", "anthropic_key": "an Anthropic API key",
	"openai_key": "an OpenAI API key", "google_api_key": "a Google API key", "npm_token": "an npm token",
	"jwt": "a JWT", "private_key": "a private key", "credentials": "credentials in a URL",
	"redacted": "a credential in a URL", "token": "a bearer token", "secret": "a secret",
}

func secretLabel(kind string) string {
	if l, ok := secretLabels[kind]; ok {
		return l
	}
	return "a credential"
}

func isLiteralSecret(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 || strings.ContainsAny(v, " \t") {
		return false
	}
	if dateRE.MatchString(v) || strings.Trim(v, "0123456789") == "" {
		return false
	}
	return !strings.HasPrefix(v, "$") && !strings.HasPrefix(v, "<") && !strings.HasPrefix(v, "op://") && !strings.HasPrefix(v, "env:")
}

func walk(v any, pointer string, fn func(pointer, key, value string)) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := pointer + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(k)
			if s, ok := x[k].(string); ok {
				fn(p, k, s)
				continue
			}
			walk(x[k], p, fn)
		}
	case []any:
		for i, e := range x {
			p := fmt.Sprintf("%s/%d", pointer, i)
			if s, ok := e.(string); ok {
				fn(p, "", s)
				continue
			}
			walk(e, p, fn)
		}
	}
}

func writableManagedConfig(a discover.Agent, _ platform.Env, root string) []Finding {
	var out []Finding
	for _, c := range a.Configs {
		if c.Tier != contract.ConfigTierManaged {
			continue
		}
		for _, p := range []string{c.Path, filepath.Dir(c.Path)} {
			if w, err := platform.WritableByOthers(filepath.Join(root, p)); err == nil && w {
				out = append(out, Finding{Tier: c.Tier, Path: p,
					Message: fmt.Sprintf("%s is writable by other users.", p),
					Fix:     fmt.Sprintf("Run: sudo chmod go-w %q", p)})
				break
			}
		}
	}
	return out
}
