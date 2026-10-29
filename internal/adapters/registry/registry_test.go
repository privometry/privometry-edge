package registry_test

import (
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
)

func TestShippedDefinitionsLoad(t *testing.T) {
	r, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	var got []contract.AgentProduct
	for _, a := range r.All() {
		got = append(got, a.Agent)
	}
	want := []contract.AgentProduct{contract.AgentProductAntigravity, contract.AgentProductClaudeCode, contract.AgentProductCodexCLI,
		contract.AgentProductCopilotCLI, contract.AgentProductCursor, contract.AgentProductGeminiCLI}
	if len(got) != len(want) {
		t.Fatalf("agents %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("agents %v, want %v", got, want)
		}
	}
}

func TestPaths(t *testing.T) {
	r, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	claude, _ := r.Get(contract.AgentProductClaudeCode)
	env := func(goos string, vars map[string]string) platform.Env {
		return platform.Env{GOOS: goos, Home: "/home/dev", Getenv: func(k string) string { return vars[k] }}
	}
	tiers := map[contract.ConfigTier][]string{}
	for _, tier := range claude.ConfigTiers {
		paths, err := claude.Paths(tier.Paths, env("linux", nil), "/home/dev/api")
		if err != nil {
			t.Fatal(err)
		}
		tiers[tier.Tier] = append(tiers[tier.Tier], paths...)
	}
	for tier, want := range map[contract.ConfigTier]string{
		contract.ConfigTierUser:    "/home/dev/.claude/settings.json",
		contract.ConfigTierProject: "/home/dev/api/.claude/settings.local.json",
		contract.ConfigTierManaged: "/etc/claude-code/managed-settings.d/*.json",
	} {
		if !contains(tiers[tier], want) {
			t.Errorf("%s paths %v missing %s", tier, tiers[tier], want)
		}
	}

	// CLAUDE_CONFIG_DIR relocates ~/.claude but not ~/.claude.json.
	src := claude.MCPSources[0]
	user, _ := claude.Paths(src.Paths, env("linux", map[string]string{"CLAUDE_CONFIG_DIR": "/cfg"}), "")
	if !contains(user, "/home/dev/.claude.json") {
		t.Errorf("~/.claude.json must not move: %v", user)
	}
	settings, _ := claude.Paths(claude.ConfigTiers[0].Paths, env("linux", map[string]string{"CLAUDE_CONFIG_DIR": "/cfg"}), "")
	if !contains(settings, "/cfg/settings.json") {
		t.Errorf("override not applied: %v", settings)
	}

	// Without a repo, project-relative paths are dropped.
	if p, _ := claude.Paths(map[string][]string{"any": {".mcp.json"}}, env("linux", nil), ""); len(p) != 0 {
		t.Errorf("relative path without repo: %v", p)
	}
}

func TestSupports(t *testing.T) {
	a := registry.Adapter{Versions: ">=2.1.295 <3.0.0"}
	for v, want := range map[string]bool{
		"2.1.304 (Claude Code)": true, "2.1.295": true, "2.1.294": false, "3.0.0": false, "2.9.9": true, "dev": false,
	} {
		if got := a.Supports(v); got != want {
			t.Errorf("Supports(%q) = %v, want %v", v, got, want)
		}
	}
	if got := registry.ParseVersion("codex-cli 0.14.2\n"); got != "0.14.2" {
		t.Errorf("ParseVersion = %q", got)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestLookups(t *testing.T) {
	r, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	claude, _ := r.Get(contract.AgentProductClaudeCode)
	for tool, want := range map[string]string{"Bash": "shell_exec", "mcp__github__create_issue": "mcp_call", "Read": "file_read", "SomethingNew": "other"} {
		if got := claude.ToolKind(tool); got != want {
			t.Errorf("ToolKind(%s) = %s, want %s", tool, got, want)
		}
	}
	if tt, ok := claude.ToolTarget("Bash"); !ok || tt.Command != "/command" {
		t.Errorf("ToolTarget(Bash) = %+v", tt)
	}
	if s, tool, ok := claude.MCPTool("mcp__plugin_x_github__list_prs"); !ok || s != "plugin_x_github" || tool != "list_prs" {
		t.Errorf("MCPTool = %q %q %v", s, tool, ok)
	}
	cursor, _ := r.Get(contract.AgentProductCursor)
	if s, tool, ok := cursor.MCPTool("MCP:search_docs"); !ok || s != "" || tool != "search_docs" {
		t.Errorf("cursor MCPTool = %q %q %v", s, tool, ok)
	}
	if e, ok := claude.Event("PreToolUse"); !ok || e.Role != registry.HookEventRolePreTool {
		t.Errorf("Event(PreToolUse) = %+v", e)
	}
	gemini, _ := r.Get(contract.AgentProductGeminiCLI)
	if s, tool, ok := gemini.MCPTool("mcp_github_list_issues"); !ok || s != "github" || tool != "list_issues" {
		t.Errorf("gemini MCPTool = %q %q %v", s, tool, ok)
	}
	if tool, ok := gemini.MCPToolOf("mcp_my_server_list_files", "my_server"); !ok || tool != "list_files" {
		t.Errorf("gemini MCPToolOf = %q %v", tool, ok)
	}
	if _, ok := gemini.MCPToolOf("mcp_other_list_files", "my_server"); ok {
		t.Error("MCPToolOf must not split a name for another server")
	}
	agy, _ := r.Get(contract.AgentProductAntigravity)
	if tt, ok := agy.ToolTarget("run_command"); !ok || tt.Command != "/CommandLine" || agy.ToolKind("browser_click") != "other" {
		t.Errorf("antigravity targets %+v", tt)
	}
	codex, _ := r.Get(contract.AgentProductCodexCLI)
	for tool, want := range map[string]string{"spawn_agent": "subagent_spawn", "collaborationspawn_agent": "subagent_spawn", "collaborationwait_agent": "other"} {
		if got := codex.ToolKind(tool); got != want {
			t.Errorf("codex ToolKind(%s) = %s, want %s", tool, got, want)
		}
	}
	copilot, _ := r.Get(contract.AgentProductCopilotCLI)
	for tool, want := range map[string]string{"bash": "shell_exec", "create": "file_write", "apply_patch": "file_write", "view": "file_read",
		"tickets-lookup_ticket": "mcp_call", "report_intent": "other"} {
		if got := copilot.ToolKind(tool); got != want {
			t.Errorf("copilot ToolKind(%s) = %s, want %s", tool, got, want)
		}
	}
}
