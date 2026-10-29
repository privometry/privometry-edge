package daemon_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// replay feeds fixture payloads (test/fixtures/<agent>/<version>/hooks, or
// documented/ when version is empty) through the shipped definition.
type replay struct {
	t       *testing.T
	d       *daemon.Daemon
	agent   string
	version string
}

func (r replay) send(event, name string) ipc.Response {
	r.t.Helper()
	dir := r.version
	if dir == "" {
		dir = "documented"
	}
	raw, err := os.ReadFile("../../test/fixtures/" + r.agent + "/" + dir + "/hooks/" + name)
	if err != nil {
		r.t.Fatal(err)
	}
	return hook(r.t, r.d, r.agent, event, raw)
}

func (r replay) observe(event, name string) {
	r.t.Helper()
	if resp := r.send(event, name); resp.Stdout != "" || resp.ExitCode != 0 {
		r.t.Errorf("%s must not change what %s does: %+v", name, r.agent, resp)
	}
}

// reply reads a decision from fields named by the agent's reply shape.
func reply(t *testing.T, resp ipc.Response, verdictKey, reasonKey string) (string, string) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(resp.Stdout), &out); err != nil {
		t.Fatalf("stdout %q: %v", resp.Stdout, err)
	}
	v, _ := out[verdictKey].(string)
	reason, _ := out[reasonKey].(string)
	return v, reason
}

func eventsByTool(t *testing.T, d *daemon.Daemon) map[string]timeline.Row {
	t.Helper()
	d.Wait()
	out := map[string]timeline.Row{}
	for _, r := range validEvents(t, d) {
		if r.Event.Action != nil {
			out[r.Event.Action.ToolName] = r
		}
	}
	return out
}

func TestGeminiDocumentedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "gemini_cli", ""}
	gemini := func(name string) (string, string) {
		t.Helper()
		return reply(t, r.send("BeforeTool", name), "decision", "reason")
	}
	r.observe("SessionStart", "sessionstart.json")
	r.observe("BeforeAgent", "beforeagent.json")
	if v, _ := gemini("beforetool-shell-ls.json"); v != "allow" {
		t.Errorf("ls -la: %s", v)
	}
	r.observe("AfterTool", "aftertool-shell-ls.json")
	if v, reason := gemini("beforetool-shell-rm.json"); v != "deny" || reason == "" {
		t.Errorf("rm -rf ~: %s %q", v, reason)
	}
	// Gemini cannot ask: asks arrive as deny with the reason.
	if v, reason := gemini("beforetool-read-env.json"); v != "deny" || reason == "" {
		t.Errorf("read .env: %s %q", v, reason)
	}
	if v, _ := gemini("beforetool-write-file.json"); v != "allow" {
		t.Errorf("write src/util.ts: %s", v)
	}
	if v, reason := gemini("beforetool-replace-gemini-md.json"); v != "deny" || reason == "" {
		t.Errorf("weakening GEMINI.md: %s %q", v, reason)
	}
	gemini("beforetool-mcp.json")
	r.observe("SessionEnd", "sessionend.json")

	byTool := eventsByTool(t, d)
	if e := byTool["mcp_tickets_lookup_ticket"].Event; e.MCP == nil || e.MCP.ServerName != "tickets" || e.MCP.Tool != "lookup_ticket" {
		t.Errorf("MCP call event: %+v", e.MCP)
	}
	if e := byTool["read_file"].Event; e.Decision == nil || e.Decision.NativeVerdict != "deny" || e.Decision.Verdict != "ask" {
		t.Errorf("read .env decision: %+v", e.Decision)
	}
	if e := byTool["run_shell_command"].Event; e.Agent == nil || e.Agent.Product != "gemini_cli" {
		t.Errorf("agent: %+v", e.Agent)
	}
}

// The recorded 1.0.105 session: toolArgs is an object, apply_patch sends the
// patch itself, and MCP tools are <server>-<tool>.
func TestCopilotRecordedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "copilot_cli", "1.0.105"}
	copilot := func(name string) (string, string) {
		t.Helper()
		return reply(t, r.send("preToolUse", name), "permissionDecision", "permissionDecisionReason")
	}
	r.observe("sessionStart", "sessionstart.json")
	r.observe("userPromptSubmitted", "userpromptsubmitted.json")
	for _, name := range []string{"pretooluse-bash-ls.json", "pretooluse-view.json", "pretooluse-apply-patch-update.json", "pretooluse-apply-patch-add.json"} {
		if v, _ := copilot(name); v != "allow" {
			t.Errorf("%s: %s", name, v)
		}
	}
	// The developer refused rm -rf build in Copilot; inside the project,
	// policy allows it. The documented session covers the denials.
	for _, name := range []string{"pretooluse-web-fetch.json", "pretooluse-mcp.json", "pretooluse-bash-rm-refused.json"} {
		if v, _ := copilot(name); v == "" {
			t.Errorf("%s: no decision", name)
		}
	}
	r.observe("postToolUse", "posttooluse-bash-ls.json")
	r.observe("postToolUse", "posttooluse-mcp.json")
	r.observe("sessionEnd", "sessionend.json")

	byTool := eventsByTool(t, d)
	if row := byTool["bash"]; !strings.HasPrefix(row.TargetClear, "ls -la") && !strings.HasPrefix(row.TargetClear, "rm -rf build") {
		t.Errorf("bash target %q", row.TargetClear)
	}
	if a := byTool["apply_patch"].Event.Action; a == nil || a.Kind != "file_write" || a.PathClass == "" {
		t.Errorf("apply_patch: %+v", a)
	}
	if e := byTool["tickets-lookup_ticket"].Event; e.Action == nil || e.Action.Kind != "mcp_call" || e.MCP == nil || e.MCP.ServerName != "tickets" || e.MCP.Tool != "lookup_ticket" {
		t.Errorf("MCP call: %+v %+v", e.Action, e.MCP)
	}
	if a := byTool["web_fetch"].Event.Action; a == nil || a.Kind != "network_fetch" {
		t.Errorf("web_fetch: %+v", a)
	}
}

// The recorded 3.27.22 session: Cursor's own events, and the Claude Code
// hooks Cursor runs (claude-*.json), which carry Cursor's tool names.
func TestCursorRecordedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "cursor", "3.27.22"}
	r.observe("sessionStart", "sessionstart.json")
	// Everything stayed inside the project. preToolUse sends no cwd, and the
	// rm -rf build shell hook sent cwd "": both fall back to workspace_roots.
	for event, names := range map[string][]string{
		"beforeShellExecution": {"beforeshellexecution-ls.json", "beforeshellexecution-curl.json", "beforeshellexecution-rm.json"},
		"beforeReadFile":       {"beforereadfile-notes.json"},
		"preToolUse":           {"pretooluse-write-notes.json", "pretooluse-write-todo.json"},
		"beforeMCPExecution":   {"beforemcpexecution-lookup-ticket.json"},
	} {
		for _, name := range names {
			if v, why := reply(t, r.send(event, name), "permission", "user_message"); v != "allow" {
				t.Errorf("%s: %s %s", name, v, why)
			}
		}
	}
	byTool := eventsByTool(t, d)
	if a := byTool["Write"].Event.Action; a == nil || a.Kind != "file_write" || a.PathClass == "" {
		t.Errorf("Write: %+v", a)
	}
	// tool_input arrives as a JSON string on beforeMCPExecution.
	if e := byTool["lookup_ticket"].Event; e.MCP == nil || e.MCP.ServerName != "tickets" || e.MCP.Tool != "lookup_ticket" {
		t.Errorf("MCP call: %+v", e.MCP)
	}

	// Without Cursor's own hook, the imported Claude Code calls decide, and
	// read Shell and MCP:tool through Cursor's definition.
	d, _ = newDaemon(t)
	for _, name := range []string{"claude-pretooluse-shell-rm.json", "claude-pretooluse-read-notes.json",
		"claude-pretooluse-write-todo.json", "claude-pretooluse-mcp-lookup-ticket.json"} {
		raw, err := os.ReadFile("../../test/fixtures/cursor/3.27.22/hooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := decision(t, hook(t, d, "claude_code", "PreToolUse", raw)); v == "" {
			t.Errorf("%s: no decision", name)
		}
	}
	byTool = eventsByTool(t, d)
	if e := byTool["Shell"].Event; e.Agent == nil || e.Agent.Product != "cursor" || e.Action.Kind != "shell_exec" || !strings.HasPrefix(byTool["Shell"].TargetClear, "rm -rf build") {
		t.Errorf("imported Shell: %+v %q", e.Action, byTool["Shell"].TargetClear)
	}
	if a := byTool["MCP:lookup_ticket"].Event.Action; a == nil || a.Kind != "mcp_call" {
		t.Errorf("imported MCP: %+v", a)
	}
	if a := byTool["Write"].Event.Action; a == nil || a.Kind != "file_write" {
		t.Errorf("imported Write: %+v", a)
	}
}

func TestCopilotDocumentedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "copilot_cli", ""}
	copilot := func(name string) (string, string) {
		t.Helper()
		return reply(t, r.send("preToolUse", name), "permissionDecision", "permissionDecisionReason")
	}
	r.observe("sessionStart", "sessionstart.json")
	r.observe("userPromptSubmitted", "userpromptsubmitted.json")
	if v, _ := copilot("pretooluse-bash-ls.json"); v != "allow" {
		t.Errorf("ls -la: %s", v)
	}
	r.observe("postToolUse", "posttooluse-bash-ls.json")
	if v, reason := copilot("pretooluse-bash-rm.json"); v != "deny" || reason == "" {
		t.Errorf("rm -rf ~: %s %q", v, reason)
	}
	if v, reason := copilot("pretooluse-view-env.json"); v != "ask" || reason == "" {
		t.Errorf("view .env: %s %q", v, reason)
	}
	if v, _ := copilot("pretooluse-create.json"); v != "allow" {
		t.Errorf("create src/util.ts: %s", v)
	}
	if v, _ := copilot("pretooluse-edit-instructions.json"); v == "allow" || v == "" {
		t.Errorf("weakening copilot-instructions.md: %s", v)
	}
	if v, _ := copilot("pretooluse-curl-upload.json"); v == "allow" || v == "" {
		t.Errorf("uploading .env: %s", v)
	}
	r.observe("sessionEnd", "sessionend.json")

	byTool := eventsByTool(t, d)
	// toolArgs arrives as a JSON string; the decoded command is what was decided.
	if row := byTool["bash"]; !strings.HasPrefix(row.TargetClear, "ls -la") && !strings.HasPrefix(row.TargetClear, "curl") && !strings.HasPrefix(row.TargetClear, "rm") {
		t.Errorf("bash target %q", row.TargetClear)
	}
	if e := byTool["view"].Event; e.Decision == nil || e.Decision.Verdict != "ask" || e.Action.PathClass == "" {
		t.Errorf("view .env: %+v %+v", e.Decision, e.Action)
	}
	if e := byTool["create"].Event; e.Agent == nil || e.Agent.Product != "copilot_cli" || e.Agent.NativeSessionID != "5f0d2c7e-91a3-4b6e-8d2f-3a4b5c6d7e8f" {
		t.Errorf("agent: %+v", e.Agent)
	}
}

// The recorded 1.4.10 session: the tool names differ from the documented
// ones (read_file, edit_file, write_file, call_mcp_tool), and MCP calls name
// the server and tool in their arguments.
func TestAntigravityRecordedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "antigravity", "1.4.10"}
	for _, name := range []string{"pretooluse-run-command-ls.json", "pretooluse-run-command-curl.json", "pretooluse-read-file-notes.json",
		"pretooluse-edit-file.json", "pretooluse-write-file.json", "pretooluse-call-mcp-tool.json", "pretooluse-run-command-rm-refused.json",
		"pretooluse-read-file-mcp-schema.json"} { // agy reads the MCP tool's schema from its own folder first
		if v, why := reply(t, r.send("PreToolUse", name), "decision", "reason"); v != "allow" {
			t.Errorf("%s: %s %s", name, v, why)
		}
	}
	for _, name := range []string{"posttooluse-run-command-ls.json", "posttooluse-edit-file.json", "posttooluse-call-mcp-tool.json"} {
		if resp := r.send("PostToolUse", name); resp.Stdout != "{}" || resp.ExitCode != 0 {
			t.Errorf("%s must answer {}: %+v", name, resp)
		}
	}
	if resp := r.send("SessionStart", "sessionstart.json"); resp.Stdout != "{}" {
		t.Errorf("SessionStart: %+v", resp)
	}

	byTool := eventsByTool(t, d)
	for tool, kind := range map[string]string{"read_file": "file_read", "edit_file": "file_write", "write_file": "file_write"} {
		if a := byTool[tool].Event.Action; a == nil || string(a.Kind) != kind || a.PathClass != "repo" {
			t.Errorf("%s: %+v", tool, a)
		}
	}
	if e := byTool["call_mcp_tool"].Event; e.MCP == nil || e.MCP.ServerName != "tickets" || e.MCP.Tool != "lookup_ticket" {
		t.Errorf("MCP call: %+v %+v", e.Action, e.MCP)
	}
}

func TestAntigravityDocumentedSession(t *testing.T) {
	d, _ := newDaemon(t)
	r := replay{t, d, "antigravity", ""}
	agy := func(name string) (string, string) {
		t.Helper()
		return reply(t, r.send("PreToolUse", name), "decision", "reason")
	}
	observe := func(event, name string) {
		t.Helper()
		if resp := r.send(event, name); resp.Stdout != "{}" || resp.ExitCode != 0 {
			t.Errorf("%s must answer {} and change nothing: %+v", name, resp)
		}
	}
	observe("SessionStart", "sessionstart.json")
	if v, _ := agy("pretooluse-run-command-ls.json"); v != "allow" {
		t.Errorf("ls -la: %s", v)
	}
	observe("PostToolUse", "posttooluse-run-command-ls.json")
	if v, reason := agy("pretooluse-run-command-rm.json"); v != "deny" || reason == "" {
		t.Errorf("rm -rf ~: %s %q", v, reason)
	}
	// Policy asks always prompt: force_ask, not ask, which an earlier "Always Allow" would skip.
	if v, reason := agy("pretooluse-view-env.json"); v != "force_ask" || reason == "" {
		t.Errorf("view .env: %s %q", v, reason)
	}
	if v, _ := agy("pretooluse-write-to-file.json"); v != "allow" {
		t.Errorf("write src/util.ts: %s", v)
	}
	if v, _ := agy("pretooluse-replace-agents-md.json"); v == "allow" || v == "" {
		t.Errorf("weakening AGENTS.md: %s", v)
	}
	agy("pretooluse-read-url.json")
	observe("PostToolUse", "posttooluse-read-url.json")

	byTool := eventsByTool(t, d)
	if e := byTool["view_file"].Event; e.Decision == nil || e.Decision.Verdict != "ask" || e.Action.PathClass == "" {
		t.Errorf("view .env: %+v %+v", e.Decision, e.Action)
	}
	if e := byTool["run_command"].Event; e.Agent == nil || e.Agent.Product != "antigravity" || e.Agent.NativeSessionID != "c1f0a2b4-7d3e-4c1a-9b8e-2f6d5a4c3b21" {
		t.Errorf("agent: %+v", e.Agent)
	}
	if e := byTool["write_to_file"].Event; e.Action == nil || e.Action.PathClass != "repo" {
		t.Errorf("the first workspace path is the working folder, so src/util.ts is in the repo: %+v", e.Action)
	}
	// Reading a web page marks the session as having seen untrusted input.
	rows, _ := d.Store().Sessions(10)
	untrusted := false
	for _, s := range rows {
		untrusted = untrusted || s.Untrusted
	}
	if !untrusted {
		t.Error("read_url_content did not mark the session untrusted")
	}
}
