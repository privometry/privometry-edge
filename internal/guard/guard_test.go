package guard

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
)

const existing = `{
  "permissions": {
    "allow": ["Read"]
  },
  "model": "opus",
  "hooks": {
    "Stop": [
      {
        "hooks": [{"type": "command", "command": "afplay /System/Library/Sounds/Glass.aiff"}]
      }
    ]
  },
  "statusLine": {"type": "command", "command": "~/bin/status"}
}
`

func setup(t *testing.T, content string, vars map[string]string) (registry.Adapter, Options, string) {
	t.Helper()
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := reg.Get(contract.AgentProductClaudeCode)
	root := t.TempDir()
	path := filepath.Join(root, "home/dev/.claude/settings.json")
	if content != "" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opts := Options{Env: platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(k string) string { return vars[k] }},
		HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304", Root: root}
	return a, opts, path
}

func parse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return m
}

func TestInstallIntoExistingSettings(t *testing.T) {
	a, opts, path := setup(t, existing, nil)
	c, err := Install(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	// The user's keys keep their order and their hooks survive.
	order := []string{`"permissions"`, `"model"`, `"hooks"`, `"statusLine"`}
	last := -1
	for _, k := range order {
		i := strings.Index(text, k)
		if i < last {
			t.Errorf("key order changed:\n%s", text)
		}
		last = i
	}
	if !strings.Contains(text, "afplay") {
		t.Error("the user's own Stop hook was removed")
	}
	m := parse(t, raw)
	hooks := m["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)[0].(map[string]any)
	entry := pre["hooks"].([]any)[0].(map[string]any)
	if pre["matcher"] != "*" || entry["command"] != "/usr/local/bin/privometry-hook claude_code PreToolUse" || entry["onFailure"] != "block" || entry["timeout"] != 10.0 {
		t.Errorf("PreToolUse entry: %v %v", pre, entry)
	}
	post := hooks["PostToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if _, ok := post["onFailure"]; ok {
		t.Error("only decision hooks fail closed")
	}
	for _, ev := range []string{"SessionStart", "SessionEnd", "ConfigChange", "InstructionsLoaded"} {
		if _, ok := hooks[ev]; !ok {
			t.Errorf("%s not registered", ev)
		}
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}
	if b, err := os.ReadFile(path + ".privometry-backup"); err != nil || string(b) != existing {
		t.Errorf("backup missing or wrong: %v", err)
	}
	if s := Check(a, opts); s.State != "installed" || !s.FailClosed || len(s.Missing) != 0 {
		t.Errorf("status %+v", s)
	}

	// Installing again changes nothing.
	again, _ := Install(a, opts)
	if again.Changed() {
		t.Errorf("second install is not idempotent:\n%s", again.After)
	}

	// Uninstall leaves exactly the user's settings.
	u, err := Uninstall(a, opts)
	if err != nil || u.Apply() != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !reflect.DeepEqual(parse(t, raw), parse(t, []byte(existing))) {
		t.Errorf("uninstall did not restore the user's settings:\n%s", raw)
	}
	if s := Check(a, opts); s.State != "missing" {
		t.Errorf("after uninstall: %+v", s)
	}
}

func TestInstallVariants(t *testing.T) {
	// No settings file yet.
	a, opts, path := setup(t, "", nil)
	c, err := Install(a, opts)
	if err != nil || c.Before != nil || c.Apply() != nil {
		t.Fatalf("new file: %v", err)
	}
	platformtest.Private(t, path)

	// Old or unknown versions get no onFailure key, which they might reject.
	for _, v := range []string{"2.1.200", ""} {
		a, opts, _ := setup(t, existing, nil)
		opts.AgentVersion = v
		c, _ := Install(a, opts)
		if c.FailClosed || strings.Contains(string(c.After), "onFailure") {
			t.Errorf("version %q got onFailure", v)
		}
	}

	// A path with spaces is quoted, still recognized, and stale entries are detected.
	a, opts, _ = setup(t, existing, nil)
	opts.HookCommand = "/Applications/Privometry Tools/privometry-hook"
	c, _ = Install(a, opts)
	c.Apply()
	if !strings.Contains(string(c.After), `"'/Applications/Privometry Tools/privometry-hook' claude_code PreToolUse"`) {
		t.Errorf("quoted command: %s", c.After)
	}
	opts.HookCommand = "/usr/local/bin/privometry-hook"
	if s := Check(a, opts); s.State != "stale" {
		t.Errorf("moved binary: %+v", s)
	}
	c, _ = Install(a, opts)
	if strings.Contains(string(c.After), "Privometry Tools") {
		t.Error("reinstall must replace the old entries")
	}

	// CLAUDE_CONFIG_DIR moves the settings file.
	a, opts, _ = setup(t, "", map[string]string{"CLAUDE_CONFIG_DIR": "/cfg/claude"})
	c, _ = Install(a, opts)
	if c.Path != "/cfg/claude/settings.json" {
		t.Errorf("override path %s", c.Path)
	}

	// Invalid JSON is never rewritten.
	a, opts, path = setup(t, `{"model": "opus",`, nil)
	if _, err := Install(a, opts); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("invalid JSON: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"model": "opus",` {
		t.Error("invalid file was modified")
	}

	// Unknown registration formats are refused.
	if _, err := Install(registry.Adapter{Agent: "other"}, opts); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown format: %v", err)
	}
}

func agentSetup(t *testing.T, agent contract.AgentProduct, file, content string, vars map[string]string) (registry.Adapter, Options, string) {
	t.Helper()
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := reg.Get(agent)
	root := t.TempDir()
	path := filepath.Join(root, file)
	if content != "" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(content), 0o644)
	}
	opts := Options{Env: platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(k string) string { return vars[k] }},
		HookCommand: "/usr/local/bin/privometry-hook", Root: root}
	return a, opts, path
}

const cursorHooks = `{
  "version": 1,
  "hooks": {
    "afterFileEdit": [{"command": "./scripts/format.sh"}]
  }
}
`

func TestCursor(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductCursor, "home/dev/.cursor/hooks.json", cursorHooks, nil)
	c, err := Install(a, opts)
	if err != nil || c.Apply() != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	m := parse(t, raw)
	hooks := m["hooks"].(map[string]any)
	if _, ok := hooks["afterFileEdit"]; !ok {
		t.Error("the user's own hook was removed")
	}
	shell := hooks["beforeShellExecution"].([]any)[0].(map[string]any)
	if shell["command"] != "/usr/local/bin/privometry-hook cursor beforeShellExecution" || shell["failClosed"] != true || shell["type"] != nil {
		t.Errorf("beforeShellExecution entry: %v", shell)
	}
	pre := hooks["preToolUse"].([]any)[0].(map[string]any)
	if pre["matcher"] != "^(Write|Delete|Task)$" || pre["failClosed"] != true {
		t.Errorf("preToolUse entry: %v", pre)
	}
	start := hooks["sessionStart"].([]any)[0].(map[string]any)
	if _, ok := start["failClosed"]; ok {
		t.Error("only decision hooks fail closed")
	}
	if !c.FailClosed || c.TrustInstructions != "" {
		t.Errorf("change: %+v", c)
	}
	if s := Check(a, opts); s.State != "installed" || !s.FailClosed || s.TrustRequired {
		t.Errorf("status %+v", s)
	}
	if !Installed(a, opts) {
		t.Error("Installed should be true")
	}
	u, _ := Uninstall(a, opts)
	u.Apply()
	raw, _ = os.ReadFile(path)
	if !reflect.DeepEqual(parse(t, raw), parse(t, []byte(cursorHooks))) {
		t.Errorf("uninstall did not restore the file:\n%s", raw)
	}

	// A new file starts with version 1; removing Privometry again leaves an empty object.
	a, opts, path = agentSetup(t, contract.AgentProductCursor, "home/dev/.cursor/hooks.json", "", nil)
	c, _ = Install(a, opts)
	c.Apply()
	if !strings.HasPrefix(strings.TrimSpace(string(c.After)), "{\n  \"version\": 1,") {
		t.Errorf("version must come first:\n%s", c.After)
	}
	u, _ = Uninstall(a, opts)
	u.Apply()
	if raw, _ := os.ReadFile(path); strings.TrimSpace(string(raw)) != "{}" {
		t.Errorf("after uninstall: %s", raw)
	}
}

func TestCodex(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductCodexCLI, "home/dev/.codex/hooks.json", "", nil)
	c, err := Install(a, opts)
	if err != nil || c.Apply() != nil {
		t.Fatal(err)
	}
	m := parse(t, mustRead(t, path))
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	entry := pre["hooks"].([]any)[0].(map[string]any)
	if pre["matcher"] != ".*" || entry["type"] != "command" || entry["command"] != "/usr/local/bin/privometry-hook codex_cli PreToolUse" {
		t.Errorf("PreToolUse: %v %v", pre, entry)
	}
	prompt := m["hooks"].(map[string]any)["UserPromptSubmit"].([]any)[0].(map[string]any)
	promptEntry := prompt["hooks"].([]any)[0].(map[string]any)
	if promptEntry["command"] != "/usr/local/bin/privometry-hook codex_cli UserPromptSubmit" {
		t.Errorf("UserPromptSubmit: %v", promptEntry)
	}
	if c.FailClosed || !strings.Contains(c.TrustInstructions, "/hooks") {
		t.Errorf("codex has no fail-closed option and needs trust: %+v", c)
	}
	if s := Check(a, opts); s.State != "installed" || !s.TrustRequired || !strings.Contains(s.Detail, "/hooks") {
		t.Errorf("status %+v", s)
	}

	// CODEX_HOME moves the file; disabled hooks in config.toml are reported.
	a, opts, _ = agentSetup(t, contract.AgentProductCodexCLI, "srv/codex/config.toml", "model = \"x\"\n[features]\nhooks = false\n",
		map[string]string{"CODEX_HOME": "/srv/codex"})
	c, _ = Install(a, opts)
	if c.Path != "/srv/codex/hooks.json" || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "hooks = false") {
		t.Errorf("path %s warnings %v", c.Path, c.Warnings)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIsPrivometry(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/usr/local/bin/privometry-hook claude_code PreToolUse":          true,
		"'/Applications/Privometry Tools/privometry-hook' claude_code X": true,
		"privometry-hook claude_code PreToolUse":                         true,
		"afplay /System/Library/Sounds/Glass.aiff":                       false,
		"/opt/not-privometry-hook-x":                                     false,
		"/opt/privometry-hooker run":                                     false,
	} {
		if got := isPrivometry(cmd); got != want {
			t.Errorf("isPrivometry(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestInstallOnWindowsQuotesThePath(t *testing.T) {
	a, opts, _ := setup(t, "", nil)
	opts.Env = platform.Env{GOOS: "windows", Home: `C:\Users\dev`, Getenv: func(string) string { return "" }}
	opts.HookCommand = `C:\Users\dev\AppData\Local\Programs\Privometry\privometry-hook.exe`
	c, err := Install(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != `C:\Users\dev\.claude\settings.json` {
		t.Errorf("path %s", c.Path)
	}
	want := `"C:\\Users\\dev\\AppData\\Local\\Programs\\Privometry\\privometry-hook.exe\" claude_code PreToolUse`
	if !strings.Contains(string(c.After), want) {
		t.Errorf("command not double-quoted:\n%s", c.After)
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("check after install: %+v", s)
	}
}

func TestInstallGemini(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductGeminiCLI, "home/dev/.gemini/settings.json",
		`{"theme": "Dracula", "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "./lint.sh"}]}]}}`, nil)
	c, err := Install(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	doc := parse(t, raw)
	if doc["theme"] != "Dracula" {
		t.Error("the user's settings were not kept")
	}
	before := doc["hooks"].(map[string]any)["BeforeTool"].([]any)
	if len(before) != 2 {
		t.Fatalf("BeforeTool groups: %v", before)
	}
	ours := before[1].(map[string]any)
	entry := ours["hooks"].([]any)[0].(map[string]any)
	if ours["matcher"] != ".*" || entry["name"] != "privometry" || entry["type"] != "command" ||
		entry["command"] != "/usr/local/bin/privometry-hook gemini_cli BeforeTool" || entry["timeout"] != float64(10000) {
		t.Errorf("BeforeTool entry: %v", ours)
	}
	if _, ok := doc["hooks"].(map[string]any)["SessionStart"].([]any)[0].(map[string]any)["matcher"]; ok {
		t.Error("lifecycle events take no matcher")
	}
	if s := Check(a, opts); s.State != "installed" || s.FailClosed {
		t.Errorf("check: %+v", s)
	}
	u, err := Uninstall(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	u.Apply()
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "privometry") || !strings.Contains(string(raw), "./lint.sh") {
		t.Errorf("after uninstall:\n%s", raw)
	}
}

func TestInstallCopilot(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductCopilotCLI, "home/dev/.copilot/hooks/privometry.json", "", nil)
	c, err := Install(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != "/home/dev/.copilot/hooks/privometry.json" {
		t.Errorf("path %s", c.Path)
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	doc := parse(t, raw)
	pre := doc["hooks"].(map[string]any)["preToolUse"].([]any)[0].(map[string]any)
	if doc["version"] != float64(1) || pre["type"] != "command" || pre["bash"] != "/usr/local/bin/privometry-hook copilot_cli preToolUse" ||
		pre["timeoutSec"] != float64(10) || pre["command"] != nil {
		t.Errorf("preToolUse entry: %s", raw)
	}
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("check: %+v", s)
	}
	u, err := Uninstall(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("Privometry's own hooks file is removed on uninstall")
	}

	// COPILOT_HOME moves the file; on Windows the command is PowerShell.
	a, opts, _ = agentSetup(t, contract.AgentProductCopilotCLI, "", "", map[string]string{"COPILOT_HOME": "/srv/copilot"})
	if c, _ := Install(a, opts); c.Path != "/srv/copilot/hooks/privometry.json" {
		t.Errorf("COPILOT_HOME: %s", c.Path)
	}
	opts.Env = platform.Env{GOOS: "windows", Home: `C:\Users\dev`, Getenv: func(string) string { return "" }}
	opts.HookCommand = `C:\Program Files\Privometry\privometry-hook.exe`
	c, _ = Install(a, opts)
	if !strings.Contains(string(c.After), `"powershell": "& \"C:\\Program Files\\Privometry\\privometry-hook.exe\" copilot_cli preToolUse"`) {
		t.Errorf("windows entry:\n%s", c.After)
	}
	c.Apply()
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("windows check: %+v", s)
	}
}

func TestInstallAntigravity(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductAntigravity, "home/dev/.gemini/config/hooks.json",
		`{"my-linter": {"PreToolUse": [{"matcher": "run_command", "hooks": [{"command": "./lint.sh", "timeout": 10}]}]}}`, nil)
	c, err := Install(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	doc := parse(t, raw)
	if _, ok := doc["my-linter"]; !ok {
		t.Error("the user's own hook was not kept")
	}
	ours := doc["privometry"].(map[string]any)
	pre := ours["PreToolUse"].([]any)[0].(map[string]any)
	entry := pre["hooks"].([]any)[0].(map[string]any)
	if pre["matcher"] != "*" || entry["type"] != "command" || entry["command"] != "/usr/local/bin/privometry-hook antigravity PreToolUse" || entry["timeout"] != float64(10) {
		t.Errorf("PreToolUse: %v", pre)
	}
	start := ours["SessionStart"].([]any)[0].(map[string]any)
	if start["command"] != "/usr/local/bin/privometry-hook antigravity SessionStart" || start["hooks"] != nil {
		t.Errorf("SessionStart takes handlers, not groups: %v", start)
	}
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("check: %+v", s)
	}
	again, _ := Install(a, opts)
	if again.Changed() {
		t.Error("installing twice changes the file")
	}
	u, err := Uninstall(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	u.Apply()
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "privometry") || !strings.Contains(string(raw), "./lint.sh") {
		t.Errorf("after uninstall:\n%s", raw)
	}
}
