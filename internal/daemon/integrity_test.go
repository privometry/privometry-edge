package daemon_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/ipc/ipctest"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/timeline"
)

func TestIntegrity(t *testing.T) {
	platformtest.UnixPaths(t)
	home := t.TempDir()
	data, err := os.MkdirTemp(ipctest.TempRoot, "privometry-i-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	claude, _ := reg.Get(contract.AgentProductClaudeCode)
	gopts := guard.Options{Env: env, HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304"}
	c, err := guard.Install(claude, gopts)
	if err != nil || c.Apply() != nil {
		t.Fatal(err)
	}
	claudeJSON := filepath.Join(home, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 1, "mcpServers": {}}`), 0o644)

	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := func(want int, why string) {
		t.Helper()
		n, err := d.CheckIntegrity()
		if err != nil || n != want {
			t.Fatalf("%s: %d events, %v; want %d", why, n, err, want)
		}
	}
	check(0, "first observation")
	check(0, "nothing changed")

	// Claude Code rewrites ~/.claude.json constantly; only the MCP server map counts.
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 2, "mcpServers": {}}`), 0o644)
	check(0, "unrelated ~/.claude.json change")
	os.WriteFile(claudeJSON, []byte(`{"numStartups": 2, "mcpServers": {"x": {"command": "npx"}}}`), 0o644)
	check(1, "new MCP server")

	u, _ := guard.Uninstall(claude, gopts)
	u.Apply()
	check(2, "hook removed: a config change and an integrity alert")

	rows := validEvents(t, d)
	if rows[0].Event.Type != "integrity" || rows[0].Event.Integrity.Check != "hook_removed" || rows[1].Event.Type != "config_change" {
		t.Fatalf("events: %s %s", rows[0].Event.Type, rows[1].Event.Type)
	}
	if rows[2].Event.Config.Holds[0] != "mcp_servers" {
		t.Errorf("MCP change holds %v", rows[2].Event.Config.Holds)
	}
	if rows[0].Event.Integrity.Path != "~/<redacted_path>" {
		t.Errorf("integrity path must be redacted: %q", rows[0].Event.Integrity.Path)
	}

	// Reinstalling is a change, not an alert; removing again alerts again.
	c, _ = guard.Install(claude, gopts)
	c.Apply()
	check(1, "reinstall")
	if rows, _ := d.Store().Events(timeline.Query{Limit: 1}); rows[0].Event.Type != "config_change" {
		t.Errorf("reinstall recorded %s", rows[0].Event.Type)
	}
}

func TestHooksDisabled(t *testing.T) {
	platformtest.UnixPaths(t)
	home := t.TempDir()
	d, _ := newDaemonAt(t, home)
	reg, _ := registry.Load(adapterdefs.FS)
	claude, _ := reg.Get(contract.AgentProductClaudeCode)
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(string) string { return "" }}
	gopts := guard.Options{Env: env, HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304"}
	c, err := guard.Install(claude, gopts)
	if err != nil || c.Apply() != nil {
		t.Fatal(err)
	}
	check := func(want int, why string) {
		t.Helper()
		n, err := d.CheckIntegrity()
		if err != nil || n != want {
			t.Fatalf("%s: %d events, %v; want %d", why, n, err, want)
		}
	}
	check(0, "first observation")

	// A user setting that turns every hook off: a config change and an alert.
	settings := filepath.Join(home, ".claude/settings.json")
	raw, _ := os.ReadFile(settings)
	os.WriteFile(settings, []byte(`{"disableAllHooks": true,`+string(raw[1:])), 0o644)
	check(2, "disableAllHooks in user settings")
	check(0, "still off: reported once")
	in := integrityOf(t, d, "hooks_disabled")
	if in.Reason != "setting" || in.Tier != "user" || in.Detail == "" {
		t.Fatalf("event %+v", in)
	}
	if st := guard.Check(claude, gopts); st.State != "disabled" {
		t.Errorf("guard state %+v", st)
	}

	// Back on, then off again in a project's local settings: the project is
	// watched once an agent worked in it, and the file is reported the first
	// time it is seen.
	os.WriteFile(settings, raw, 0o644)
	check(1, "hooks back on: a config change only")
	project := filepath.Join(home, "src/app")
	os.MkdirAll(filepath.Join(project, ".claude"), 0o755)
	os.WriteFile(filepath.Join(project, ".claude/settings.local.json"), []byte(`{"disableAllHooks": true}`), 0o644)
	hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) { m["cwd"] = project }))
	check(1, "project settings.local.json")
	if in := integrityOf(t, d, "hooks_disabled"); in.Tier != "project" {
		t.Fatalf("project event %+v", in)
	}
}

// integrityOf returns the newest integrity event with the check.
func integrityOf(t *testing.T, d *daemon.Daemon, check string) *events.Integrity {
	t.Helper()
	for _, r := range validEvents(t, d) {
		if in := r.Event.Integrity; in != nil && string(in.Check) == check {
			return in
		}
	}
	t.Fatalf("no %s event", check)
	return nil
}
