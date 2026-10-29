package daemon_test

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/timeline"
)

func TestBypassFlags(t *testing.T) {
	data, err := os.MkdirTemp("/tmp", "privometry-b-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	reg, _ := registry.Load(adapterdefs.FS)
	running := [][]string{
		{"/usr/local/bin/agy", "--dangerously-skip-permissions", "fix the build"},
		{"node", "/usr/local/bin/gemini", "--approval-mode", "yolo"},
		{"/Applications/Tools/claude", "--permission-mode=bypassPermissions"},
		{"/opt/homebrew/bin/claude", "--permission-mode", "bypassPermissions"}, // the same agent and flag: one event
		{"/usr/local/bin/codex", "exec", "ls"},
		{"grep", "--yolo"},
		{"copilot", "--yolo-mode-docs"},
		// Renamed: found by the npm package path.
		{"node", "/home/dev/.npm-global/lib/node_modules/@anthropic-ai/claude-code/cli.js", "--dangerously-skip-permissions"},
	}
	d, err := daemon.New(daemon.Config{Env: platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}, Registry: reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Procs: daemon.Procs{List: func() ([]platform.Process, error) {
			var out []platform.Process
			for i, args := range running {
				out = append(out, platform.Process{PID: 100 + i, PPID: 1, Args: args})
			}
			return out, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	details := func() []string {
		rows, _ := d.Store().Events(timeline.Query{Type: "integrity", Limit: 50})
		var out []string
		for _, r := range rows {
			if string(r.Event.Integrity.Check) == "hooks_bypassed" {
				out = append(out, string(r.Event.Integrity.AgentProduct)+": "+r.Event.Integrity.Detail)
			}
		}
		return out
	}
	if n, err := d.CheckBypass(); err != nil || n != 4 {
		t.Fatalf("first check: %d %v (%v)", n, err, details())
	}
	got := strings.Join(details(), "\n")
	for _, want := range []string{"antigravity: Antigravity is running with --dangerously-skip-permissions, which turns its hooks off",
		"gemini_cli: Gemini CLI is running with --approval-mode yolo", "claude_code: Claude Code is running with --permission-mode bypassPermissions",
		"claude_code: Claude Code is running with --dangerously-skip-permissions"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fix the build") {
		t.Error("the command line leaked into an event")
	}
	if n, _ := d.CheckBypass(); n != 0 {
		t.Errorf("a still-running agent is reported once, got %d more", n)
	}
	running = running[1:] // agy stopped
	d.CheckBypass()
	running = append(running, []string{"agy", "--dangerously-skip-permissions"})
	if n, _ := d.CheckBypass(); n != 1 {
		t.Errorf("agy started again: %d events", n)
	}
}
