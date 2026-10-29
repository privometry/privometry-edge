package daemon_test

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// procTable is a fake process table.
type procTable struct {
	mu    sync.Mutex
	procs map[int]platform.Process
	env   map[int]map[string]string
	cwd   map[int]string
}

func (pt *procTable) add(p platform.Process, cwd string, env map[string]string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.procs[p.PID], pt.cwd[p.PID], pt.env[p.PID] = p, cwd, env
}

func (pt *procTable) remove(pid int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.procs, pid)
}

func (pt *procTable) Procs() daemon.Procs {
	return daemon.Procs{
		List: func() ([]platform.Process, error) {
			pt.mu.Lock()
			defer pt.mu.Unlock()
			var out []platform.Process
			for _, p := range pt.procs {
				out = append(out, p)
			}
			return out, nil
		},
		Info: func(pid int) (platform.Process, error) {
			pt.mu.Lock()
			defer pt.mu.Unlock()
			p, ok := pt.procs[pid]
			if !ok {
				return platform.Process{}, errors.New("no such process")
			}
			p.Args = nil
			return p, nil
		},
		Env: func(pid int, names []string) (map[string]string, error) {
			pt.mu.Lock()
			defer pt.mu.Unlock()
			out := map[string]string{}
			for _, n := range names {
				if v, ok := pt.env[pid][n]; ok {
					out[n] = v
				}
			}
			return out, nil
		},
		Cwd: func(pid int) (string, error) {
			pt.mu.Lock()
			defer pt.mu.Unlock()
			return pt.cwd[pid], nil
		},
	}
}

func TestSilentAgents(t *testing.T) {
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-s-")
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
	for _, agent := range []contract.AgentProduct{contract.AgentProductClaudeCode, contract.AgentProductCodexCLI} {
		a, _ := reg.Get(agent)
		c, err := guard.Install(a, guard.Options{Env: env, HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304"})
		if err != nil || c.Apply() != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(home, "src/off")
	os.MkdirAll(filepath.Join(project, ".claude"), 0o755)
	os.WriteFile(filepath.Join(project, ".claude/settings.local.json"), []byte(`{"disableAllHooks": true}`), 0o644)

	clock := &testClock{now: time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)}
	start := clock.Now()
	pt := &procTable{procs: map[int]platform.Process{}, env: map[int]map[string]string{}, cwd: map[int]string{}}
	claude := func(pid int, args ...string) platform.Process {
		return platform.Process{PID: pid, PPID: 1, Start: start, Args: append([]string{"/home/dev/.local/bin/claude"}, args...)}
	}
	pt.add(claude(100), home, nil)                                                                   // calls its hooks
	pt.add(platform.Process{PID: 101, PPID: 100, Start: start, Args: []string{"/bin/zsh"}}, "", nil) // the shell it runs hooks in
	pt.add(claude(110), home, map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(home, "alt")})
	pt.add(claude(120), project, nil)
	pt.add(claude(130), home, nil)
	pt.add(claude(140, "mcp", "serve"), home, nil)
	pt.add(claude(150, "--dangerously-skip-permissions"), home, nil)
	pt.add(platform.Process{PID: 160, PPID: 1, Start: start, Args: []string{"node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"}}, home, nil)
	pt.add(platform.Process{PID: 170, PPID: 1, Start: start, Args: []string{"/opt/homebrew/bin/gemini"}}, home, nil) // no Privometry hook
	pt.add(platform.Process{PID: 180, PPID: 1, Start: start, Args: []string{"/Applications/ChatGPT.app/Contents/Resources/codex", "app-server"}}, home, nil)

	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Now: clock.Now, Procs: pt.Procs(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	silent := func(want int, why string) {
		t.Helper()
		n, err := d.CheckSilent()
		if err != nil || n != want {
			t.Fatalf("%s: %d events, %v; want %d", why, n, err, want)
		}
	}
	clock.Advance(2 * time.Minute)
	silent(0, "too early")

	// The hook client runs under the agent's shell.
	resp := d.Handle(ipc.Request{V: ipc.Version, Op: "hook", Hook: &ipc.HookRequest{Agent: "claude_code", Event: "SessionStart",
		Payload: []byte(`{"session_id": "s1", "cwd": "/tmp", "hook_event_name": "SessionStart", "source": "startup"}`), PPID: 101}})
	if !resp.OK {
		t.Fatal(resp.Error)
	}
	clock.Advance(2 * time.Minute)
	silent(4, "after three minutes")
	silent(0, "reported once")

	rows, _ := d.Store().Events(timeline.Query{Type: "integrity", Limit: 20})
	got := map[string]string{}
	for _, r := range rows {
		in := r.Event.Integrity
		if in.Check != "hooks_silent" {
			continue
		}
		got[string(in.AgentProduct)+" "+string(in.Reason)] = in.Detail
	}
	for key, want := range map[string]string{
		"claude_code config_dir_override": "CLAUDE_CONFIG_DIR (~/<redacted_path>), which has no Privometry hook",
		"claude_code setting":             "a setting in ~/<redacted_path> turns its hooks off",
		"claude_code unknown":             "has run for 4 minutes",
		"codex_cli untrusted_hook":        "approved",
	} {
		if !strings.Contains(got[key], want) {
			t.Errorf("%s: %q, want it to contain %q (all: %v)", key, got[key], want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("events %v", got)
	}
	validEvents(t, d)

	// The PID comes back as a new process: it is a new agent.
	pt.remove(130)
	silent(0, "gone")
	clock.Advance(5 * time.Minute)
	p := claude(130)
	p.Start = clock.Now().Add(-4 * time.Minute)
	pt.add(p, home, nil)
	silent(1, "same PID, new process")
}

func TestDefinitionsCarryBypassDetectionFields(t *testing.T) {
	reg, _ := registry.Load(adapterdefs.FS)
	claude, _ := reg.Get(contract.AgentProductClaudeCode)
	if len(claude.Detect.NoSessionArgs) == 0 || len(claude.Detect.ProcessPatterns) == 0 || len(claude.Hooks.DisableSettings) == 0 {
		t.Fatalf("Claude Code definition: %+v %+v", claude.Detect, claude.Hooks.DisableSettings)
	}
}
