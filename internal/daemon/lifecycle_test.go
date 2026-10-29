package daemon_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/ipc/ipctest"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
)

func lifecycleDaemon(t *testing.T, home, data string, clock *testClock, boot time.Time) *daemon.Daemon {
	t.Helper()
	reg, _ := registry.Load(adapterdefs.FS)
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Now: clock.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		BootTime: func() (time.Time, error) { return boot, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func spool(t *testing.T, data string, at ...time.Time) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(data, daemon.SpoolFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, a := range at {
		line, _ := json.Marshal(daemon.SpoolEntry{Event: events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"),
			Type: events.EventTypeFailMode, OccurredAt: contract.At(a)}})
		f.Write(append(line, '\n'))
	}
}

func TestSensorStopped(t *testing.T) {
	platformtest.UnixPaths(t)
	home := t.TempDir()
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	boot := t0.Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		stopped bool          // a stop marker after the last alive time
		down    time.Duration // until the next start
		boot    time.Time
		want    events.IntegrityReason // "" for no event
		actions int64
	}{
		{name: "killed", down: 90 * time.Minute, boot: boot, want: events.IntegrityReasonKilled, actions: 2},
		{name: "stopped", stopped: true, down: 90 * time.Minute, boot: boot, want: events.IntegrityReasonStopped, actions: 2},
		{name: "restarted quickly", down: 2 * time.Minute, boot: boot},
		{name: "rebooted", down: 90 * time.Minute, boot: t0.Add(30 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := os.MkdirTemp(ipctest.TempRoot, "privometry-l-")
			defer os.RemoveAll(data)
			clock := &testClock{now: t0}
			first := lifecycleDaemon(t, home, data, clock, tc.boot)
			if ok, err := first.CheckLastRun(); ok || err != nil {
				t.Fatalf("first run: %v %v", ok, err)
			}
			first.MarkAlive()
			if tc.stopped {
				clock.Advance(30 * time.Second)
				first.MarkStopped()
			}
			first.Close()
			// One decision before the last alive time, two while down.
			spool(t, data, t0.Add(-time.Minute), t0.Add(10*time.Minute), t0.Add(20*time.Minute))
			clock.Advance(tc.down)

			d := lifecycleDaemon(t, home, data, clock, tc.boot)
			ok, err := d.CheckLastRun()
			if err != nil || ok != (tc.want != "") {
				t.Fatalf("CheckLastRun: %v %v", ok, err)
			}
			if _, err := os.Stat(filepath.Join(data, daemon.StopFile)); !os.IsNotExist(err) {
				t.Error("the stop marker is kept after a start")
			}
			if tc.want == "" {
				return
			}
			in := integrityOf(t, d, "sensor_stopped")
			if in.Reason != tc.want || in.DownSeconds == nil || *in.DownSeconds < int64(tc.down/time.Second)-60 || in.ActionsWhileDown == nil || *in.ActionsWhileDown != tc.actions {
				t.Errorf("event %+v", in)
			}
			if !strings.Contains(in.Detail, "decided 2 actions") {
				t.Errorf("detail %q", in.Detail)
			}
		})
	}
}

func TestUninstallsReportedByTheCLI(t *testing.T) {
	platformtest.UnixPaths(t)
	home := t.TempDir()
	data, _ := os.MkdirTemp(ipctest.TempRoot, "privometry-u-")
	defer os.RemoveAll(data)
	clock := &testClock{now: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	d := lifecycleDaemon(t, home, data, clock, clock.now.Add(-time.Hour))
	reg, _ := registry.Load(adapterdefs.FS)
	claude, _ := reg.Get(contract.AgentProductClaudeCode)
	gopts := guard.Options{Env: platform.Env{GOOS: "linux", Home: home, Getenv: func(string) string { return "" }},
		HookCommand: "/usr/local/bin/privometry-hook", AgentVersion: "2.1.304"}
	c, _ := guard.Install(claude, gopts)
	c.Apply()
	if _, err := d.CheckIntegrity(); err != nil {
		t.Fatal(err)
	}
	life := func(q daemon.Lifecycle) ipc.Response {
		body, _ := json.Marshal(q)
		return d.Handle(ipc.Request{V: ipc.Version, Op: "lifecycle", Query: body})
	}
	if resp := life(daemon.Lifecycle{Event: "hook_removed", Agent: "claude_code"}); resp.OK {
		t.Fatal("a hook that is still installed was reported removed")
	}
	u, _ := guard.Uninstall(claude, gopts)
	u.Apply()
	if resp := life(daemon.Lifecycle{Event: "hook_removed", Agent: "claude_code"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if in := integrityOf(t, d, "hook_removed"); !strings.Contains(in.Detail, "guard uninstall") || in.Path == "" {
		t.Errorf("hook_removed %+v", in)
	}
	if n, _ := d.CheckIntegrity(); n != 0 {
		t.Errorf("the watcher reported the removal again: %d events", n)
	}
	if resp := life(daemon.Lifecycle{Event: "sensor_uninstalled"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	integrityOf(t, d, "sensor_uninstalled")
	if resp := life(daemon.Lifecycle{Event: "nonsense"}); resp.OK {
		t.Error("unknown lifecycle event accepted")
	}
}
