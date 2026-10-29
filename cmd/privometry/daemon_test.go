package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
)

func TestDaemonCommands(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("service install is macOS and Linux only")
	}
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-s-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	env := platform.Env{GOOS: runtime.GOOS, Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	var calls []string
	daemonEnv = func() (platform.Env, error) { return env, nil }
	serviceRunner = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	defer func() { daemonEnv = platform.CurrentEnv }()
	privometryd := home + "/bin/privometryd"
	os.MkdirAll(home+"/bin", 0o755)
	os.WriteFile(privometryd, []byte("#!/bin/sh\n"), 0o755)

	call := func(args ...string) (string, int) {
		var out, errOut bytes.Buffer
		code := run(append([]string{"daemon"}, args...), &out, &errOut)
		return out.String() + errOut.String(), code
	}

	if out, code := call("install", "--privometryd", privometryd, "--dry-run"); code != 0 || !strings.Contains(out, "Would write") || !strings.Contains(out, privometryd) || len(calls) != 0 {
		t.Fatalf("dry run (%d), calls %v:\n%s", code, calls, out)
	}
	if out, _ := call("status"); !strings.Contains(out, "not installed") || !strings.Contains(out, "not reachable") {
		t.Errorf("status before install:\n%s", out)
	}

	// The fake service manager does not start anything, so run a daemon here.
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	out, code := call("install", "--privometryd", privometryd)
	if code != 0 || !strings.Contains(out, "privometryd is running") || len(calls) == 0 {
		t.Fatalf("install (%d), calls %v:\n%s", code, calls, out)
	}
	out, _ = call("status", "--privometryd", privometryd, "--format", "json")
	var report struct {
		Service struct{ Installed, Current bool }
		Daemon  *struct{ Version, DeviceID string } `json:"daemon"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || !report.Service.Installed || !report.Service.Current || report.Daemon == nil {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	if out, code := call("uninstall"); code != 0 || !strings.Contains(out, "Removed") {
		t.Errorf("uninstall (%d):\n%s", code, out)
	}
	if out, _ := call("status"); !strings.Contains(out, "not installed") {
		t.Errorf("status after uninstall:\n%s", out)
	}
}
