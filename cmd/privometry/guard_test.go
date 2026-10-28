package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privometry/privometry-oss/internal/platform"
)

func TestGuardCommands(t *testing.T) {
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-g-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	guardEnv = func() (platform.Env, error) {
		return platform.Env{GOOS: "darwin", Home: home, Getenv: func(k string) string {
			if k == "PRIVOMETRY_HOME" {
				return data
			}
			return ""
		}}, nil
	}
	defer func() { guardEnv = platform.CurrentEnv }()
	hook := filepath.Join(t.TempDir(), "privometry-hook")
	os.WriteFile(hook, []byte("#!/bin/sh\n"), 0o755)
	settings := filepath.Join(home, ".claude", "settings.json")

	call := func(args ...string) (string, int) {
		var out, errOut bytes.Buffer
		code := run(append([]string{"guard"}, args...), &out, &errOut)
		return out.String() + errOut.String(), code
	}

	out, code := call("install", "--agent", "claude_code", "--hook", hook, "--dry-run")
	if code != 0 || !strings.Contains(out, "would change ~/.claude/settings.json") || !strings.Contains(out, "+ ") {
		t.Fatalf("dry run (%d):\n%s", code, out)
	}
	if _, err := os.Stat(settings); err == nil {
		t.Fatal("dry run wrote the file")
	}

	out, code = call("install", "--agent", "claude_code", "--hook", hook)
	if code != 0 || !strings.Contains(out, "hook installed in ~/.claude/settings.json") || !strings.Contains(out, "daemon is not running") {
		t.Fatalf("install (%d):\n%s", code, out)
	}
	out, _ = call("status", "--agent", "claude_code", "--hook", hook, "--format", "json")
	var status []struct{ Agent, State string }
	if err := json.Unmarshal([]byte(out), &status); err != nil || len(status) != 1 || status[0].State != "installed" {
		t.Fatalf("status: %s %v", out, err)
	}
	if out, _ := call("install", "--agent", "claude_code", "--hook", hook); !strings.Contains(out, "already up to date") {
		t.Errorf("second install:\n%s", out)
	}
	if out, code := call("install", "--agent", "cursor", "--hook", hook); code != 0 || !strings.Contains(out, "hook installed in ~/.cursor/hooks.json") {
		t.Errorf("cursor (%d):\n%s", code, out)
	}
	out, code = call("install", "--agent", "codex_cli", "--hook", hook)
	if code != 0 || !strings.Contains(out, "hook installed in ~/.codex/hooks.json") || !strings.Contains(out, "cannot fail closed") ||
		!strings.Contains(out, "Next step: Open Codex, run /hooks") {
		t.Errorf("codex (%d):\n%s", code, out)
	}
	out, _ = call("status", "--agent", "codex_cli", "--hook", hook)
	if !strings.Contains(out, "no calls yet: Open Codex, run /hooks") {
		t.Errorf("codex status:\n%s", out)
	}
	if out, code := call("uninstall", "--agent", "claude_code"); code != 0 || !strings.Contains(out, "hook removed from") {
		t.Errorf("uninstall (%d):\n%s", code, out)
	}
	raw, _ := os.ReadFile(settings)
	if strings.Contains(string(raw), "privometry-hook") {
		t.Errorf("hook left after uninstall:\n%s", raw)
	}
	if _, code := call("install", "--agent", "claude_code", "--hook", filepath.Join(home, "missing")); code != 2 {
		t.Errorf("missing hook binary should be a usage error, got %d", code)
	}
}
