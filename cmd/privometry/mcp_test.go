package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privometry/privometry-oss/internal/platform"
)

func TestMCPCmd(t *testing.T) {
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-m-")
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
	shim := filepath.Join(t.TempDir(), "privometry-mcp-shim")
	os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755)
	config := filepath.Join(home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(config), 0o700)
	original := "# mine\n[mcp_servers.tickets]\ncommand = \"python3\"\nargs = [\"server.py\"]\n\n[mcp_servers.remote]\nurl = \"https://mcp.example.com\"\n"
	os.WriteFile(config, []byte(original), 0o600)

	call := func(args ...string) (string, int) {
		var out, errOut bytes.Buffer
		code := run(append([]string{"mcp"}, args...), &out, &errOut)
		return out.String() + errOut.String(), code
	}
	out, code := call("status", "--agent", "codex_cli")
	if code != 0 || !strings.Contains(out, "tickets") || !strings.Contains(out, "not wrapped") || !strings.Contains(out, "remote") {
		t.Fatalf("status (%d):\n%s", code, out)
	}
	out, _ = call("wrap", "--agent", "codex_cli", "--shim", shim, "--dry-run")
	if !strings.Contains(out, "would change ~/.codex/config.toml") || !strings.Contains(out, "+ args = [\"--agent\", \"codex_cli\"") {
		t.Errorf("dry run:\n%s", out)
	}
	if raw, _ := os.ReadFile(config); string(raw) != original {
		t.Error("a dry run wrote the config")
	}
	out, code = call("wrap", "--agent", "codex_cli", "--shim", shim)
	if code != 0 || !strings.Contains(out, "Codex: wrapped the local MCP servers in ~/.codex/config.toml") || !strings.Contains(out, "Restart the agents") {
		t.Errorf("wrap (%d):\n%s", code, out)
	}
	if out, _ = call("status", "--agent", "codex_cli"); !strings.Contains(out, "wrapped  ") {
		t.Errorf("status after wrap:\n%s", out)
	}
	if out, _ = call("wrap", "--agent", "codex_cli", "--shim", shim); !strings.Contains(out, "Nothing to change") {
		t.Errorf("second wrap:\n%s", out)
	}
	if out, code = call("unwrap", "--agent", "codex_cli"); code != 0 {
		t.Errorf("unwrap (%d):\n%s", code, out)
	}
	if raw, _ := os.ReadFile(config); !strings.Contains(string(raw), "command = \"python3\"") || !strings.Contains(string(raw), "# mine") {
		t.Errorf("after unwrap:\n%s", raw)
	}
	if _, err := os.Stat(config + ".privometry-backup"); err != nil {
		t.Errorf("the first edit keeps a backup: %v", err)
	}
	if _, code = call("bogus"); code != 2 {
		t.Errorf("unknown subcommand exit %d", code)
	}
}
