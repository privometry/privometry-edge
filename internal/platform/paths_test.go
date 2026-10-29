package platform

import (
	"path/filepath"
	"strings"
	"testing"
)

func env(goos string, vars map[string]string) Env {
	home := "/home/dev"
	if goos == "darwin" {
		home = "/Users/dev"
	}
	if goos == "windows" {
		home = `C:\Users\dev`
	}
	return Env{GOOS: goos, Home: home, Getenv: func(k string) string { return vars[k] }}
}

func TestOS(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "macos", "linux": "linux", "windows": "windows", "freebsd": "other"} {
		if got := env(goos, nil).OS(); got != want {
			t.Errorf("OS(%s) = %q, want %q", goos, got, want)
		}
	}
}

func TestLocations(t *testing.T) {
	win := map[string]string{"LOCALAPPDATA": `C:\Users\dev\AppData\Local`, "USERNAME": "dev"}
	tests := []struct {
		name string
		e    Env
		fn   func(Env) (string, error)
		want string
	}{
		{"mac db", env("darwin", nil), Env.DBPath, "/Users/dev/.privometry/privometry.db"},
		{"linux socket", env("linux", nil), Env.IPCAddress, "/home/dev/.privometry/privometryd.sock"},
		{"linux user policy", env("linux", nil), Env.UserPolicyPath, "/home/dev/.privometry/policy.yaml"},
		{"windows db", env("windows", win), Env.DBPath, `C:\Users\dev\AppData\Local\Privometry\privometry.db`},
		{"windows pipe", env("windows", win), Env.IPCAddress, `\\.\pipe\privometry-dev`},
		{"windows pipe for a side-by-side home", env("windows", map[string]string{"USERNAME": "dev", "PRIVOMETRY_HOME": `D:\t\home`}),
			Env.IPCAddress, `\\.\pipe\privometry-dev-18d2cf97`},
	}
	for _, tc := range tests {
		got, err := tc.fn(tc.e)
		if err != nil || got != tc.want {
			t.Errorf("%s = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := env("windows", nil).DataDir(); err == nil {
		t.Error("windows DataDir without LOCALAPPDATA should fail")
	}
}

func TestExpandPath(t *testing.T) {
	win := env("windows", map[string]string{"APPDATA": `C:\Users\dev\AppData\Roaming`, "PROGRAMDATA": `C:\ProgramData`})
	tests := []struct {
		e        Env
		in, want string
	}{
		{env("darwin", nil), "~", "/Users/dev"},
		{env("darwin", nil), "~/.claude/settings.json", "/Users/dev/.claude/settings.json"},
		{env("linux", nil), "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.json"},
		{env("linux", nil), ".mcp.json", ".mcp.json"},
		{win, `%USERPROFILE%\.cursor\mcp.json`, `C:\Users\dev\.cursor\mcp.json`},
		{win, `%appdata%\Cursor\User\settings.json`, `C:\Users\dev\AppData\Roaming\Cursor\User\settings.json`},
		{win, `~\.codex\config.toml`, `C:\Users\dev\.codex\config.toml`},
		{win, `%ProgramData%\OpenAI\Codex\requirements.toml`, `C:\ProgramData\OpenAI\Codex\requirements.toml`},
	}
	for _, tc := range tests {
		got, err := tc.e.ExpandPath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ExpandPath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := win.ExpandPath(`%LOCALAPPDATA%\x`); err == nil {
		t.Error("unset LOCALAPPDATA should fail")
	}
}

func TestDisplayPath(t *testing.T) {
	tests := []struct{ p, home, repo, want string }{
		{"/home/dev/work/api/src/a.go", "/home/dev", "/home/dev/work/api", "src/a.go"},
		{"/home/dev/work/api", "/home/dev", "/home/dev/work/api", "."},
		{"/home/dev/.claude/CLAUDE.md", "/home/dev", "/home/dev/work/api", "~/.claude/CLAUDE.md"},
		{"/home/dev", "/home/dev", "", "~"},
		{"/home/devops/x", "/home/dev", "", "/home/devops/x"},
		{"/etc/claude-code/CLAUDE.md", "/home/dev", "", "/etc/claude-code/CLAUDE.md"},
		{`C:\Users\dev\work\api\src\a.go`, `C:\Users\dev`, `C:\Users\dev\work\api`, "src/a.go"},
		{`C:\Users\dev\.gemini\GEMINI.md`, `C:\Users\dev`, "", "~/.gemini/GEMINI.md"},
		{`C:\ProgramData\x.json`, `C:\Users\dev`, "", `C:\ProgramData\x.json`},
	}
	for _, tc := range tests {
		if got := DisplayPath(tc.p, tc.home, tc.repo); got != tc.want {
			t.Errorf("DisplayPath(%q) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestUnderRoot(t *testing.T) {
	root := filepath.Join("r", "t")
	if got := UnderRoot(root, "/home/dev/.claude"); got != filepath.Join(root, "home", "dev", ".claude") {
		t.Errorf("Unix path: %q", got)
	}
	// A drive letter becomes a folder, so the path stays inside root.
	if got := UnderRoot(root, `C:\Users\dev\x.xml`); strings.Contains(got, ":") || !strings.HasPrefix(got, filepath.Join(root, "C")) {
		t.Errorf("Windows path: %q", got)
	}
	if got := UnderRoot("", "/a/../b"); got != filepath.Join("/b") {
		t.Errorf("empty root: %q", got)
	}
}
