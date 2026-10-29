package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
)

func writeFile(t *testing.T, root, file, content string) {
	t.Helper()
	path := filepath.Join(root, file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDisabledByUserSetting(t *testing.T) {
	a, opts, path := setup(t, existing, nil)
	c, _ := Install(a, opts)
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), `"model": "opus",`, `"model": "opus", "disableAllHooks": true,`, 1)), 0o644)
	s := Check(a, opts)
	if s.State != "disabled" || s.DisabledBy != "/home/dev/.claude/settings.json" || !strings.Contains(s.Detail, `"disableAllHooks": true`) {
		t.Errorf("status %+v", s)
	}
	// false leaves hooks on.
	os.WriteFile(path, []byte(strings.Replace(string(raw), `"model": "opus",`, `"model": "opus", "disableAllHooks": false,`, 1)), 0o644)
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("disableAllHooks false: %+v", s)
	}
}

func TestCheckDisabledByProjectSetting(t *testing.T) {
	platformtest.UnixPaths(t)
	a, opts, _ := setup(t, "", nil)
	c, _ := Install(a, opts)
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, opts.Root, "home/dev/src/app/.claude/settings.local.json", `{"disableAllHooks": true}`)
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("project files count only with a project: %+v", s)
	}
	opts.Project = "/home/dev/src/app"
	if s := Check(a, opts); s.State != "disabled" || s.DisabledBy != "/home/dev/src/app/.claude/settings.local.json" {
		t.Errorf("status %+v", s)
	}
	// Managed settings count too, and are read first.
	writeFile(t, opts.Root, "etc/claude-code/managed-settings.d/10-team.json", `{"disableAllHooks": true}`)
	if dis := Disabled(a, opts, ""); dis == nil || dis.Path != "/etc/claude-code/managed-settings.d/10-team.json" || dis.Tier != "managed" {
		t.Errorf("managed: %+v", dis)
	}
}

func TestCheckDisabledCodex(t *testing.T) {
	a, opts, _ := agentSetup(t, contract.AgentProductCodexCLI, "home/dev/.codex/config.toml", "[features]\ncodex_hooks = false\n", nil)
	c, _ := Install(a, opts)
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	s := Check(a, opts)
	if s.State != "disabled" || !strings.Contains(s.Detail, "[features] codex_hooks = false") {
		t.Errorf("status %+v", s)
	}
}

func TestCheckDisabledAntigravityEntry(t *testing.T) {
	a, opts, path := agentSetup(t, contract.AgentProductAntigravity, "home/dev/.gemini/config/hooks.json", `{}`, nil)
	c, _ := Install(a, opts)
	if err := c.Apply(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), `"privometry": {`, `"privometry": {"enabled": false,`, 1)), 0o644)
	if s := Check(a, opts); s.State != "disabled" || !strings.Contains(s.Detail, `"enabled": false`) {
		t.Errorf("status %+v", s)
	}
	// Installing again turns the entry back on.
	c, _ = Install(a, opts)
	c.Apply()
	if s := Check(a, opts); s.State != "installed" {
		t.Errorf("after reinstall: %+v", s)
	}
}

func TestDisabledNeedsDisableSettings(t *testing.T) {
	a, opts, _ := agentSetup(t, contract.AgentProductCursor, "home/dev/.cursor/hooks.json", `{}`, nil)
	if dis := Disabled(a, opts, ""); dis != nil {
		t.Errorf("cursor has no disable settings: %+v", dis)
	}
}
