package discover

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
)

func TestMCPServerPointerWildcard(t *testing.T) {
	d := discoverer{opts: Options{Env: platform.Env{Home: "/home/dev"}}}
	cf := &ConfigFile{
		Tier: contract.ConfigTierUser,
		Path: "~/.claude.json",
		Doc: map[string]any{
			"projects": map[string]any{
				"/home/dev/work/local-api": map[string]any{
					"mcpServers": map[string]any{
						"local-db": map[string]any{
							"command": "npx",
							"args":    []any{"@example/local-db@2.0.0"},
							"env":     map[string]any{"DATABASE_PASSWORD": "${DATABASE_PASSWORD}"},
						},
					},
				},
			},
		},
	}
	servers := d.mcpServers(cf, "/projects/*/mcpServers")
	if len(servers) != 1 {
		t.Fatalf("servers = %+v", servers)
	}
	s := servers[0]
	if s.Name != "local-db" || s.Command != "npx @example/local-db@2.0.0" || s.Pinned == nil || !*s.Pinned {
		t.Errorf("server = %+v", s)
	}
	if s.Pointer != "/projects/~0~1work~1local-api/mcpServers/local-db" {
		t.Errorf("report pointer = %q", s.Pointer)
	}
	if s.RawPointer != "/projects/~1home~1dev~1work~1local-api/mcpServers/local-db" {
		t.Errorf("raw pointer = %q", s.RawPointer)
	}
	if !slices.Equal(s.EnvNames, []string{"DATABASE_PASSWORD"}) {
		t.Errorf("env names = %v", s.EnvNames)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/home/dev") || strings.Contains(string(raw), "RawPointer") {
		t.Errorf("private pointer leaked in JSON: %s", raw)
	}
}

func TestInstalledPlugins(t *testing.T) {
	d := discoverer{}
	cf := &ConfigFile{Tier: contract.ConfigTierUser, Path: "~/.claude/plugins/installed_plugins.json", Doc: map[string]any{
		"version": float64(2),
		"plugins": map[string]any{
			"swift-lsp@claude-plugins-official": []any{map[string]any{
				"scope": "user", "version": "1.0.0", "installPath": "/private/plugin/cache/swift-lsp",
			}},
		},
	}}
	plugins := d.plugins(cf)
	if len(plugins) != 1 {
		t.Fatalf("plugins = %+v", plugins)
	}
	p := plugins[0]
	if p.ID != "swift-lsp@claude-plugins-official" || p.Name != "swift-lsp" ||
		p.Marketplace != "claude-plugins-official" || p.Version != "1.0.0" || p.Scope != "user" {
		t.Errorf("plugin = %+v", p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "installPath") || strings.Contains(string(raw), "/private/plugin") {
		t.Errorf("installation path leaked in JSON: %s", raw)
	}
}
