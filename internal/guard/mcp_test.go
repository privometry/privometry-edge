package guard_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/platform"
)

const (
	shim    = "/opt/privometry/bin/privometry-mcp-shim"
	newShim = "/usr/local/bin/privometry-mcp-shim"
)

const claudeJSON = `{
  "numStartups": 42,
  "mcpServers": {
    "tickets": {"type": "stdio", "command": "python3", "args": ["server.py", "--port", "0"], "env": {"TOKEN_FILE": "~/.tickets"}},
    "docs": {"type": "http", "url": "https://docs.example.com/mcp"}
  },
  "projects": {
    "/home/dev/api": {"allowedTools": [], "mcpServers": {"db": {"command": "npx", "args": ["-y", "@acme/db-mcp@1.2.0"]}}}
  }
}
`

const codexTOML = `# My Codex settings
model = "gpt-6"

[mcp_servers.tickets]
command = "python3" # the ticket server
args = [
  "server.py", # entry point
  "--port", "0",
]
startup_timeout_sec = 20

[mcp_servers.tickets.env]
TOKEN_FILE = "~/.tickets"

[mcp_servers."web search"]
command = "npx"

[mcp_servers.remote]
url = "https://mcp.example.com"

[projects."/home/dev/api"]
trust_level = "trusted"
`

func mcpSetup(t *testing.T, files map[string]string) (*registry.Registry, guard.Options) {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		realPath := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(realPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(realPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	return reg, guard.Options{Env: platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(string) string { return "" }}, Root: root}
}

func apply(t *testing.T, changes []*guard.Change, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if err := c.Apply(); err != nil {
			t.Fatal(err)
		}
	}
}

func byName(t *testing.T, reg *registry.Registry, agent string, opts guard.Options) map[string]guard.MCPServer {
	t.Helper()
	a, _ := reg.Get(contract.AgentProduct(agent))
	servers, err := guard.MCPServers(a, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]guard.MCPServer{}
	for _, s := range servers {
		out[s.Name] = s
	}
	return out
}

func TestWrapClaudeCode(t *testing.T) {
	reg, opts := mcpSetup(t, map[string]string{"/home/dev/.claude.json": claudeJSON})
	a, _ := reg.Get("claude_code")
	changes, err := guard.WrapMCP(a, opts, shim)
	if len(changes) != 1 {
		t.Fatalf("%d changes: %v", len(changes), err)
	}
	after := string(changes[0].After)
	if !strings.Contains(after, `"--agent",`) || !strings.Contains(after, `"numStartups": 42`) || !strings.Contains(after, `"TOKEN_FILE": "~/.tickets"`) {
		t.Errorf("after:\n%s", after)
	}
	apply(t, changes, err)

	servers := byName(t, reg, "claude_code", opts)
	tickets, db, docs := servers["tickets"], servers["db"], servers["docs"]
	if !tickets.Wrapped || tickets.Command != "python3" || !slices.Equal(tickets.Args, []string{"server.py", "--port", "0"}) {
		t.Errorf("tickets %+v", tickets)
	}
	if !db.Wrapped || db.Command != "npx" {
		t.Errorf("project-scoped server in ~/.claude.json: %+v", db)
	}
	if !docs.Remote || docs.Wrapped {
		t.Errorf("remote server must be left alone: %+v", docs)
	}

	again, err := guard.WrapMCP(a, opts, shim)
	if err != nil || len(again) != 0 {
		t.Errorf("wrapping twice changed %d files: %v", len(again), err)
	}
	moved, err := guard.WrapMCP(a, opts, newShim)
	if len(moved) != 1 || !strings.Contains(string(moved[0].After), newShim) || strings.Contains(string(moved[0].After), shim+`"`) {
		t.Errorf("a moved shim must be re-pointed: %v", err)
	}

	undo, err := guard.UnwrapMCP(a, opts)
	apply(t, undo, err)
	servers = byName(t, reg, "claude_code", opts)
	if servers["tickets"].Wrapped || servers["tickets"].Command != "python3" || servers["db"].Command != "npx" {
		t.Errorf("after unwrap: %+v", servers)
	}
}

func TestWrapCodexTOMLKeepsTheFile(t *testing.T) {
	reg, opts := mcpSetup(t, map[string]string{"/home/dev/.codex/config.toml": codexTOML})
	a, _ := reg.Get("codex_cli")
	changes, err := guard.WrapMCP(a, opts, shim)
	if err != nil || len(changes) != 1 {
		t.Fatalf("%d changes: %v", len(changes), err)
	}
	after := string(changes[0].After)
	for _, kept := range []string{"# My Codex settings", "startup_timeout_sec = 20", "[mcp_servers.tickets.env]", `url = "https://mcp.example.com"`, `trust_level = "trusted"`} {
		if !strings.Contains(after, kept) {
			t.Errorf("lost %q:\n%s", kept, after)
		}
	}
	want := `command = "` + shim + `"` + "\n" + `args = ["--agent", "codex_cli", "--server", "tickets", "--", "python3", "server.py", "--port", "0"]`
	if !strings.Contains(after, want) {
		t.Errorf("tickets not wrapped as expected:\n%s", after)
	}
	if !strings.Contains(after, `args = ["--agent", "codex_cli", "--server", "web search", "--", "npx"]`) {
		t.Errorf("a server without args gets them added after command:\n%s", after)
	}
	apply(t, changes, err)
	servers := byName(t, reg, "codex_cli", opts)
	if !servers["tickets"].Wrapped || servers["tickets"].Command != "python3" || !servers["web search"].Wrapped || !servers["remote"].Remote {
		t.Errorf("servers %+v", servers)
	}

	undo, err := guard.UnwrapMCP(a, opts)
	apply(t, undo, err)
	raw, _ := os.ReadFile(filepath.Join(opts.Root, "/home/dev/.codex/config.toml"))
	servers = byName(t, reg, "codex_cli", opts)
	if servers["tickets"].Wrapped || !slices.Equal(servers["tickets"].Args, []string{"server.py", "--port", "0"}) || !strings.Contains(string(raw), "# My Codex settings") {
		t.Errorf("after unwrap %+v\n%s", servers, raw)
	}
}

func TestWrapRefusesWhatItCannotEditSafely(t *testing.T) {
	inline := "[mcp_servers]\ninline = { command = \"python3\", args = [\"s.py\"] }\n"
	reg, opts := mcpSetup(t, map[string]string{
		"/home/dev/.codex/config.toml": inline,
		"/home/dev/.cursor/mcp.json":   "{\n  // my servers\n  \"mcpServers\": {\"x\": {\"command\": \"x\"}}\n}\n",
	})
	codex, _ := reg.Get("codex_cli")
	changes, err := guard.WrapMCP(codex, opts, shim)
	if err != nil || len(changes) != 0 {
		t.Errorf("an inline table must be left alone: %d changes, %v", len(changes), err)
	}
	if s := byName(t, reg, "codex_cli", opts)["inline"]; !strings.Contains(s.Note, "not written as its own") {
		t.Errorf("inline server note %q", s.Note)
	}
	cursor, _ := reg.Get("cursor")
	if _, err := guard.WrapMCP(cursor, opts, shim); err == nil || !strings.Contains(err.Error(), "comments") {
		t.Errorf("JSON with comments: %v", err)
	}
}

// Antigravity, Copilot CLI and Gemini CLI keep their user MCP servers in JSON
// under mcpServers; remote ones (serverUrl, url, httpUrl) are left alone.
func TestWrapNewerAgents(t *testing.T) {
	reg, opts := mcpSetup(t, map[string]string{
		"/home/dev/.gemini/config/mcp_config.json": `{"mcpServers": {"sqlite": {"command": "node", "args": ["sqlite-mcp.js"], "env": {"DB": "/var/app.db"}},
  "remote": {"serverUrl": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer ${TOKEN}"}}}}`,
		"/home/dev/.copilot/mcp-config.json": `{"mcpServers": {"tickets": {"type": "local", "command": "python3", "args": ["server.py"], "tools": ["*"]}}}`,
		"/home/dev/.gemini/settings.json":    `{"theme": "Dracula", "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"]}, "web": {"httpUrl": "https://mcp.example.com"}}}`,
	})
	for _, c := range []struct{ agent, local, remote string }{{"antigravity", "sqlite", "remote"}, {"copilot_cli", "tickets", ""}, {"gemini_cli", "fs", "web"}} {
		a, _ := reg.Get(contract.AgentProduct(c.agent))
		changes, err := guard.WrapMCP(a, opts, shim)
		apply(t, changes, err)
		servers := byName(t, reg, c.agent, opts)
		if s := servers[c.local]; !s.Wrapped || s.Remote {
			t.Errorf("%s %s: %+v", c.agent, c.local, s)
		}
		if c.remote != "" {
			if s := servers[c.remote]; !s.Remote || s.Wrapped {
				t.Errorf("%s %s must be left alone: %+v", c.agent, c.remote, s)
			}
		}
		if len(changes) == 1 && !strings.Contains(string(changes[0].After), `"--agent", "`+c.agent+`"`) &&
			!strings.Contains(string(changes[0].After), `"`+c.agent+`"`) {
			t.Errorf("%s: shim not told its agent:\n%s", c.agent, changes[0].After)
		}
	}
}
