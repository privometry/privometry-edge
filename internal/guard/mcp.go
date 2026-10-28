package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
)

// Local stdio MCP servers in an agent's user-tier config can be wrapped so
// they run through privometry-mcp-shim (PRD EDGE-25):
//
//	"tickets": {"command": "python3", "args": ["server.py"]}
//
// becomes
//
//	"tickets": {"command": "/path/privometry-mcp-shim",
//	            "args": ["--agent", "claude_code", "--server", "tickets", "--", "python3", "server.py"]}
//
// Everything else about the server (env, cwd, timeouts) stays as it was, and
// the original command and arguments come back with UnwrapMCP. Remote (http)
// servers are left alone; project-tier configs belong to the repo and are not
// edited.

// ShimName is the shim's binary name; a wrapped server's command ends in it.
const ShimName = "privometry-mcp-shim"

// MCPServer is one MCP server in an agent's user-tier config.
type MCPServer struct {
	Agent   contract.AgentProduct `json:"agent"`
	Path    string                `json:"path"`
	Name    string                `json:"name"`
	Remote  bool                  `json:"remote"`
	Wrapped bool                  `json:"wrapped"`
	// Command and Args are what the server runs, without the shim.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Note says why a server cannot be wrapped, if it cannot.
	Note string `json:"note,omitempty"`
}

// MCPServers lists the MCP servers in the agent's user-tier configs.
func MCPServers(a registry.Adapter, opts Options) ([]MCPServer, error) {
	var out []MCPServer
	err := eachMCPSource(a, opts, func(src mcpSource) error {
		servers, _, err := src.edit(a.Agent, nil)
		out = append(out, servers...)
		return err
	})
	return out, err
}

// WrapMCP computes the edits that run each local stdio server through the
// shim at shimPath. A server already wrapped with another shim path is
// pointed at this one.
func WrapMCP(a registry.Adapter, opts Options, shimPath string) ([]*Change, error) {
	return editMCP(a, opts, func(s MCPServer) (string, []string, bool) {
		if s.Remote || s.Note != "" {
			return "", nil, false
		}
		return shimPath, shimArgs(a.Agent, s), true
	})
}

// UnwrapMCP computes the edits that restore each wrapped server's own command.
func UnwrapMCP(a registry.Adapter, opts Options) ([]*Change, error) {
	return editMCP(a, opts, func(s MCPServer) (string, []string, bool) {
		if !s.Wrapped {
			return "", nil, false
		}
		return s.Command, s.Args, true
	})
}

func shimArgs(agent contract.AgentProduct, s MCPServer) []string {
	return append([]string{"--agent", string(agent), "--server", s.Name, "--", s.Command}, s.Args...)
}

// rewrite decides a server's new command and arguments; ok false leaves it.
type rewrite func(MCPServer) (command string, args []string, ok bool)

func editMCP(a registry.Adapter, opts Options, fn rewrite) ([]*Change, error) {
	byFile := map[string]*Change{}
	var order []string
	err := eachMCPSource(a, opts, func(src mcpSource) error {
		c, ok := byFile[src.real]
		if !ok {
			raw, err := os.ReadFile(src.real)
			if err != nil {
				return err
			}
			c = &Change{Agent: string(a.Agent), Path: src.display, real: src.real, Before: raw, After: raw}
			byFile[src.real] = c
			order = append(order, src.real)
		}
		src.raw = c.After
		servers, after, err := src.edit(a.Agent, fn)
		if err != nil {
			return err
		}
		c.After = after
		for _, s := range servers {
			if s.Note != "" && !s.Remote {
				c.Warnings = append(c.Warnings, s.Name+": "+s.Note)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []*Change
	for _, real := range order {
		c := byFile[real]
		if c.Changed() {
			out = append(out, c)
		}
	}
	return out, nil
}

// mcpSource is one user-tier MCP source that exists on disk.
type mcpSource struct {
	display, real, format, pointer string
	raw                            []byte
}

func eachMCPSource(a registry.Adapter, opts Options, fn func(mcpSource) error) error {
	for _, src := range a.MCPSources {
		if src.Tier != contract.ConfigTierUser {
			continue
		}
		paths, err := a.Paths(src.Paths, opts.Env, "")
		if err != nil {
			return err
		}
		for _, p := range paths {
			real := filepath.Join(opts.Root, p)
			raw, err := os.ReadFile(real)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if err := fn(mcpSource{display: p, real: real, format: string(src.Format), pointer: src.Pointer, raw: raw}); err != nil {
				return err
			}
		}
	}
	return nil
}

// edit lists the source's servers and, with fn, rewrites them, returning the
// new file content.
func (s mcpSource) edit(agent contract.AgentProduct, fn rewrite) ([]MCPServer, []byte, error) {
	switch s.format {
	case "json", "jsonc":
		return s.editJSON(agent, fn)
	case "toml":
		return s.editTOML(agent, fn)
	}
	return nil, s.raw, fmt.Errorf("guard: %s: %s MCP configs are not supported", s.display, s.format)
}

func (s mcpSource) editJSON(agent contract.AgentProduct, fn rewrite) ([]MCPServer, []byte, error) {
	doc, err := parseOrdered(s.raw)
	if err != nil {
		return nil, s.raw, fmt.Errorf("guard: %s is not plain JSON (comments are not supported), so Privometry will not edit it: %w", s.display, err)
	}
	var servers []MCPServer
	changed := false
	for _, m := range objectsAt(doc, strings.Split(strings.TrimPrefix(s.pointer, "/"), "/")) {
		for _, name := range m.keys {
			entry, ok := m.get(name).(*object)
			if !ok {
				continue
			}
			srv := describeJSON(agent, s.display, name, entry)
			servers = append(servers, srv)
			if fn == nil {
				continue
			}
			if cmd, args, ok := fn(srv); ok && (cmd != stringOf(entry.get("command")) || !slices.Equal(args, stringsOf(entry.get("args")))) {
				entry.set("command", cmd)
				vals := make([]any, len(args))
				for i, a := range args {
					vals[i] = a
				}
				entry.set("args", vals)
				changed = true
			}
		}
	}
	if !changed {
		return servers, s.raw, nil
	}
	return servers, encode(doc), nil
}

func describeJSON(agent contract.AgentProduct, display, name string, entry *object) MCPServer {
	srv := MCPServer{Agent: agent, Path: display, Name: name}
	typ := stringOf(entry.get("type"))
	cmd := stringOf(entry.get("command"))
	if cmd == "" || (typ != "" && typ != "stdio" && typ != "local") { // Copilot CLI says local
		srv.Remote = true
		return srv
	}
	srv.Command, srv.Args = cmd, stringsOf(entry.get("args"))
	if entry.get("args") != nil && srv.Args == nil {
		srv.Note = "its args are not a list of strings"
	}
	return unshim(srv)
}

// unshim reads a wrapped server's own command from the shim's arguments.
func unshim(s MCPServer) MCPServer {
	if path.Base(filepath.ToSlash(s.Command)) != ShimName {
		return s
	}
	i := slices.Index(s.Args, "--")
	if i < 0 || i+1 >= len(s.Args) {
		s.Note = "it runs " + ShimName + " without a server command"
		return s
	}
	s.Wrapped = true
	s.Command, s.Args = s.Args[i+1], slices.Clone(s.Args[i+2:])
	return s
}

// objectsAt returns the objects at a JSON pointer whose segments may be *.
func objectsAt(o *object, segs []string) []*object {
	if len(segs) == 0 || (len(segs) == 1 && segs[0] == "") {
		return []*object{o}
	}
	var next []*object
	if segs[0] == "*" {
		for _, k := range o.keys {
			if c, ok := o.get(k).(*object); ok {
				next = append(next, c)
			}
		}
	} else if c, ok := o.get(strings.NewReplacer("~1", "/", "~0", "~").Replace(segs[0])).(*object); ok {
		next = append(next, c)
	}
	var out []*object
	for _, c := range next {
		out = append(out, objectsAt(c, segs[1:])...)
	}
	return out
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// stringsOf returns a list of strings, or nil for anything else.
func stringsOf(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}
