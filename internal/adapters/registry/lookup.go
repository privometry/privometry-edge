package registry

import (
	"sort"
	"strings"
)

// Event returns the hook event definition with the agent's event name.
func (a *Adapter) Event(name string) (HookEvent, bool) {
	for _, e := range a.Hooks.Events {
		if e.Name == name {
			return e, true
		}
	}
	return HookEvent{}, false
}

// matchName finds the entry for a tool name in a map keyed by tool name or
// wildcard: an exact key first, then the longest matching wildcard.
func matchName[V any](m map[string]V, name string) (V, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	var keys []string
	for k := range m {
		if strings.Contains(k, "*") && wildcard(k, name) {
			keys = append(keys, k)
		}
	}
	var zero V
	if len(keys) == 0 {
		return zero, false
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	return m[keys[0]], true
}

// wildcard matches name against a pattern where * matches any sequence.
func wildcard(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(name, p)
		}
		j := strings.Index(name, p)
		if j < 0 {
			return false
		}
		name = name[j+len(p):]
	}
	return true
}

// ToolKind maps an agent tool name to a Privometry action kind ("other" if unknown).
func (a *Adapter) ToolKind(tool string) string {
	if k, ok := matchName(a.ToolKinds, tool); ok {
		return string(k)
	}
	return "other"
}

// ToolTarget returns where a tool's command, path, URL, query or patch sits
// in its tool_input.
func (a *Adapter) ToolTarget(tool string) (AdapterToolTarget, bool) {
	return matchName(a.ToolTargets, tool)
}

// MCPTool splits an MCP tool name using the adapter's name template, for
// example mcp__github__create_issue into github and create_issue. Server is
// empty when the template has no {server}.
func (a *Adapter) MCPTool(name string) (server, tool string, ok bool) {
	if a.MCPTools == nil {
		return "", "", false
	}
	tpl := a.MCPTools.NameTemplate
	si, ti := strings.Index(tpl, "{server}"), strings.Index(tpl, "{tool}")
	switch {
	case ti < 0:
		return "", "", false
	case si < 0:
		prefix := tpl[:ti]
		if !strings.HasPrefix(name, prefix) {
			return "", "", false
		}
		return "", name[len(prefix):], true
	}
	prefix, sep := tpl[:si], tpl[si+len("{server}"):ti]
	if !strings.HasPrefix(name, prefix) {
		return "", "", false
	}
	rest := name[len(prefix):]
	i := strings.Index(rest, sep)
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i+len(sep):], true
}

// MCPToolOf returns the tool part of an MCP tool name when the server is
// known from the payload, which settles names the template alone cannot
// split, such as mcp_my_server_list_files with server my_server.
func (a *Adapter) MCPToolOf(name, server string) (string, bool) {
	if a.MCPTools == nil || !strings.Contains(a.MCPTools.NameTemplate, "{server}") {
		return "", false
	}
	tpl := strings.Replace(a.MCPTools.NameTemplate, "{server}", server, 1)
	ti := strings.Index(tpl, "{tool}")
	if ti < 0 || !strings.HasPrefix(name, tpl[:ti]) || len(name) == ti {
		return "", false
	}
	return name[ti:], true
}
