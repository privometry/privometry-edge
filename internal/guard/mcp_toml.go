package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/privometry/privometry-oss/internal/contract"
)

// TOML configs (Codex's config.toml) are edited line by line, so comments,
// order and formatting survive: only the command and args lines of a
// server's own [mcp_servers.<name>] table change. Servers written another way
// (inline tables, dotted keys) are reported and left alone. Every edit is
// checked by parsing the result: the server must have the new command and
// arguments and everything else must be unchanged.

func (s mcpSource) editTOML(agent contract.AgentProduct, fn rewrite) ([]MCPServer, []byte, error) {
	var doc map[string]any
	if _, err := toml.Decode(string(s.raw), &doc); err != nil {
		return nil, s.raw, fmt.Errorf("guard: %s is not valid TOML, so Privometry will not edit it: %w", s.display, err)
	}
	table, _ := doc[strings.TrimPrefix(s.pointer, "/")].(map[string]any)
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	slices.Sort(names)

	lines := strings.SplitAfter(string(s.raw), "\n")
	var servers []MCPServer
	want := map[string][2]any{} // server: new command and args
	for _, name := range names {
		entry, _ := table[name].(map[string]any)
		srv := describeTOML(agent, s.display, name, entry)
		header := tomlHeader(lines, name)
		if !srv.Remote && srv.Note == "" && header < 0 {
			srv.Note = "it is not written as its own [mcp_servers." + name + "] table"
		}
		servers = append(servers, srv)
		if fn == nil {
			continue
		}
		cmd, args, ok := fn(srv)
		if !ok || (cmd == stringOf(entry["command"]) && slices.Equal(args, tomlStrings(entry["args"]))) {
			continue
		}
		lines = setTOMLKeys(lines, header, cmd, args)
		want[name] = [2]any{cmd, args}
	}
	if len(want) == 0 {
		return servers, s.raw, nil
	}
	out := []byte(strings.Join(lines, ""))
	if err := checkTOML(doc, out, strings.TrimPrefix(s.pointer, "/"), want); err != nil {
		return servers, s.raw, fmt.Errorf("guard: %s: the edit did not come out as intended, so nothing was changed: %w", s.display, err)
	}
	return servers, out, nil
}

func describeTOML(agent contract.AgentProduct, display, name string, entry map[string]any) MCPServer {
	srv := MCPServer{Agent: agent, Path: display, Name: name}
	cmd := stringOf(entry["command"])
	if cmd == "" {
		srv.Remote = true // Codex runs url servers over streamable HTTP
		return srv
	}
	srv.Command, srv.Args = cmd, tomlStrings(entry["args"])
	if entry["args"] != nil && srv.Args == nil {
		srv.Note = "its args are not a list of strings"
	}
	return unshim(srv)
}

func tomlStrings(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		return stringsOf(list)
	}
	return nil
}

// tomlHeader finds the line of a server's [mcp_servers.<name>] header, or -1.
func tomlHeader(lines []string, name string) int {
	quoted := regexp.QuoteMeta(name)
	re := regexp.MustCompile(`^\s*\[\s*mcp_servers\s*\.\s*(?:` + quoted + `|"` + quoted + `"|'` + quoted + `')\s*\]\s*(?:#.*)?$`)
	for i, l := range lines {
		if re.MatchString(strings.TrimRight(l, "\r\n")) {
			return i
		}
	}
	return -1
}

var (
	tomlTableLine = regexp.MustCompile(`^\s*\[`)
	commandLine   = regexp.MustCompile(`^\s*command\s*=`)
	argsLine      = regexp.MustCompile(`^\s*args\s*=`)
)

// setTOMLKeys replaces the command and args assignments in the table that
// starts at header, adding args after command when the table has none.
func setTOMLKeys(lines []string, header int, cmd string, args []string) []string {
	end := len(lines)
	for i := header + 1; i < len(lines); i++ {
		if tomlTableLine.MatchString(lines[i]) {
			end = i
			break
		}
	}
	cmdAt, argsFrom, argsTo := -1, -1, -1
	for i := header + 1; i < end; i++ {
		switch {
		case cmdAt < 0 && commandLine.MatchString(lines[i]):
			cmdAt = i
		case argsFrom < 0 && argsLine.MatchString(lines[i]):
			argsFrom, argsTo = i, arrayEnd(lines, i)
		}
	}
	vals := make([]string, len(args))
	for i, a := range args {
		vals[i] = tomlString(a)
	}
	newArgs := "args = [" + strings.Join(vals, ", ") + "]\n"
	out := slices.Clone(lines)
	out[cmdAt] = "command = " + tomlString(cmd) + "\n"
	if argsFrom < 0 {
		return slices.Insert(out, cmdAt+1, newArgs)
	}
	return slices.Concat(out[:argsFrom], []string{newArgs}, out[argsTo+1:])
}

// arrayEnd returns the line where the array assigned on line from closes,
// following brackets outside strings and comments.
func arrayEnd(lines []string, from int) int {
	depth, started := 0, false
	for i := from; i < len(lines); i++ {
		var quote byte
		l := lines[i]
		if i == from {
			l = l[strings.Index(l, "=")+1:]
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			switch {
			case quote != 0:
				if c == '\\' && quote == '"' {
					j++
				} else if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '#':
				j = len(l)
			case c == '[':
				depth++
				started = true
			case c == ']':
				depth--
			}
		}
		if started && depth <= 0 {
			return i
		}
	}
	return from
}

// tomlString writes a TOML basic string; JSON's escapes are valid TOML.
func tomlString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // writes to a buffer
	return strings.TrimSuffix(b.String(), "\n")
}

// checkTOML parses the edited file and compares it with the original: only
// the edited servers' command and args may differ, and they must be as wanted.
func checkTOML(before map[string]any, after []byte, key string, want map[string][2]any) error {
	var got map[string]any
	if _, err := toml.Decode(string(after), &got); err != nil {
		return err
	}
	expect := deepCopy(before).(map[string]any)
	table, _ := expect[key].(map[string]any)
	for name, w := range want {
		entry, _ := table[name].(map[string]any)
		if entry == nil {
			return fmt.Errorf("server %s is missing", name)
		}
		entry["command"] = w[0]
		args := make([]any, 0, len(w[1].([]string)))
		for _, a := range w[1].([]string) {
			args = append(args, a)
		}
		entry["args"] = args
	}
	if !reflect.DeepEqual(normalize(expect), normalize(got)) {
		return fmt.Errorf("other settings would change")
	}
	return nil
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

// normalize makes decoded TOML comparable: arrays of tables and arrays of
// strings decode to different Go types depending on their contents.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return v
}
