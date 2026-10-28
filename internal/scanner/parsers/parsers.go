// Package parsers reads agent config files into generic values. Each parser
// returns maps with string keys, slices and scalars, so callers can walk any
// format with the same JSON-pointer lookup.
package parsers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

// MaxSize caps how much of one config file is read. Agent configs are small;
// anything larger is reported rather than parsed.
const MaxSize = 4 << 20

// ErrTooLarge is returned for files over MaxSize.
var ErrTooLarge = errors.New("parsers: file too large")

// Parse decodes raw in the given format: json, jsonc, toml, yaml, markdown or
// mdc (YAML frontmatter only), or starlark (not parsed; returns nil).
func Parse(format string, raw []byte) (any, error) {
	if len(raw) > MaxSize {
		return nil, ErrTooLarge
	}
	switch format {
	case "json":
		return decodeJSON(raw)
	case "jsonc":
		return decodeJSON(stripJSONC(raw))
	case "toml":
		var v map[string]any
		if _, err := toml.Decode(string(raw), &v); err != nil {
			return nil, err
		}
		return v, nil
	case "yaml":
		var v any
		if err := yaml.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return v, nil
	case "markdown", "mdc":
		return Frontmatter(raw)
	case "starlark":
		return nil, nil
	}
	return nil, fmt.Errorf("parsers: unknown format %q", format)
}

func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Frontmatter returns the YAML block between leading "---" lines, or an empty
// map when the file has none.
func Frontmatter(raw []byte) (map[string]any, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return map[string]any{}, nil
	}
	body, _, found := strings.Cut(text[4:], "\n---")
	if !found {
		return nil, errors.New("parsers: unterminated frontmatter")
	}
	out := map[string]any{}
	if err := yaml.Unmarshal([]byte(body), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// stripJSONC removes // and /* */ comments and trailing commas outside strings.
func stripJSONC(raw []byte) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case inString:
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			end := bytes.Index(raw[i+2:], []byte("*/"))
			if end < 0 {
				i = len(raw)
			} else {
				i += end + 3
			}
		case c == ',':
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				continue // trailing comma
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// Lookup follows a JSON pointer (RFC 6901) through parsed values. It returns
// nil when any step is missing.
func Lookup(doc any, pointer string) any {
	if pointer == "" {
		return doc
	}
	cur := doc
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		switch v := cur.(type) {
		case map[string]any:
			var ok bool
			if cur, ok = v[part]; !ok {
				return nil
			}
		case []any: // an array index, such as /workspacePaths/0
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) || strconv.Itoa(i) != part {
				return nil
			}
			cur = v[i]
		default:
			return nil
		}
	}
	return cur
}

// String returns v as a string when it is one.
func String(v any) string {
	s, _ := v.(string)
	return s
}

// Map returns v as a map when it is one.
func Map(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// List returns v as a slice when it is one.
func List(v any) []any {
	l, _ := v.([]any)
	return l
}
