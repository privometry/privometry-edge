package parsers_test

import (
	"testing"

	"github.com/privometry/privometry-oss/internal/scanner/parsers"
)

func TestFormats(t *testing.T) {
	cases := []struct {
		format, input, pointer, want string
	}{
		{"json", `{"mcpServers":{"gh":{"command":"npx"}}}`, "/mcpServers/gh/command", "npx"},
		{"jsonc", "{\n // comment with \"quotes\"\n \"a\": \"http://x\", /* block */ \"b\": [1,2,],\n}", "/a", "http://x"},
		{"toml", "approval_policy = \"never\"\n[mcp_servers.docs]\ncommand = \"uvx\"\n", "/mcp_servers/docs/command", "uvx"},
		{"yaml", "a:\n  b: c\n", "/a/b", "c"},
		{"markdown", "---\nname: review\ndescription: Reviews code\n---\n# Body\n", "/name", "review"},
		{"mdc", "no frontmatter here", "/name", ""},
	}
	for _, c := range cases {
		doc, err := parsers.Parse(c.format, []byte(c.input))
		if err != nil {
			t.Errorf("%s: %v", c.format, err)
			continue
		}
		if got := parsers.String(parsers.Lookup(doc, c.pointer)); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.format, c.pointer, got, c.want)
		}
	}
}

func TestErrors(t *testing.T) {
	for format, input := range map[string]string{
		"json": `{"a":`, "toml": "a = ", "markdown": "---\nname: x\n",
	} {
		if _, err := parsers.Parse(format, []byte(input)); err == nil {
			t.Errorf("%s: want an error for %q", format, input)
		}
	}
	if _, err := parsers.Parse("json", make([]byte, parsers.MaxSize+1)); err != parsers.ErrTooLarge {
		t.Errorf("oversized file: %v", err)
	}
}

func TestLookupArrays(t *testing.T) {
	doc, _ := parsers.Parse("json", []byte(`{"workspacePaths":["/home/dev/api","/home/dev/web"],"a":{"0":"key"}}`))
	for pointer, want := range map[string]string{
		"/workspacePaths/0": "/home/dev/api", "/workspacePaths/1": "/home/dev/web", "/workspacePaths/2": "",
		"/workspacePaths/-1": "", "/workspacePaths/01": "", "/workspacePaths/x": "", "/a/0": "key",
	} {
		if got := parsers.String(parsers.Lookup(doc, pointer)); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", pointer, got, want)
		}
	}
}
