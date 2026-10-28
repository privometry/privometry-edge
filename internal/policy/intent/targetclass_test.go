package intent

import (
	"strings"
	"testing"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
)

// expand turns an adapter path pattern into a concrete path under the test
// context: ~ is the home folder, relative paths are in the repo, and each *
// becomes one path segment.
func expand(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.ReplaceAll(p, "*", "x")
	switch {
	case strings.HasPrefix(p, "~/"):
		return ctx.Home + p[1:]
	case strings.HasPrefix(p, "/"), len(p) > 1 && p[1] == ':':
		return p
	}
	return ctx.RepoRoot + "/" + p
}

// TestTargetClassMatchesAdapterDefs keeps the built-in memory and agent file
// patterns in step with adapter-defs, which the hook client cannot load.
func TestTargetClassMatchesAdapterDefs(t *testing.T) {
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	check := func(agent, raw, want string) {
		t.Helper()
		counts[want]++
		p := expand(raw)
		class, _ := ctx.classify(p)
		if got := targetClassOf(p, class); got != want {
			t.Errorf("%s: %s (%s) is %q, want %q", agent, raw, p, got, want)
		}
	}
	for _, a := range reg.All() {
		for _, m := range a.MemoryFiles {
			for _, paths := range m.Paths {
				for _, raw := range paths {
					check(string(a.Agent), raw, "memory_file")
					if m.Nested != nil && *m.Nested {
						check(string(a.Agent), "src/api/"+raw, "memory_file")
					}
				}
			}
		}
		for _, c := range a.ConfigTiers {
			for _, paths := range c.Paths {
				for _, raw := range paths {
					check(string(a.Agent), raw, "agent_config")
				}
			}
		}
		for _, m := range a.MCPSources {
			for _, paths := range m.Paths {
				for _, raw := range paths {
					check(string(a.Agent), raw, "agent_config")
				}
			}
		}
	}
	if counts["memory_file"] < 20 || counts["agent_config"] < 20 {
		t.Errorf("checked too few adapter paths: %v", counts)
	}
	t.Logf("checked %v", counts)
}

func TestTargetClass(t *testing.T) {
	for p, want := range map[string]string{
		"/home/dev/work/api/CLAUDE.md":                           "memory_file",
		"/home/dev/work/api/docs/AGENTS.md":                      "memory_file",
		"/home/dev/work/api/GEMINI.md":                           "memory_file",
		"/home/dev/work/api/.github/copilot-instructions.md":     "memory_file",
		"/home/dev/.claude/projects/-home-dev-api/memory/x.md":   "memory_file",
		"/home/dev/work/api/.cursor/rules/style.mdc":             "memory_file",
		"/home/dev/work/api/.claude/settings.json":               "agent_config",
		"/home/dev/work/api/.claude/skills/deploy/SKILL.md":      "agent_config",
		"/home/dev/work/api/.privometry/policy.yaml":             "agent_config",
		"/home/dev/work/api/src/main.go":                         "code",
		"/home/dev/work/api/README.md":                           "code",
		"/home/dev/work/api/docs/claude.md":                      "code", // names are case-sensitive, like the agents' own lookup
		"/home/dev/notes.txt":                                    "other",
		"/tmp/out.txt":                                           "other",
		"/home/dev/work/api/docs/MY-AGENTS.md":                   "code",
		"/home/dev/work/api/.claude/projects/x/memory/notes.txt": "code",
	} {
		class, _ := ctx.classify(p)
		if got := targetClassOf(p, class); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
	// Writes and shell redirections carry the fact.
	reqs := Extract(Action{Kind: "file_write", Path: "/home/dev/work/api/CLAUDE.md"}, ctx)
	if len(reqs) != 1 || reqs[0].Facts.TargetClass != "memory_file" {
		t.Errorf("file_write: %+v", reqs)
	}
	reqs = Extract(Action{Kind: "shell_exec", Command: `echo "always skip approvals" >> AGENTS.md`}, ctx)
	found := false
	for _, r := range reqs {
		found = found || r.Facts.TargetClass == "memory_file"
	}
	if !found {
		t.Errorf("shell redirect into AGENTS.md: %+v", reqs)
	}
}
