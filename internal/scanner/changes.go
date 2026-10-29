package scanner

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/scanner/posture"
)

// ParseChanges reads the files a merge or pull request changes: one per
// line, either a plain path or a line of git diff --name-status (a status
// letter, a tab and the path; renames and copies give two paths, and the
// new one counts). Paths are relative to the repo root.
func ParseChanges(r io.Reader) ([]Change, error) {
	var out []Change
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		c := Change{Path: line}
		if fields := strings.Split(line, "\t"); len(fields) > 1 {
			status := fields[0]
			if status == "" || !strings.Contains("ACDMRTUX", status[:1]) {
				return nil, fmt.Errorf("line %d: %q is not a git --name-status line", n, line)
			}
			c = Change{Path: fields[len(fields)-1], Deleted: status[0] == 'D'}
		}
		c.Path = path.Clean(strings.TrimPrefix(c.Path, "./"))
		if path.IsAbs(c.Path) || c.Path == ".." || strings.HasPrefix(c.Path, "../") {
			return nil, fmt.Errorf("line %d: %q is not relative to the repo root", n, c.Path)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// agentFile is what a repo file is to the agents that read it.
type agentFile struct {
	agents   []string
	product  contract.AgentProduct
	what     string
	severity contract.Risk
}

// classify says whether a repo-relative path is a project-tier file an agent
// reads: config, MCP servers or memory and instructions. Config holding
// hooks, permissions or MCP servers, and MCP declarations, are medium
// severity; instructions, rules and skills are low.
func classify(reg *registry.Registry, osKey, rel string) (agentFile, bool) {
	var f agentFile
	what := map[string]bool{}
	note := func(a registry.Adapter, desc string, sev contract.Risk) {
		if !slices.Contains(f.agents, a.DisplayName) {
			f.agents = append(f.agents, a.DisplayName)
		}
		if f.product == "" {
			f.product = a.Agent
		}
		what[desc] = true
		if posture.Rank(sev) > posture.Rank(f.severity) {
			f.severity = sev
		}
	}
	for _, a := range reg.All() {
		for _, t := range a.ConfigTiers {
			if t.Tier != contract.ConfigTierProject || !matchAny(t.Paths, osKey, rel, false) {
				continue
			}
			sev := contract.RiskLow
			var holds []string
			for _, h := range t.Holds {
				holds = append(holds, string(h))
				switch h {
				case "hooks", "permissions", "mcp_servers", "settings", "plugins":
					sev = contract.RiskMedium
				}
			}
			note(a, strings.ReplaceAll(strings.Join(holds, ", "), "_", " "), sev)
		}
		for _, s := range a.MCPSources {
			if s.Tier == contract.ConfigTierProject && matchAny(s.Paths, osKey, rel, false) {
				note(a, "MCP servers", contract.RiskMedium)
			}
		}
		for _, m := range a.MemoryFiles {
			if m.Tier == contract.ConfigTierProject && matchAny(m.Paths, osKey, rel, m.Nested != nil && *m.Nested) {
				note(a, string(m.Kind), contract.RiskLow)
			}
		}
	}
	if len(f.agents) == 0 {
		return f, false
	}
	var descs []string
	for d := range what {
		descs = append(descs, d)
	}
	slices.Sort(descs)
	f.what = strings.Join(descs, "; ")
	return f, true
}

// matchAny matches rel against an adapter's relative path patterns for os.
// A nested pattern also matches in any folder below the root.
func matchAny(osPaths map[string][]string, osKey, rel string, nested bool) bool {
	for _, key := range []string{"any", osKey} {
		for _, p := range osPaths[key] {
			if path.IsAbs(p) || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "%") {
				continue
			}
			if ok, _ := path.Match(p, rel); ok {
				return true
			}
			if nested {
				for i := strings.Index(rel, "/"); i >= 0; i = nextSlash(rel, i) {
					if ok, _ := path.Match(p, rel[i+1:]); ok {
						return true
					}
				}
			}
		}
	}
	return false
}

func nextSlash(s string, i int) int {
	j := strings.Index(s[i+1:], "/")
	if j < 0 {
		return -1
	}
	return i + 1 + j
}

// changedFiles turns changed agent and policy files into findings.
func changedFiles(reg *registry.Registry, opts Options) []posture.Finding {
	var out []posture.Finding
	for _, c := range opts.Changed {
		verb := "Changed"
		if c.Deleted {
			verb = "Deleted"
		}
		if c.Path == policy.RepoPolicyPath {
			out = append(out, posture.Finding{Check: "agent_file_changed", Severity: contract.RiskMedium, Tier: contract.ConfigTierProject,
				Path: c.Path, Message: verb + " the repo's Privometry policy, whose rules and allowlist apply to everyone working in this repo.",
				Fix: "Review the policy change; run privometry policy test to check it."})
			continue
		}
		f, ok := classify(reg, opts.Env.OS(), c.Path)
		if !ok {
			continue
		}
		out = append(out, posture.Finding{Check: "agent_file_changed", Severity: f.severity, Agent: f.product, Tier: contract.ConfigTierProject,
			Path: c.Path, Message: fmt.Sprintf("%s a file %s reads from this repo (%s).", verb, strings.Join(f.agents, " and "), f.what),
			Fix: "Review the change: agents act on these files without asking, for everyone who opens this repo."})
	}
	return out
}
