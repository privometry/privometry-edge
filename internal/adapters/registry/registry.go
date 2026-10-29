// Package registry loads adapter definitions (specs/adapter/v1) and answers
// questions about them: which paths an agent uses on this OS, and whether an
// installed version is supported. The types in adapter.gen.go are generated.
package registry

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/specs"
)

// Registry holds validated adapter definitions, sorted by agent.
type Registry struct {
	adapters []Adapter
}

// Load reads every *.yaml in fsys, validates it against the adapter schema and
// decodes it. One invalid definition fails the whole load: a half-loaded set
// would silently drop protection for an agent.
func Load(fsys fs.FS) (*Registry, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	var adapters []Adapter
	for _, f := range files {
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var a Adapter
		if err := specs.DecodeInto("adapter/v1/adapter.schema.json", f, raw, &a); err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		adapters = append(adapters, a)
	}
	return New(adapters)
}

// New builds a registry from validated definitions, such as the adapters of
// a signed adapter set. Two definitions of one agent are an error.
func New(adapters []Adapter) (*Registry, error) {
	r := &Registry{}
	seen := map[contract.AgentProduct]bool{}
	for _, a := range adapters {
		if seen[a.Agent] {
			return nil, fmt.Errorf("registry: %s is defined twice", a.Agent)
		}
		seen[a.Agent] = true
		r.adapters = append(r.adapters, a)
	}
	sort.Slice(r.adapters, func(i, j int) bool { return r.adapters[i].Agent < r.adapters[j].Agent })
	return r, nil
}

// All returns the definitions in agent order.
func (r *Registry) All() []Adapter { return r.adapters }

// Get returns the definition for one agent.
func (r *Registry) Get(agent contract.AgentProduct) (Adapter, bool) {
	for _, a := range r.adapters {
		if a.Agent == agent {
			return a, true
		}
	}
	return Adapter{}, false
}

// Paths returns the path patterns that apply on env's OS: the "any" entries
// followed by the OS-specific ones. Relative patterns are joined to repoRoot,
// or dropped when repoRoot is empty. Environment overrides are applied first,
// then ~ and %VAR% are expanded. Patterns may still contain * globs.
func (a *Adapter) Paths(osPaths map[string][]string, env platform.Env, repoRoot string) ([]string, error) {
	var out []string
	for _, key := range []string{"any", env.OS()} {
		for _, p := range osPaths[key] {
			p = a.applyOverrides(p, env)
			expanded, err := env.ExpandPath(p)
			if err != nil {
				return nil, err
			}
			if !isAbs(expanded, env) {
				if repoRoot == "" {
					continue
				}
				expanded = path.Join(repoRoot, expanded)
			}
			out = append(out, expanded)
		}
	}
	return out, nil
}

// applyOverrides swaps a path prefix for the value of an override variable,
// for example ~/.claude for $CLAUDE_CONFIG_DIR. The prefix must end at a path
// boundary, so ~/.claude does not capture ~/.claude.json.
func (a *Adapter) applyOverrides(p string, env platform.Env) string {
	for _, o := range a.EnvOverrides {
		val := env.Getenv(o.Var)
		if val == "" || !strings.HasPrefix(p, o.Replaces) {
			continue
		}
		rest := p[len(o.Replaces):]
		if rest == "" || rest[0] == '/' || rest[0] == '\\' {
			return val + rest
		}
	}
	return p
}

func isAbs(p string, env platform.Env) bool {
	if env.GOOS == "windows" {
		return len(p) > 2 && p[1] == ':' || strings.HasPrefix(p, `\\`)
	}
	return strings.HasPrefix(p, "/")
}

var versionRE = regexp.MustCompile(`\d+\.\d+\.\d+`)

// ParseVersion extracts the first x.y.z from version command output such as
// "2.1.304 (Claude Code)". It returns "" when there is none.
func ParseVersion(output string) string { return versionRE.FindString(output) }

// Supports reports whether version satisfies the definition's range, such as
// ">=2.1.295 <3.0.0". An unparseable version is not supported.
func (a *Adapter) Supports(version string) bool {
	v, ok := parseTriple(version)
	if !ok {
		return false
	}
	for _, c := range strings.Fields(a.Versions) {
		op := strings.TrimRight(c, "0123456789.")
		bound, ok := parseTriple(c[len(op):])
		if !ok {
			return false
		}
		cmp := compare(v, bound)
		switch op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		case "=", "":
			ok = cmp == 0
		default:
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

func parseTriple(s string) ([3]int, bool) {
	var t [3]int
	parts := strings.Split(ParseVersion(s), ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return t, false
		}
		t[i] = n
	}
	return t, true
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
