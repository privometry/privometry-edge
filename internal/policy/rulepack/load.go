// Package rulepack loads built-in and community rule packs and matches
// their versions against a policy's extends ranges.
package rulepack

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/specs"
)

// Pack is a loaded rule pack: its manifest and every rule from rules/*.yaml.
type Pack struct {
	Manifest Manifest
	Rules    []compiler.Rule
}

// Load reads every <dir>/pack.yaml in fsys and its rule files, validating
// each against its schema.
func Load(fsys fs.FS) ([]Pack, error) {
	manifests, err := fs.Glob(fsys, "*/pack.yaml")
	if err != nil {
		return nil, err
	}
	var packs []Pack
	for _, mpath := range manifests {
		var p Pack
		raw, err := fs.ReadFile(fsys, mpath)
		if err != nil {
			return nil, err
		}
		if err := specs.DecodeInto("rulepack/v1/pack.schema.json", mpath, raw, &p.Manifest); err != nil {
			return nil, fmt.Errorf("rulepack: %w", err)
		}
		files, _ := fs.Glob(fsys, path.Join(path.Dir(mpath), "rules", "*.yaml"))
		sort.Strings(files)
		for _, f := range files {
			raw, err := fs.ReadFile(fsys, f)
			if err != nil {
				return nil, err
			}
			if err := specs.Validate("rulepack/v1/rules.schema.json", f, raw); err != nil {
				return nil, fmt.Errorf("rulepack: %w", err)
			}
			var doc struct {
				Rules []compiler.Rule `yaml:"rules"`
			}
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				return nil, fmt.Errorf("rulepack: %s: %w", f, err)
			}
			p.Rules = append(p.Rules, doc.Rules...)
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Manifest.ID < packs[j].Manifest.ID })
	return packs, nil
}

// Satisfies reports whether version matches a range from a policy's extends:
// "1.2.3" (exact), "1.2" or "~1.2" (same minor), "1" or "^1" (same major),
// "^1.2" (at least 1.2, same major), "~1.0.3" (at least 1.0.3, same minor).
// Pre-release versions never match.
func Satisfies(version, rng string) bool {
	if strings.ContainsAny(version, "-+") {
		return false
	}
	v, ok := triple(version)
	if !ok {
		return false
	}
	op := ""
	if strings.HasPrefix(rng, "^") || strings.HasPrefix(rng, "~") {
		op, rng = rng[:1], rng[1:]
	}
	parts := strings.Split(rng, ".")
	lo, ok := triple(strings.Join(append(parts, "0", "0")[:3], "."))
	if !ok || len(parts) > 3 {
		return false
	}
	if compare(v, lo) < 0 {
		return false
	}
	switch {
	case op == "^" || len(parts) == 1:
		return v[0] == lo[0]
	case op == "~" || len(parts) == 2:
		return v[0] == lo[0] && v[1] == lo[1]
	}
	return compare(v, lo) == 0
}

func triple(s string) ([3]int, bool) {
	var t [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
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
