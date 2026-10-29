// Package rulepacks_test is the release gate for every rule pack in this
// folder; the checks live in internal/policy/packtest so "privometry policy test"
// runs the same ones.
package rulepacks_test

import (
	"path/filepath"
	"testing"

	"github.com/privometry/privometry-edge/internal/policy/packtest"
)

func TestPacks(t *testing.T) {
	manifests, _ := filepath.Glob("*/pack.yaml")
	if len(manifests) < 5 {
		t.Fatalf("expected the five Privometry packs, found %v", manifests)
	}
	community, _ := filepath.Glob("community/*/pack.yaml") // examples, not shipped
	manifests = append(manifests, community...)
	for _, m := range manifests {
		dir := filepath.Dir(m)
		t.Run(dir, func(t *testing.T) {
			r := packtest.Pack(dir)
			for _, p := range r.Problems {
				t.Error(p)
			}
			for _, f := range r.Failures {
				t.Error(f)
			}
			t.Logf("%s: %d rules, %d tests", r.Name, r.Rules, r.Tests)
		})
	}
}
