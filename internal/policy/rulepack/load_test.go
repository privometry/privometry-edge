package rulepack_test

import (
	"slices"
	"testing"

	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/rulepacks"
)

func TestLoadShippedPacks(t *testing.T) {
	packs, err := rulepack.Load(rulepacks.FS)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range packs {
		ids = append(ids, p.Manifest.ID)
	}
	want := []string{"privometry/agent-instructions", "privometry/core-catastrophic", "privometry/exfiltration", "privometry/mcp-allowlist", "privometry/secrets"}
	if !slices.Equal(ids, want) || len(packs[1].Rules) < 10 {
		t.Fatalf("shipped packs %v, want %v", ids, want)
	}
}

func TestSatisfies(t *testing.T) {
	for _, c := range []struct {
		v, r string
		want bool
	}{
		{"1.0.0", "^1", true}, {"1.9.3", "^1", true}, {"2.0.0", "^1", false}, {"1.2.0", "^1.2", true}, {"1.1.9", "^1.2", false},
		{"1.0.5", "~1.0.3", true}, {"1.1.0", "~1.0.3", false}, {"1.0.2", "~1.0.3", false}, {"1.2.7", "1.2", true},
		{"1.3.0", "1.2", false}, {"1.2.3", "1.2.3", true}, {"1.2.4", "1.2.3", false}, {"1.0.0-beta.1", "^1", false}, {"1", "^1", false},
	} {
		if got := rulepack.Satisfies(c.v, c.r); got != c.want {
			t.Errorf("Satisfies(%s, %s) = %v, want %v", c.v, c.r, got, c.want)
		}
	}
}
