package riskfeed

import (
	"encoding/json"
	"os"
	"testing"
)

// The shared vectors are what ManifestHash computes; the platform must match them.
func TestManifestVectorsAreCurrent(t *testing.T) {
	raw, err := os.ReadFile("../../specs/conformance/riskfeed/manifest-hashes.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name  string `json:"name"`
			Tools []any  `json:"tools"`
			Hash  string `json:"tool_manifest_hash"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Cases {
		if got := ManifestHash(c.Tools); got != c.Hash {
			t.Errorf("%s: %s, vectors say %s (run go run ./scripts/gen-conformance)", c.Name, got, c.Hash)
		}
	}
}

func TestManifestHashIgnoresWhatIsNotTheManifest(t *testing.T) {
	a := []any{map[string]any{"name": "x", "description": "d", "annotations": map[string]any{"readOnlyHint": true}}}
	b := []any{map[string]any{"description": "d", "name": "x"}}
	if ManifestHash(a) != ManifestHash(b) {
		t.Error("annotations are not part of the manifest")
	}
	c := []any{map[string]any{"description": "d!", "name": "x"}}
	if ManifestHash(b) == ManifestHash(c) {
		t.Error("a changed description changes the hash")
	}
}
