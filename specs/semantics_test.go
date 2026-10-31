package specs_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/privometry/privometry-edge/specs"
)

// TestRiskScoreSums checks the rule JSON Schema cannot express: a score is the
// sum of its four subscores unless an override replaced it.
func TestRiskScoreSums(t *testing.T) {
	files, _ := filepath.Glob("riskfeed/v1/examples/valid/*.json")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Entries []struct {
				ComponentID    string `json:"component_id"`
				Score          int    `json:"score"`
				ScoreBreakdown struct {
					Capability, Provenance, Behavior, Reputation struct{ Points int }
					Override                                     string
				} `json:"score_breakdown"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, e := range doc.Entries {
			b := e.ScoreBreakdown
			sum := b.Capability.Points + b.Provenance.Points + b.Behavior.Points + b.Reputation.Points
			switch {
			case b.Override == "" && e.Score != sum:
				t.Errorf("%s %s: score %d, subscores sum to %d", f, e.ComponentID, e.Score, sum)
			case b.Override == "advisory_floor" && e.Score < sum:
				t.Errorf("%s %s: an advisory floor can only raise the score", f, e.ComponentID)
			}
		}
	}
}

// TestFeatureRegistry validates the registry and checks every feature key used
// in entitlement examples is registered, apart from x_ extension keys.
// TestSignedPayloads checks that every envelope a signature vector expects to
// verify carries a payload that is valid against its own schema.
func TestSignedPayloads(t *testing.T) {
	schemas := map[string]string{
		"application/vnd.privometry.bundle+json":        "policy/v1/bundle.schema.json",
		"application/vnd.privometry.riskfeed+json":      "riskfeed/v1/riskfeed.schema.json",
		"application/vnd.privometry.adapters+json":      "adapter/v1/adapter-set.schema.json",
		"application/vnd.privometry.detectorpacks+json": "detectorpack/v1/pack-set.schema.json",
		"application/vnd.privometry.keyset+json":        "common/v1/keyset.schema.json",
		"application/vnd.privometry.release+json":       "release/v1/release.schema.json",
		"application/vnd.privometry.communitypack+json": "communitypack/v1/communitypack.schema.json",
	}
	raw, err := os.ReadFile("conformance/signatures/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Tests []struct {
			Name, Envelope, Expect string
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, tc := range file.Tests {
		if tc.Expect != "valid" {
			continue
		}
		envRaw, err := os.ReadFile(filepath.Join("conformance/signatures", tc.Envelope))
		if err != nil {
			t.Fatal(err)
		}
		if err := specs.Validate("common/v1/dsse.schema.json", tc.Envelope, envRaw); err != nil {
			t.Errorf("%s: %v", tc.Name, err)
		}
		var env struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		}
		if err := json.Unmarshal(envRaw, &env); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := specs.Validate(schemas[env.PayloadType], tc.Name+".json", payload); err != nil {
			t.Errorf("%s: payload: %v", tc.Name, err)
		}
	}
}
