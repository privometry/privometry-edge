package signing_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/signing"
)

const vectorDir = "../../specs/conformance/signatures"

// TestVectors runs the shared signature vectors. The Java verifier must
// reach the same valid or invalid result for every case.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Schema string `json:"schema"`
		Tests  []struct {
			Name        string    `json:"name"`
			Check       string    `json:"check"`
			Envelope    string    `json:"envelope"`
			KeySet      string    `json:"keyset"`
			Role        string    `json:"role"`
			PayloadType string    `json:"payload_type"`
			VerifyAt    time.Time `json:"verify_at"`
			Expect      string    `json:"expect"`
			Reason      string    `json:"reason"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Schema != "privometry.signaturetest/v1" || len(file.Tests) == 0 {
		t.Fatalf("unexpected vectors file: schema %q, %d tests", file.Schema, len(file.Tests))
	}
	for _, tc := range file.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			ks := loadKeySet(t, tc.KeySet)
			env, err := os.ReadFile(filepath.Join(vectorDir, tc.Envelope))
			if err != nil {
				t.Fatal(err)
			}
			switch tc.Check {
			case "artifact":
				_, err = signing.Verify(env, ks, tc.Role, tc.PayloadType, tc.VerifyAt)
			case "keyset_update":
				_, err = signing.VerifyKeySetUpdate(env, ks, tc.VerifyAt)
			default:
				t.Fatalf("unknown check %q", tc.Check)
			}
			if got := map[bool]string{true: "valid", false: "invalid"}[err == nil]; got != tc.Expect {
				t.Errorf("%s (%s): got %s, err %v", tc.Expect, tc.Reason, got, err)
			}
		})
	}
}

func TestParseKeySetRejectsMismatchedKeyID(t *testing.T) {
	ks, err := os.ReadFile(filepath.Join(vectorDir, "keyset-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(ks, &doc); err != nil {
		t.Fatal(err)
	}
	keys := doc["keys"].([]any)
	keys[0].(map[string]any)["role"] = "policy" // root key relabeled as a policy key
	raw, _ := json.Marshal(doc)
	if _, err := signing.ParseKeySet(raw); err == nil {
		t.Fatal("a key whose ID does not match its role must be rejected")
	}
}

func loadKeySet(t *testing.T, name string) *signing.KeySet {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := signing.ParseKeySet(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}
