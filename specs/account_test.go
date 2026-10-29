package specs_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/privometry/privometry-edge/specs"
)

// accountProof is a CLI key's DSSE proof (account-api/v1 Proof).
type accountProof struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// cliKey is a registered key and its algorithm (ES256 or Ed25519).
type cliKey struct {
	pub any
	alg string
}

// TestAccountProofs checks what the schema cannot: every CLI-key proof in
// the account API examples verifies. A registration proof is signed by the
// key it registers, and its keyid and public_key_sha256 are the SHA-256 of
// that key's SubjectPublicKeyInfo; a sign-in proof names the credential and
// challenge of its request and is signed by a key registered in the examples.
// Every payload is a valid AccountProof. The signature covers DSSE PAE, as for
// Privometry's signed artifacts. The keys are TEST KEYS whose private halves
// come from sha256("privometry-test-key:account:<name>"); never trust them.
func TestAccountProofs(t *testing.T) {
	const dir = "account-api/v1/examples/"
	keys := map[string]cliKey{} // by SHA-256 of the SubjectPublicKeyInfo

	for _, f := range glob(t, dir+"RegistrationComplete/valid/*.json") {
		var doc struct {
			Credential struct {
				Type, Algorithm string
				PublicKey       string `json:"public_key"`
				Proof           accountProof
			}
		}
		readJSON(t, f, &doc)
		c := doc.Credential
		if c.Type != "cli_key" {
			continue
		}
		spki, err := base64.StdEncoding.DecodeString(c.PublicKey)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		pub, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			t.Fatalf("%s: public_key: %v", f, err)
		}
		sum := sha256.Sum256(spki)
		thumb := "sha256:" + hex.EncodeToString(sum[:])
		key := cliKey{pub, c.Algorithm}
		payload := checkProof(t, f, c.Proof, "register", key)
		if c.Proof.Signatures[0].KeyID != thumb || payload["public_key_sha256"] != thumb {
			t.Errorf("%s: keyid and public_key_sha256 must be %s", f, thumb)
		}
		keys[thumb] = key
	}
	if len(keys) == 0 {
		t.Fatal("no CLI keys registered in the examples")
	}

	for _, f := range glob(t, dir+"SignInRequest/valid/*.json") {
		var req struct {
			ChallengeID  string `json:"challenge_id"`
			Method       string
			CredentialID string `json:"credential_id"`
			Proof        accountProof
		}
		readJSON(t, f, &req)
		if req.Method != "cli_key" {
			continue
		}
		payload := checkProof(t, f, req.Proof, "sign_in", keys)
		if req.Proof.Signatures[0].KeyID != req.CredentialID || payload["credential_id"] != req.CredentialID || payload["challenge_id"] != req.ChallengeID {
			t.Errorf("%s: the proof must name the request's credential and challenge", f)
		}
	}

	for _, f := range glob(t, dir+"Proof/valid/*.json") {
		var p accountProof
		readJSON(t, f, &p)
		checkProof(t, f, p, "", keys)
	}
}

// checkProof validates the payload as an AccountProof with the given purpose
// (any when empty) and requires the signature to verify with by, a cliKey
// or a map of them. It returns the decoded payload.
func checkProof(t *testing.T, file string, p accountProof, purpose string, by any) map[string]any {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		t.Fatalf("%s: payload: %v", file, err)
	}
	if err := specs.Validate("account-api/v1/messages.schema.json#/$defs/AccountProof", "payload.json", body); err != nil {
		t.Errorf("%s: payload is not an AccountProof: %v", file, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if purpose != "" && payload["purpose"] != purpose {
		t.Errorf("%s: purpose %v, want %s", file, payload["purpose"], purpose)
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("%s: sig: %v", file, err)
	}
	msg := pae(p.PayloadType, body)
	candidates := []cliKey{}
	switch k := by.(type) {
	case cliKey:
		candidates = append(candidates, k)
	case map[string]cliKey:
		for _, v := range k {
			candidates = append(candidates, v)
		}
	}
	for _, k := range candidates {
		if verifyCLIKey(k, msg, sig) {
			return payload
		}
	}
	t.Errorf("%s: signature does not verify", file)
	return payload
}

func verifyCLIKey(k cliKey, msg, sig []byte) bool {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(msg)
		return k.alg == "ES256" && pub.Curve == elliptic.P256() && ecdsa.VerifyASN1(pub, digest[:], sig)
	case ed25519.PublicKey:
		return k.alg == "Ed25519" && ed25519.Verify(pub, msg, sig)
	}
	return false
}

// pae is DSSE's pre-authentication encoding.
func pae(payloadType string, body []byte) []byte {
	return append([]byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(body))), body...)
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	files, _ := filepath.Glob(pattern)
	if len(files) == 0 {
		t.Fatalf("no files match %s", pattern)
	}
	return files
}

func readJSON(t *testing.T, file string, v any) {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}
