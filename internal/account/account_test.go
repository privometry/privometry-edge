package account

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cloudaccount "github.com/privometry/privometry-edge/internal/cloud/account"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

func TestSealedKey(t *testing.T) {
	priv, err := NewCLIKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(priv, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, priv.Seed()) || strings.Contains(string(sealed), base64.StdEncoding.EncodeToString(priv.Seed())) {
		t.Fatal("the sealed key holds the private key in the clear")
	}
	opened, err := Open(sealed, "correct horse")
	if err != nil || !opened.Equal(priv) {
		t.Fatalf("open: %v", err)
	}
	if _, err := Open(sealed, "correct horsE"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, err := Seal(priv, "12345"); err == nil {
		t.Error("a 5-character PIN must be refused")
	}

	// The ciphertext is bound to the public key stored beside it.
	var s SealedKey
	json.Unmarshal(sealed, &s)
	other, _ := NewCLIKey()
	s.PublicKey, _ = SPKI(other.Public().(ed25519.PublicKey))
	swapped, _ := json.Marshal(s)
	if _, err := Open(swapped, "correct horse"); err == nil {
		t.Error("a sealed key with another public key must not open")
	}
}

func TestSignedProofsMatchTheContract(t *testing.T) {
	priv, _ := NewCLIKey()
	spki, _ := SPKI(priv.Public().(ed25519.PublicKey))
	thumb := Thumbprint(spki)
	proof, err := SignProof(priv, thumb, cloudaccount.AccountProof{Purpose: cloudaccount.AccountProofPurposeRegister,
		Audience: "https://in.api.privometry.dev/account/v1", Challenge: strings.Repeat("A", 43), RegistrationID: contract.NewID("reg"),
		PublicKeySHA256: thumb, IssuedAt: contract.At(time.Now())})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(proof)
	if err := specs.Validate("account-api/v1/messages.schema.json#/$defs/Proof", "proof.json", raw); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(proof.Payload)
	if err := specs.Validate("account-api/v1/messages.schema.json#/$defs/AccountProof", "payload.json", payload); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(proof.Signatures[0].Sig)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), signing.PAE(ProofPayloadType, payload), sig) || proof.Signatures[0].KeyID != thumb {
		t.Fatal("the proof does not verify over PAE with its keyid")
	}
}

func TestClientProblems(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/v1/registrations/reg_x:verify":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(403)
			w.Write([]byte(`{"type":"https://privometry.dev/problems/invalid-code","title":"The code is wrong or expired","status":403,"detail":"That code is not right.","code_attempts_left":3}`))
		case "/account/v1/sign-in/challenges":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		default:
			w.Header().Set("Retry-After", "42")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(429)
			w.Write([]byte(`{"type":"https://privometry.dev/problems/rate-limited","title":"Too many requests","status":429}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL + "/account/v1", HTTP: srv.Client()}
	ctx := context.Background()

	_, err := c.VerifyCode(ctx, "reg_x", "000000")
	var p *Problem
	if !errors.As(err, &p) || p.Kind() != "invalid-code" || p.CodeAttemptsLeft == nil || *p.CodeAttemptsLeft != 3 {
		t.Fatalf("invalid code: %#v", err)
	}
	if _, err := c.ResendCode(ctx, "reg_x"); !IsProblem(err, "rate-limited") || !errors.As(err, &p) || p.RetryAfter != "42" {
		t.Fatalf("rate limited: %v", err)
	}
	if _, err := c.SignInChallenge(ctx, "crd_x"); !IsProblem(err, "about:blank") || !errors.As(err, &p) || p.Status != http.StatusFound {
		t.Fatalf("redirects are not followed: %v", err)
	}
	plain := &Client{BaseURL: "http://in.api.privometry.dev/account/v1", HTTP: http.DefaultClient}
	if _, err := plain.ResendCode(ctx, "reg_x"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plain HTTP must be refused: %v", err)
	}
}
