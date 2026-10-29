package keyset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/internal/trust"
)

func testEnv(t *testing.T) platform.Env {
	data := t.TempDir()
	return platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
}

type key struct {
	role string
	priv ed25519.PrivateKey
}

func newKey(role string) key {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return key{role, priv}
}

func (k key) id() string { return signing.KeyID(k.role, "test-1", k.priv.Public().(ed25519.PublicKey)) }

// set signs a key set listing keys with signer.
func set(t *testing.T, signer key, keys ...key) contract.Envelope {
	var list []map[string]any
	for _, k := range keys {
		list = append(list, map[string]any{"keyid": k.id(), "role": k.role, "not_before": "2026-01-01T00:00:00.000Z",
			"public_key": base64.StdEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))})
	}
	doc, err := json.Marshal(map[string]any{"schema": "privometry.keyset/v1", "version": 1, "issued_at": "2026-01-01T00:00:00.000Z", "keys": list})
	if err != nil {
		t.Fatal(err)
	}
	return signing.Sign(signing.PayloadTypeKeySet, doc, signer.id(), signer.priv)
}

func noRoots(t *testing.T) {
	roots = func() (*signing.KeySet, error) { return nil, trust.ErrNoRootKeys }
	t.Cleanup(func() { roots = trust.RootKeys })
}

func TestPinWithoutBuiltInRoots(t *testing.T) {
	noRoots(t)
	env := testEnv(t)
	root, policy := newKey("root"), newKey("policy")
	got, err := Pin(env, set(t, root, root, policy), time.Now())
	if err != nil || !got.Pinned || len(got.Keys.Keys) != 2 {
		t.Fatalf("pin: %+v %v", got, err)
	}
	loaded, err := Load(env)
	if err != nil || loaded == nil || !loaded.Pinned {
		t.Fatalf("load: %+v %v", loaded, err)
	}
	// Signed by a key it does not list as root: refused.
	if _, err := Pin(env, set(t, policy, root, policy), time.Now()); err == nil || !strings.Contains(err.Error(), "root key") {
		t.Fatalf("signed by the policy key: %v", err)
	}
	if _, err := Pin(env, set(t, newKey("root"), root, policy), time.Now()); err == nil {
		t.Fatal("signed by a root key it does not list")
	}
}

func TestPinWithBuiltInRoots(t *testing.T) {
	env := testEnv(t)
	builtIn, other, policy := newKey("root"), newKey("root"), newKey("policy")
	pub := builtIn.priv.Public().(ed25519.PublicKey)
	ks, _ := signing.ParseKeySet([]byte(`{"schema":"privometry.keyset/v1","version":1,"issued_at":"2026-01-01T00:00:00.000Z","keys":[{"keyid":"` +
		builtIn.id() + `","role":"root","not_before":"2026-01-01T00:00:00.000Z","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}]}`))
	roots = func() (*signing.KeySet, error) { return ks, nil }
	t.Cleanup(func() { roots = trust.RootKeys })
	got, err := Pin(env, set(t, builtIn, other, policy), time.Now())
	if err != nil || got.Pinned {
		t.Fatalf("verified against built-in roots: %+v %v", got, err)
	}
	// A self-signed key set is not enough once roots are built in.
	if _, err := Pin(env, set(t, other, other, policy), time.Now()); err == nil {
		t.Fatal("a key set signed by a root key the build does not know")
	}
}
