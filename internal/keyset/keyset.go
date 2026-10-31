// Package keyset keeps the region's key set an enrolled device trusts: the
// policy key that signs bundles and the license key that signs entitlements,
// listed in a key set a root key signed (edge-api/v1 EnrollResponse.key_set).
// A build with root keys built in verifies it against them; a build without
// pins it at enrollment after checking that a root key it lists signed it.
package keyset

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/internal/trust"
)

// File is the signed key set in the data directory.
const File = "keyset.json"

// roots returns the built-in root keys; tests replace it.
var roots = trust.RootKeys

// Trusted is the key set a device holds and how it came to trust it.
type Trusted struct {
	Keys   *signing.KeySet
	Pinned bool // no root keys are built in; trusted because enrollment delivered it
}

// Pin verifies the key set from enrollment and keeps it.
func Pin(env platform.Env, signed contract.Envelope, now time.Time) (*Trusted, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	t, err := verify(raw, now)
	if err != nil {
		return nil, err
	}
	dir, err := env.DataDir()
	if err != nil {
		return nil, err
	}
	if err := platform.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, File)
	if err := os.WriteFile(path+".tmp", append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	return t, os.Rename(path+".tmp", path)
}

// Load returns the key set this device holds; nil when it has none.
func Load(env platform.Env) (*Trusted, error) {
	dir, err := env.DataDir()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, File))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e contract.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	ks, err := signedSet(e)
	if err != nil {
		return nil, err
	}
	// Check it as of when it was issued: a key set stays trusted after its issue date.
	return verify(raw, ks.issued)
}

func verify(raw []byte, now time.Time) (*Trusted, error) {
	if r, err := roots(); err == nil {
		payload, err := signing.Verify(raw, r, "root", signing.PayloadTypeKeySet, now)
		if err != nil {
			return nil, fmt.Errorf("key set: %w", err)
		}
		ks, err := signing.ParseKeySet(payload)
		if err != nil {
			return nil, fmt.Errorf("key set: %w", err)
		}
		return &Trusted{Keys: ks}, nil
	} else if !errors.Is(err, trust.ErrNoRootKeys) {
		return nil, err
	}
	var e contract.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	s, err := signedSet(e)
	if err != nil {
		return nil, err
	}
	if _, err := signing.Verify(raw, s.keys, "root", signing.PayloadTypeKeySet, now); err != nil {
		return nil, fmt.Errorf("key set: not signed by a root key it lists: %w", err)
	}
	return &Trusted{Keys: s.keys, Pinned: true}, nil
}

type parsed struct {
	keys   *signing.KeySet
	issued time.Time
}

// signedSet reads the key set inside an envelope without verifying it.
func signedSet(e contract.Envelope) (*parsed, error) {
	if e.PayloadType != signing.PayloadTypeKeySet {
		return nil, fmt.Errorf("key set: payload type %q", e.PayloadType)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	ks, err := signing.ParseKeySet(payload)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	var doc struct {
		IssuedAt contract.Time `json:"issued_at"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	return &parsed{keys: ks, issued: doc.IssuedAt.Time}, nil
}
