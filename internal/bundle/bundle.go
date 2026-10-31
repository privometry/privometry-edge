// Package bundle verifies and holds the signed organization policy bundle a
// device enforces (privometry.bundle/v1, PRD EDGE-27), and evaluates its
// approved catalog. A connector fetches bundles and stores them with Store;
// the edge loads the held one, verified again, as its org policy layer.
//
// A bundle is signed with the policy key of the region's key set (package
// keyset) and names one organization: the one in the device's enrollment
// record. The device refuses a bundle for another organization or older than
// the one it holds, and keeps enforcing the bundle it holds, expired or not,
// until a good one arrives.
package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-edge/internal/keyset"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

// File is the bundle this device enforces, as the signed envelope it received.
const File = "bundle.json"

// EnrollmentFile is the connector's record of the device's enrollment; the
// edge reads only its org_id, the organization bundles must name.
const EnrollmentFile = "device.json"

// PayloadType is the DSSE payload type of a bundle.
const PayloadType = "application/vnd.privometry.bundle+json"

// MaxSize is the largest bundle the edge accepts (bundle.schema.json).
const MaxSize = 5 << 20

var (
	// ErrOtherOrg means the bundle names an organization other than this device's.
	ErrOtherOrg = errors.New("bundle is for another organization")
	// ErrRollback means the bundle is older than the one this device holds.
	ErrRollback = errors.New("bundle is older than the one this device holds")
	// ErrExpired means the bundle's expiry has passed.
	ErrExpired = errors.New("bundle has expired")
	// ErrNoKeySet means the device has no key set to verify bundles with.
	ErrNoKeySet = errors.New("this device has no key set to verify bundles; enroll it again")
	// ErrNotEnrolled means the device is not enrolled in an organization.
	ErrNotEnrolled = errors.New("this device is not enrolled")
)

// Held is a verified bundle.
type Held struct {
	Bundle  *Bundle
	Expired bool
}

// Verify checks a bundle envelope against the key set: signed by a policy
// key, a valid privometry.bundle/v1 document for orgID, not older than held.
// The entitlements it carries are signed separately and are the connector's
// to check; the edge never reads them.
func Verify(raw []byte, ks *signing.KeySet, orgID string, held *Bundle, at time.Time) (*Bundle, error) {
	payload, err := signing.Verify(raw, ks, "policy", PayloadType, at)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if err := specs.Validate("policy/v1/bundle.schema.json", "bundle", payload); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if b.OrgID != orgID {
		return nil, fmt.Errorf("%w: %s, not %s", ErrOtherOrg, b.OrgID, orgID)
	}
	if held != nil && b.Version < held.Version {
		return nil, fmt.Errorf("%w: version %d after %d", ErrRollback, b.Version, held.Version)
	}
	return &b, nil
}

// Load returns the bundle this device holds, verified again; nil when it holds none.
func Load(env platform.Env, now time.Time) (*Held, error) {
	raw, err := Raw(env)
	if raw == nil || err != nil {
		return nil, err
	}
	org, ks, err := Trusted(env)
	if err != nil {
		return nil, err
	}
	// The policy key was valid when the bundle was signed; check it as of then.
	created, err := CreatedAt(raw)
	if err != nil {
		return nil, err
	}
	b, err := Verify(raw, ks.Keys, org, nil, created)
	if err != nil {
		return nil, err
	}
	return &Held{Bundle: b, Expired: !now.Before(b.ExpiresAt.Time)}, nil
}

// Raw is the held bundle's envelope as stored, unverified; nil when there is none.
func Raw(env platform.Env) ([]byte, error) {
	path, err := Path(env)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// Store keeps a bundle envelope the caller has verified as the one this
// device enforces.
func Store(env platform.Env, raw []byte) error {
	path, err := Path(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// Trusted is the organization bundles must name and the key set that verifies
// them; ErrNotEnrolled or ErrNoKeySet when the device lacks either.
func Trusted(env platform.Env) (string, *keyset.Trusted, error) {
	org, err := enrolledOrg(env)
	if err != nil {
		return "", nil, err
	}
	if org == "" {
		return "", nil, ErrNotEnrolled
	}
	ks, err := keyset.Load(env)
	if err != nil {
		return "", nil, err
	}
	if ks == nil {
		return "", nil, ErrNoKeySet
	}
	return org, ks, nil
}

// CreatedAt reads a bundle envelope's created_at without verifying it.
func CreatedAt(raw []byte) (time.Time, error) {
	var e struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return time.Time{}, fmt.Errorf("bundle: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return time.Time{}, fmt.Errorf("bundle: %w", err)
	}
	var b struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(payload, &b); err != nil {
		return time.Time{}, fmt.Errorf("bundle: %w", err)
	}
	return b.CreatedAt, nil
}

// Path is where the held bundle lives.
func Path(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, File), nil
}

// enrolledOrg is the org_id of the device's enrollment record, "" when it has none.
func enrolledOrg(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(dir, EnrollmentFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var rec struct {
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", fmt.Errorf("enrollment record: %w", err)
	}
	return rec.OrgID, nil
}
