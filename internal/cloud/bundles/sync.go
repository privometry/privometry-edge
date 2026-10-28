package bundles

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/cloud/enroll"
	"github.com/privometry/privometry-oss/internal/cloud/entitlements"
	"github.com/privometry/privometry-oss/internal/cloud/keyset"
	"github.com/privometry/privometry-oss/internal/keystore"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/signing"
	"github.com/privometry/privometry-oss/specs"
)

// Signed bundles (PRD EDGE-27): GET /edge/v1/bundle, verified with the policy
// key of the region's key set before anything uses it. A device refuses a
// bundle for another organization, an older version than it holds, and one
// that has already expired; it keeps enforcing the bundle it holds, expired
// or not, until a good one arrives.

// File is the bundle this device enforces, as the signed envelope it received.
const File = "bundle.json"

// Payload types of the documents a bundle carries.
const (
	PayloadType             = "application/vnd.privometry.bundle+json"
	EntitlementsPayloadType = "application/vnd.privometry.entitlements+json"
)

// MaxSize is the largest bundle the edge accepts (bundle.schema.json).
const MaxSize = 5 << 20

var (
	ErrOtherOrg    = errors.New("bundle is for another organization")
	ErrRollback    = errors.New("bundle is older than the one this device holds")
	ErrExpired     = errors.New("bundle has expired")
	ErrNoKeySet    = errors.New("this device has no key set to verify bundles; enroll it again")
	ErrNotEnrolled = errors.New("this device is not enrolled")
)

// Held is a verified bundle with its verified entitlements.
type Held struct {
	Bundle       *Bundle
	Entitlements *entitlements.Entitlements
	Expired      bool
}

// Verify checks a bundle envelope against the key set: signed by a policy
// key, a valid privometry.bundle/v1 document for orgID, not older than held,
// carrying entitlements signed by a license key for the same organization.
func Verify(raw []byte, ks *signing.KeySet, orgID string, held *Bundle, at time.Time) (*Held, error) {
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
	envelope, err := json.Marshal(b.Entitlements)
	if err != nil {
		return nil, err
	}
	entPayload, err := signing.Verify(envelope, ks, "license", EntitlementsPayloadType, at)
	if err != nil {
		return nil, fmt.Errorf("bundle entitlements: %w", err)
	}
	if err := specs.Validate("entitlements/v1/entitlements.schema.json", "entitlements", entPayload); err != nil {
		return nil, fmt.Errorf("bundle entitlements: %w", err)
	}
	var ent entitlements.Entitlements
	if err := json.Unmarshal(entPayload, &ent); err != nil {
		return nil, fmt.Errorf("bundle entitlements: %w", err)
	}
	if ent.OrgID != orgID {
		return nil, fmt.Errorf("bundle entitlements: %w", ErrOtherOrg)
	}
	return &Held{Bundle: &b, Entitlements: &ent}, nil
}

// Load returns the bundle this device holds, verified again; nil when it holds none.
func Load(env platform.Env, now time.Time) (*Held, error) {
	path, err := bundlePath(env)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id, ks, err := trusted(env)
	if err != nil {
		return nil, err
	}
	// The policy key was valid when the bundle was signed; check it as of then.
	created, err := createdAt(raw)
	if err != nil {
		return nil, err
	}
	h, err := Verify(raw, ks.Keys, id.OrgID, nil, created)
	if err != nil {
		return nil, err
	}
	h.Expired = !now.Before(h.Bundle.ExpiresAt.Time)
	return h, nil
}

// Result is what a sync did.
type Result struct {
	Held    *Held
	Changed bool // a new bundle was stored
}

// Sync fetches the newest bundle as this device and keeps it when it
// verifies. base is the client whose server roots to use (tests set their own).
func Sync(ctx context.Context, base *http.Client, env platform.Env, keys keystore.Store, now time.Time) (*Result, error) {
	id, ks, err := trusted(env)
	if err != nil {
		return nil, err
	}
	held, err := Load(env, now)
	if err != nil {
		held = nil // a held bundle that no longer verifies is replaced, never trusted
	}
	client, err := enroll.MutualTLS(base, id, keys, 30*time.Second)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimSuffix(id.APIBaseURL, "/") + "/bundle"
	if held != nil {
		endpoint += "?current=" + url.QueryEscape(held.Bundle.BundleID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && held != nil:
		return &Result{Held: held}, nil
	case resp.StatusCode != http.StatusOK:
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(raw, &p)
		return nil, fmt.Errorf("bundle: %s answered %d %s", endpoint, resp.StatusCode, strings.TrimSpace(p.Title+" "+p.Detail))
	case len(raw) > MaxSize:
		return nil, errors.New("bundle: larger than 5 MB")
	}
	var current *Bundle
	if held != nil {
		current = held.Bundle
	}
	h, err := Verify(raw, ks.Keys, id.OrgID, current, now)
	if err != nil {
		return nil, err
	}
	if !now.Before(h.Bundle.ExpiresAt.Time) {
		return nil, fmt.Errorf("%w: at %s", ErrExpired, h.Bundle.ExpiresAt.Format(time.RFC3339))
	}
	path, err := bundlePath(env)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return nil, err
	}
	return &Result{Held: h, Changed: true}, nil
}

func trusted(env platform.Env) (*enroll.Identity, *keyset.Trusted, error) {
	id, err := enroll.Load(env)
	if err != nil {
		return nil, nil, err
	}
	if id == nil {
		return nil, nil, ErrNotEnrolled
	}
	ks, err := keyset.Load(env)
	if err != nil {
		return nil, nil, err
	}
	if ks == nil {
		return nil, nil, ErrNoKeySet
	}
	return id, ks, nil
}

func createdAt(raw []byte) (time.Time, error) {
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

func bundlePath(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, File), nil
}
