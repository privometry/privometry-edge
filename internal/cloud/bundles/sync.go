// Package bundles fetches the organization's signed policy bundle for an
// enrolled device (GET /edge/v1/bundle) and checks the entitlements it
// carries. The edge verifies and enforces the bundle itself (package bundle);
// entitlements are for the connector only.
package bundles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/entitlements"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

// EntitlementsPayloadType is the DSSE payload type of the entitlements a bundle carries.
const EntitlementsPayloadType = "application/vnd.privometry.entitlements+json"

// Held is a verified bundle with its verified entitlements.
type Held struct {
	Bundle       *bundle.Bundle
	Entitlements *entitlements.Entitlements
	Expired      bool
}

// Verify checks a bundle envelope as the edge does (bundle.Verify), then the
// entitlements it carries: signed by a license key, for the same organization.
func Verify(raw []byte, ks *signing.KeySet, orgID string, held *bundle.Bundle, at time.Time) (*Held, error) {
	b, err := bundle.Verify(raw, ks, orgID, held, at)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("bundle entitlements: %w", bundle.ErrOtherOrg)
	}
	return &Held{Bundle: b, Entitlements: &ent}, nil
}

// Load returns the bundle this device holds with its entitlements, verified
// again; nil when it holds none.
func Load(env platform.Env, now time.Time) (*Held, error) {
	raw, err := bundle.Raw(env)
	if raw == nil || err != nil {
		return nil, err
	}
	org, ks, err := bundle.Trusted(env)
	if err != nil {
		return nil, err
	}
	created, err := bundle.CreatedAt(raw)
	if err != nil {
		return nil, err
	}
	h, err := Verify(raw, ks.Keys, org, nil, created)
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
	id, err := enroll.Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, bundle.ErrNotEnrolled
	}
	org, ks, err := bundle.Trusted(env)
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxSize+1))
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
	case len(raw) > bundle.MaxSize:
		return nil, errors.New("bundle: larger than 5 MB")
	}
	var current *bundle.Bundle
	if held != nil {
		current = held.Bundle
	}
	h, err := Verify(raw, ks.Keys, org, current, now)
	if err != nil {
		return nil, err
	}
	if !now.Before(h.Bundle.ExpiresAt.Time) {
		return nil, fmt.Errorf("%w: at %s", bundle.ErrExpired, h.Bundle.ExpiresAt.Format(time.RFC3339))
	}
	if err := bundle.Store(env, raw); err != nil {
		return nil, err
	}
	return &Result{Held: h, Changed: true}, nil
}
