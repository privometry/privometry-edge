// Package riskfeed syncs and holds the risk feed on an enrolled device, and
// computes the tool manifest hashes the feed is keyed by.
package riskfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/cloud/bundles"
	"github.com/privometry/privometry-oss/internal/cloud/enroll"
	"github.com/privometry/privometry-oss/internal/cloud/keyset"
	"github.com/privometry/privometry-oss/internal/keystore"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/signing"
	"github.com/privometry/privometry-oss/specs"
)

// The risk feed on an enrolled device (PRD CP-22; GET /edge/v1/riskfeed): the
// curated feed when the organization has curated_feed, else the community
// feed, verified with the feed key of the region's key set, kept as one merged
// document. Snapshots replace it; deltas apply on top of the sequence they
// name; anything older than what the device holds is refused.

// File is the merged feed in the data directory.
const File = "riskfeed.json"

// PayloadType is the DSSE payload type of feed documents.
const PayloadType = "application/vnd.privometry.riskfeed+json"

// ErrRollback means a document is not newer than the feed the device holds.
var ErrRollback = errors.New("risk feed is not newer than the one this device holds")

// Held is the feed this device holds.
type Held struct {
	Feed      string           `json:"feed"`
	Sequence  int64            `json:"sequence"`
	ExpiresAt time.Time        `json:"expires_at"`
	Entries   map[string]Entry `json:"entries"` // by component_id
}

// Load returns the feed this device holds; nil when it holds none.
func Load(env platform.Env) (*Held, error) {
	path, err := feedPath(env)
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
	var h Held
	return &h, json.Unmarshal(raw, &h)
}

// ByPackage finds the entry for a package (an npm, PyPI or OCI name, or a URL), or nil.
func (h *Held) ByPackage(pkg string) *Entry {
	if h == nil || pkg == "" {
		return nil
	}
	for _, e := range h.Entries {
		if e.Source.Name == pkg {
			e := e
			return &e
		}
	}
	return nil
}

// Sync fetches what is new and keeps it. It reports whether the feed changed.
func Sync(ctx context.Context, base *http.Client, env platform.Env, keys keystore.Store, now time.Time) (bool, error) {
	id, err := enroll.Load(env)
	if err != nil || id == nil {
		return false, err
	}
	ks, err := keyset.Load(env)
	if err != nil || ks == nil {
		return false, fmt.Errorf("risk feed: no key set to verify it with")
	}
	feed := "community"
	if held, err := bundles.Load(env, now); err == nil && held != nil && held.Entitlements.Features["curated_feed"] {
		feed = "curated"
	}
	cur, err := Load(env)
	if err != nil || (cur != nil && cur.Feed != feed) {
		cur = nil // unreadable, or another feed: start from a snapshot
	}
	client, err := enroll.MutualTLS(base, id, keys, 60*time.Second)
	if err != nil {
		return false, err
	}
	doc, err := fetch(ctx, client, strings.TrimSuffix(id.APIBaseURL, "/"), feed, cur, ks.Keys, now)
	if err != nil || doc == nil {
		return false, err
	}
	if doc.Kind == DocumentKindDelta && (cur == nil || doc.BaseSequence == nil || *doc.BaseSequence != cur.Sequence) {
		// A delta that does not apply to what we hold: get the snapshot instead.
		if doc, err = fetch(ctx, client, strings.TrimSuffix(id.APIBaseURL, "/"), feed, nil, ks.Keys, now); err != nil || doc == nil {
			return false, err
		}
	}
	next := &Held{Feed: feed, Sequence: doc.Sequence, ExpiresAt: doc.ExpiresAt.Time, Entries: map[string]Entry{}}
	if doc.Kind == DocumentKindDelta {
		for k, v := range cur.Entries {
			next.Entries[k] = v
		}
		for _, r := range doc.Removed {
			delete(next.Entries, r)
		}
	}
	for _, e := range doc.Entries {
		next.Entries[e.ComponentID] = e
	}
	return true, save(env, next)
}

func fetch(ctx context.Context, client *http.Client, base, feed string, cur *Held, ks *signing.KeySet, now time.Time) (*Document, error) {
	endpoint := base + "/riskfeed?feed=" + feed
	if cur != nil {
		endpoint += fmt.Sprintf("&since=%d", cur.Sequence)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("risk feed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("risk feed: %s answered %d", endpoint, resp.StatusCode)
	}
	payload, err := signing.Verify(raw, ks, "feed", PayloadType, now)
	if err != nil {
		return nil, fmt.Errorf("risk feed: %w", err)
	}
	if err := specs.Validate("riskfeed/v1/riskfeed.schema.json", "riskfeed", payload); err != nil {
		return nil, fmt.Errorf("risk feed: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("risk feed: %w", err)
	}
	if string(doc.Feed) != feed {
		return nil, fmt.Errorf("risk feed: asked for %s, got %s", feed, doc.Feed)
	}
	if cur != nil && doc.Sequence <= cur.Sequence {
		return nil, fmt.Errorf("%w: %d after %d", ErrRollback, doc.Sequence, cur.Sequence)
	}
	return &doc, nil
}

func save(env platform.Env, h *Held) error {
	path, err := feedPath(env)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func feedPath(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, File), nil
}
