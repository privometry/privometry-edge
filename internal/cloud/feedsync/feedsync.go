// Package feedsync fetches the risk feed for an enrolled device (GET
// /edge/v1/riskfeed): the curated feed when the organization has
// curated_feed, else the community feed. The edge verifies and holds it
// (package riskfeed).
package feedsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/keyset"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/riskfeed"
	"github.com/privometry/privometry-edge/internal/signing"
)

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
	cur, err := riskfeed.Load(env)
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
	if !riskfeed.Applies(cur, doc) {
		// A delta that does not apply to what we hold: get the snapshot instead.
		if doc, err = fetch(ctx, client, strings.TrimSuffix(id.APIBaseURL, "/"), feed, nil, ks.Keys, now); err != nil || doc == nil {
			return false, err
		}
	}
	return true, riskfeed.Save(env, riskfeed.Apply(cur, feed, doc))
}

func fetch(ctx context.Context, client *http.Client, base, feed string, cur *riskfeed.Held, ks *signing.KeySet, now time.Time) (*riskfeed.Document, error) {
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
	return riskfeed.Verify(raw, ks, feed, cur, now)
}
