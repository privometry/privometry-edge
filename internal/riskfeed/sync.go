// Package riskfeed verifies and holds the risk feed, and computes the tool
// manifest hashes the feed is keyed by. A connector fetches feed documents.
package riskfeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

// The risk feed (PRD CP-22) is verified with the feed key of the region's key
// set and kept as one merged document. Snapshots replace it; deltas apply on
// top of the sequence they name; anything older than what the device holds is
// refused.

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

// Verify checks a feed document against the key set: signed by a feed key, a
// valid privometry.riskfeed/v1 document of the feed asked for, and newer than
// what the device holds (cur).
func Verify(raw []byte, ks *signing.KeySet, feed string, cur *Held, now time.Time) (*Document, error) {
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

// Applies reports whether doc can be applied to cur: a snapshot always can, a
// delta only on top of the sequence it names.
func Applies(cur *Held, doc *Document) bool {
	return doc.Kind != DocumentKindDelta || (cur != nil && doc.BaseSequence != nil && *doc.BaseSequence == cur.Sequence)
}

// Apply is cur with doc applied; doc must apply (Applies).
func Apply(cur *Held, feed string, doc *Document) *Held {
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
	return next
}

// Save keeps h as the feed this device holds.
func Save(env platform.Env, h *Held) error {
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
