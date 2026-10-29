package riskfeed_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/cloudtest"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/riskfeed"
)

func entry(id, pkg string, score int, verdict string, signals ...string) map[string]any {
	level := map[bool]string{true: "critical", false: "low"}[score >= 75]
	if signals == nil {
		signals = []string{}
	}
	sub := func(p int) map[string]any { return map[string]any{"points": p, "signals": []string{}} }
	bd := map[string]any{"capability": sub(0), "provenance": sub(0), "behavior": sub(0), "reputation": sub(score % 26)}
	if score == 100 {
		bd["override"] = "known_malicious"
	}
	return map[string]any{"component_id": id, "kind": "mcp_server", "source": map[string]any{"ecosystem": "npm", "name": pkg},
		"versions": []any{map[string]any{"version": "1.0.0"}}, "score": score, "level": level, "signals": signals, "default_verdict": verdict,
		"updated_at": "2026-10-28T00:00:00.000Z", "curation": "community", "score_breakdown": bd}
}

func doc(kind string, seq int, base int, entries []any, removed []string) map[string]any {
	d := map[string]any{"schema": "privometry.riskfeed/v1", "feed": "curated", "kind": kind, "sequence": seq, "published_at": "2026-10-28T00:00:00.000Z",
		"expires_at": "2026-11-04T00:00:00.000Z", "methodology_version": "1.0.0", "entries": entries}
	if kind == "delta" {
		d["base_sequence"] = base
		if removed == nil {
			removed = []string{}
		}
		d["removed"] = removed
	}
	return d
}

func TestSyncSnapshotsAndDeltas(t *testing.T) {
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	keys, _ := keystore.Open(env, "file")
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	// No bundle yet, so the device asks for the community feed: serve the same documents under that name.
	a, b := "mcp_01JA0000000000000000000001", "mcp_01JA0000000000000000000002"
	snap := doc("snapshot", 5, 0, []any{entry(a, "@acme/files", 10, "allow"), entry(b, "@acme/shell", 20, "allow")}, nil)
	snap["feed"] = "community"
	edge.FeedDocument(t, snap)
	ctx := context.Background()
	if changed, err := riskfeed.Sync(ctx, edge.Client(), env, keys, time.Now()); err != nil || !changed {
		t.Fatalf("first sync: %v %v", changed, err)
	}
	held, _ := riskfeed.Load(env)
	if held.Sequence != 5 || len(held.Entries) != 2 || held.ByPackage("@acme/files").Score != 10 {
		t.Fatalf("held: %+v", held)
	}
	if changed, err := riskfeed.Sync(ctx, edge.Client(), env, keys, time.Now()); err != nil || changed {
		t.Fatalf("nothing new: %v %v", changed, err)
	}
	delta := doc("delta", 6, 5, []any{entry(a, "@acme/files", 100, "deny", "known_malicious")}, []string{b})
	delta["feed"] = "community"
	edge.FeedDocument(t, delta)
	if changed, err := riskfeed.Sync(ctx, edge.Client(), env, keys, time.Now()); err != nil || !changed {
		t.Fatalf("delta: %v %v", changed, err)
	}
	held, _ = riskfeed.Load(env)
	if held.Sequence != 6 || len(held.Entries) != 1 || held.ByPackage("@acme/files").DefaultVerdict != "deny" || held.ByPackage("@acme/shell") != nil {
		t.Fatalf("after delta: %+v", held)
	}
	// An older snapshot is refused and the feed kept.
	old := doc("snapshot", 4, 0, []any{}, nil)
	old["feed"] = "community"
	edge.FeedDocument(t, old)
	// The fake serves the old snapshot for any since without a matching delta.
	if _, err := riskfeed.Sync(ctx, edge.Client(), env, keys, time.Now()); !errors.Is(err, riskfeed.ErrRollback) {
		t.Fatalf("an older snapshot: %v", err)
	}
	if kept, _ := riskfeed.Load(env); kept.Sequence != 6 {
		t.Fatalf("a refused document must not replace the feed: %d", kept.Sequence)
	}
}
