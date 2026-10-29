package bundles_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/cloudtest"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/keyset"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
)

const policyYAML = `schema: privometry.policy/v1
name: acme-org
rules:
  - id: no-force-push
    category: catastrophic
    when: { action: shell_exec, program: git, subcommand: push, flags: [--force] }
    verdict: deny
    message: Force pushes go through review.
`

func enrolled(t *testing.T) (*cloudtest.Edge, platform.Env, keystore.Store) {
	t.Helper()
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	keys, err := keystore.Open(env, "file")
	if err != nil {
		t.Fatal(err)
	}
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	id, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !id.KeySetPinned {
		t.Error("a build without root keys pins the key set from enrollment")
	}
	return edge, env, keys
}

func TestSyncKeepsVerifiedBundles(t *testing.T) {
	edge, env, keys := enrolled(t)
	now := time.Now()
	ctx := context.Background()
	if held, err := bundles.Load(env, now); held != nil || err != nil {
		t.Fatalf("before any sync: %v %v", held, err)
	}
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 3, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Sources: []cloudtest.Source{{Name: "acme-org", Version: "1", Content: policyYAML}}}))
	res, err := bundles.Sync(ctx, edge.Client(), env, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Held.Bundle.Version != 3 || res.Held.Entitlements.OrgID != edge.OrgID {
		t.Fatalf("first sync: %+v", res)
	}
	again, err := bundles.Sync(ctx, edge.Client(), env, keys, now)
	if err != nil || again.Changed || again.Held.Bundle.BundleID != res.Held.Bundle.BundleID {
		t.Fatalf("unchanged bundle: %+v %v", again, err)
	}
	held, err := bundles.Load(env, now)
	if err != nil || held == nil || held.Bundle.Sources[0].Name != "acme-org" || held.Expired {
		t.Fatalf("load: %+v %v", held, err)
	}
	// The same version from the workspace (another bundle ID) is accepted.
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 3, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)}))
	if res, err := bundles.Sync(ctx, edge.Client(), env, keys, now); err != nil || !res.Changed {
		t.Fatalf("same version, other bundle: %+v %v", res, err)
	}
	// After it expires the device keeps enforcing it and says so.
	later, err := bundles.Load(env, now.Add(31*24*time.Hour))
	if err != nil || !later.Expired {
		t.Fatalf("expired: %+v %v", later, err)
	}
}

func TestSyncRefusesBadBundles(t *testing.T) {
	edge, env, keys := enrolled(t)
	now := time.Now()
	ctx := context.Background()
	good := edge.Signed(t, cloudtest.Bundle{Version: 5, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)})
	edge.Serve(good)
	if _, err := bundles.Sync(ctx, edge.Client(), env, keys, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Getenv("PRIVOMETRY_HOME"), bundles.File)
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"older version", edge.Signed(t, cloudtest.Bundle{Version: 4, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}), "older than"},
		{"another organization", edge.Signed(t, cloudtest.Bundle{Version: 6, OrgID: "org_01JA0000000000000000000009", CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour)}), "another organization"},
		{"already expired", edge.Signed(t, cloudtest.Bundle{Version: 6, CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)}), "expired"},
		{"signed with the license key", edge.SignedWith(t, cloudtest.Bundle{Version: 6, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}, "license"),
			"no valid signature"},
		{"tampered", []byte(strings.Replace(string(edge.Signed(t, cloudtest.Bundle{Version: 6, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)})),
			`"payload":"`, `"payload":"e30K`, 1)), "bundle"},
		{"from another region", cloudtest.NewRegion(t).Signed(t, cloudtest.Bundle{Version: 6, OrgID: edge.OrgID, CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour)}), "no valid signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edge.Serve(tc.raw)
			if _, err := bundles.Sync(ctx, edge.Client(), env, keys, now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			held, err := os.ReadFile(path)
			if err != nil || string(held) != string(good) {
				t.Fatal("a refused bundle must not replace the one the device holds")
			}
		})
	}
}

func TestSyncNeedsEnrollmentAndAKeySet(t *testing.T) {
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	keys, _ := keystore.Open(env, "file")
	if _, err := bundles.Sync(context.Background(), nil, env, keys, time.Now()); !errors.Is(err, bundles.ErrNotEnrolled) {
		t.Fatalf("not enrolled: %v", err)
	}
	edge, env, keys := enrolled(t)
	os.Remove(filepath.Join(env.Getenv("PRIVOMETRY_HOME"), keyset.File))
	if _, err := bundles.Sync(context.Background(), edge.Client(), env, keys, time.Now()); !errors.Is(err, bundles.ErrNoKeySet) {
		t.Fatalf("no key set: %v", err)
	}
}
