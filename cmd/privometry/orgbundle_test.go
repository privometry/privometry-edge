package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/cloudtest"
	"github.com/privometry/privometry-edge/internal/platform"
)

func TestBundleSyncAndStatus(t *testing.T) {
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	accountEnv = func() (platform.Env, error) { return env, nil }
	accountHTTP = func() *http.Client { return edge.Client() }
	t.Cleanup(func() {
		accountEnv = platform.CurrentEnv
		accountHTTP = func() *http.Client { return &http.Client{Timeout: 30 * time.Second} }
	})
	if code, out, _ := runCmd("bundle", "status"); code != 1 || !strings.Contains(out, "not enrolled") {
		t.Fatalf("before enrolling: %d %s", code, out)
	}
	if code, out, errOut := runCmd("enroll", "--keystore", "file", "--edge", edge.URL(), "--token", cloudtest.Token); code != 0 {
		t.Fatalf("enroll: %d %s %s", code, out, errOut)
	}
	if code, out, _ := runCmd("device", "status"); code != 0 || !strings.Contains(out, "Key set:     pinned at enrollment") {
		t.Errorf("device status: %d %s", code, out)
	}
	if code, out, _ := runCmd("bundle", "status"); code != 1 || !strings.Contains(out, "No organization bundle yet") {
		t.Fatalf("before syncing: %d %s", code, out)
	}
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 4, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Sources: []cloudtest.Source{{Name: "acme-org", Version: "2", Content: "schema: privometry.policy/v1\nname: acme-org\n"}}}))
	if code, out, errOut := runCmd("bundle", "sync"); code != 0 || !strings.Contains(out, "Fetched bundle version 4") {
		t.Fatalf("sync: %d %s %s", code, out, errOut)
	}
	if code, out, _ := runCmd("bundle", "sync"); code != 0 || !strings.Contains(out, "version 4 is the newest") {
		t.Fatalf("sync again: %d %s", code, out)
	}
	code, out, _ := runCmd("bundle", "status")
	for _, want := range []string{"version 4 (bnd_", "Policies:     acme-org@2", "Entitlements: trial (trial)", "Key set:      version 1, pinned at enrollment"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("status lacks %q: %d\n%s", want, code, out)
		}
	}
	if code, _, _ := runCmd("bundle", "explode"); code != 2 {
		t.Errorf("bad subcommand: exit %d", code)
	}
}
