package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/community"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
)

// TestCommunityPackFlow follows a pack from its publisher to a user: keygen,
// sign, trust add, install, list, distrust, remove.
func TestCommunityPackFlow(t *testing.T) {
	data, home := t.TempDir(), t.TempDir()
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	daemonEnv = func() (platform.Env, error) { return env, nil }
	defer func() { daemonEnv = platform.CurrentEnv }()
	cli := func(args ...string) (string, int) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		return out.String() + errOut.String(), code
	}

	// The publisher.
	pub := t.TempDir()
	if out, code := cli("packs", "keygen", "--publisher", "example", "--out", filepath.Join(pub, "example")); code != 0 || !strings.Contains(out, "Fingerprint sha256:") {
		t.Fatalf("keygen: %d %s", code, out)
	}
	platformtest.Private(t, filepath.Join(pub, "example.key"))
	signed := filepath.Join(pub, "helm-guard.pack.json")
	if out, code := cli("packs", "sign", "../../rulepacks/community/example-helm-guard", "--key", filepath.Join(pub, "example.key"), "--out", signed); code != 0 {
		t.Fatalf("sign: %d %s", code, out)
	}

	// The user: untrusted first, then trusted after answering yes.
	if out, code := cli("packs", "install", "--no-restart", signed); code != 2 || !strings.Contains(out, "no trusted key") {
		t.Errorf("install before trust: %d %s", code, out)
	}
	prompter = &scripted{t: t, lines: []string{"n"}}
	defer func() { prompter = ttyPrompter{} }()
	if out, code := cli("trust", "add", filepath.Join(pub, "example.keyset.json")); code != 1 || !strings.Contains(out, "Nothing changed") {
		t.Errorf("trust add, answered no: %d %s", code, out)
	}
	prompter = &scripted{t: t, lines: []string{"y"}}
	if out, code := cli("trust", "add", filepath.Join(pub, "example.keyset.json")); code != 0 || !strings.Contains(out, "Publisher example") {
		t.Fatalf("trust add: %d %s", code, out)
	}
	if out, code := cli("packs", "install", "--no-restart", signed); code != 0 || !strings.Contains(out, "extends: [example/helm-guard@^1]") {
		t.Fatalf("install: %d %s", code, out)
	}
	out, _ := cli("packs", "list", "--format", "json")
	var list []community.Installed
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 || list[0].ID != "example/helm-guard" || list[0].Problem != "" {
		t.Errorf("list: %s", out)
	}

	// Policies opting in with extends are covered in internal/community; here,
	// distrusting the publisher stops the pack from loading.
	if out, _ := cli("trust", "list"); !strings.Contains(out, "publisher:example:") {
		t.Errorf("trust list: %s", out)
	}
	if out, code := cli("trust", "remove", "example"); code != 0 {
		t.Errorf("trust remove: %d %s", code, out)
	}
	if out, _ := cli("packs", "list"); !strings.Contains(out, "not loaded: ") {
		t.Errorf("list after distrust: %s", out)
	}
	if out, code := cli("packs", "remove", "--no-restart", "example/helm-guard"); code != 0 {
		t.Errorf("remove: %d %s", code, out)
	}
	if out, code := cli("packs", "remove", "--no-restart", "example/helm-guard"); code != 1 {
		t.Errorf("second remove: %d %s", code, out)
	}
}
