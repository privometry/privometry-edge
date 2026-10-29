package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/trust"
)

func TestDefinitionsCmd(t *testing.T) {
	trust.WithoutReleaseKeys(t) // "install without release keys" expects the refusal
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	daemonEnv = func() (platform.Env, error) { return env, nil }
	defer func() { daemonEnv = platform.CurrentEnv }()

	// A set signed with a conformance test key: this build has no release
	// keys, so nothing it signs is accepted.
	signed := "../../specs/conformance/signatures/envelopes/adapters-valid.json"
	garbage := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(garbage, []byte(`{"payloadType":"application/vnd.privometry.bundle+json","payload":"e30=","signatures":[]}`), 0o600)

	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"status", []string{"status"}, 0, "Adapter definitions: built-in set 6\nDetector packs: built-in set 3\n"},
		{"status json", []string{"status", "--format", "json"}, 0, `"source": "built-in"`},
		{"install without release keys", []string{"install", "--no-restart", signed}, 1, "no release signing keys"},
		{"install another artifact", []string{"install", garbage}, 1, "not an adapter set or a detector pack set"},
		{"install nothing", []string{"install"}, 2, "name one or more"},
		{"update over plain HTTP", []string{"update", "--url", "http://example.com/defs"}, 2, "not an HTTPS URL"},
		{"unknown subcommand", []string{"rollback"}, 2, "unknown subcommand"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"definitions"}, c.args...), &stdout, &stderr)
			out := stdout.String() + stderr.String()
			if code != c.code || !strings.Contains(out, c.out) {
				t.Errorf("exit %d, want %d; output:\n%s", code, c.code, out)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(data, "definitions", "adapters.json")); !os.IsNotExist(err) {
		t.Errorf("a refused set was written: %v", err)
	}
}
