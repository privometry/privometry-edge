package daemon_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/cloudtest"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/ipc/ipctest"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
)

const orgPolicy = `schema: privometry.policy/v1
name: acme-org
rules:
  - id: no-kubectl-delete
    category: catastrophic
    when: { action: shell_exec, program: kubectl, subcommand: delete }
    verdict: deny
    message: Delete Kubernetes resources from the release pipeline.
`

// An enrolled device enforces the organization policies of the bundle it
// holds, and picks up a new bundle without a restart.
func TestDaemonEnforcesTheOrganizationBundle(t *testing.T) {
	data, err := os.MkdirTemp(ipctest.TempRoot, "privometry-d-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(data) })
	env := platform.Env{GOOS: "linux", Home: "/home/dev", Getenv: func(k string) string {
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
	if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	packs, err := policy.BuiltinPacks()
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, CloudHTTP: edge.Client(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	kubectlDelete := func(useID string) func(map[string]any) {
		return func(m map[string]any) {
			command("kubectl delete deployment api")(m)
			m["tool_use_id"] = useID // each call is a new tool use, not a retry
		}
	}
	if v, _ := decision(t, hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", kubectlDelete("toolu_before")))); v == "deny" {
		t.Fatalf("without the organization bundle kubectl delete is not denied by a rule, got %s", v)
	}
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Sources: []cloudtest.Source{{Name: "acme-org", Version: "1", Content: orgPolicy}}}))
	if _, err := bundles.Sync(context.Background(), edge.Client(), env, keys, now); err != nil {
		t.Fatal(err)
	}
	verdict, reason := decision(t, hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", kubectlDelete("toolu_after"))))
	if verdict != "deny" || !strings.Contains(reason, "release pipeline") {
		t.Fatalf("with the bundle: %s %q", verdict, reason)
	}
}
