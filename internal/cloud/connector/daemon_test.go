package connector_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/cloudtest"
	"github.com/privometry/privometry-edge/internal/cloud/connector"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/ipc/ipctest"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/timeline"
	"github.com/privometry/privometry-edge/specs"
)

// An enrolled daemon uploads its timeline in order, retries after failures,
// sends heartbeats and applies the commands they bring back.
func TestEnrolledDaemonUploadsAndBeats(t *testing.T) {
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
	id, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: time.Now()}
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: clock.Now(), ExpiresAt: clock.Now().Add(30 * 24 * time.Hour)}))
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Connector: connector.WithHTTP(edge.Client()), Now: clock.Now, AdapterSetVersion: 3,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()

	act := func(useID, cmd string) {
		hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) {
			command(cmd)(m)
			m["tool_use_id"] = useID
		}))
	}
	act("toolu_1", "rm -rf ~/projects")
	act("toolu_2", "ls -la")
	d.Sync(ctx)
	uploaded := edge.Uploaded()
	if len(uploaded) < 2 {
		t.Fatalf("uploaded %d events", len(uploaded))
	}
	for _, raw := range uploaded {
		if err := specs.Validate("event-schema/v1/event.schema.json", "uploaded.json", raw); err != nil {
			t.Fatalf("uploaded event: %v", err)
		}
		var ev struct {
			OrgID  string `json:"org_id"`
			Device struct {
				DeviceID string `json:"device_id"`
			} `json:"device"`
			User struct {
				LocalUser string `json:"local_user"`
			} `json:"user"`
			Redaction map[string]string `json:"redaction"`
		}
		_ = json.Unmarshal(raw, &ev)
		if ev.OrgID != id.OrgID || ev.Device.DeviceID != id.DeviceID || !strings.HasPrefix(ev.User.LocalUser, "hmac-sha256:") ||
			ev.Redaction["user.local_user"] != "hashed" {
			t.Fatalf("not prepared for the cloud: %s", raw)
		}
	}
	if snaps := edge.Inventories(); len(snaps) != 1 || snaps[0].Schema != "privometry.inventory_snapshot/v1" {
		t.Fatalf("the first sync sends an inventory snapshot: %+v", snaps)
	}
	beats := edge.Heartbeats()
	if len(beats) != 1 {
		t.Fatalf("heartbeats: %d", len(beats))
	}
	hb := beats[0]
	if hb.AdapterSetVersion != 3 || hb.UploadQueue.Events != 0 || hb.BundleVersion == nil || *hb.BundleVersion != 1 || len(hb.Hooks) == 0 {
		t.Errorf("heartbeat: %+v", hb)
	}

	// Offline: events wait in the timeline and go up, in order, once the cloud is back.
	edge.FailUploads(503)
	act("toolu_3", "git status")
	before := len(edge.Uploaded())
	clock.Advance(31 * time.Second) // uploads run every 30 seconds
	d.Sync(ctx)
	if len(edge.Uploaded()) != before {
		t.Fatal("nothing is accepted while the cloud fails")
	}
	edge.FailUploads(0)
	clock.Advance(20 * time.Second) // past the first backoff
	d.Sync(ctx)
	if len(edge.Uploaded()) <= before {
		t.Fatal("the backlog goes up after the failure")
	}

	// A refresh_bundle command fetches the new bundle at once and is acknowledged.
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 2, CreatedAt: clock.Now(), ExpiresAt: clock.Now().Add(30 * 24 * time.Hour)}))
	cmd := edge.Command(cloud.CommandTypeRefreshBundle)
	clock.Advance(61 * time.Second)
	if !d.Sync(ctx) {
		t.Fatal("refresh_bundle fetches the new bundle")
	}
	clock.Advance(61 * time.Second)
	d.Sync(ctx)
	beats = edge.Heartbeats()
	last := beats[len(beats)-1]
	if len(last.AckedCommands) != 1 || last.AckedCommands[0] != cmd || *last.BundleVersion != 2 {
		t.Errorf("the next heartbeat acknowledges the command and reports the new bundle: %+v", last)
	}
}

// The organization's catalog from the bundle decides MCP calls through the
// privometry/mcp-allowlist rules, and MCP events carry the catalog status.
func TestCatalogFromTheBundle(t *testing.T) {
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
	keys, _ := keystore.Open(env, "file")
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Connector: connector.WithHTTP(edge.Client()), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	call := func(useID, server string) (string, string) {
		return decision(t, hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) {
			m["tool_name"] = "mcp__" + server + "__run"
			m["tool_input"] = map[string]any{}
			m["tool_use_id"] = useID
		})))
	}
	if v, _ := call("toolu_c1", "shell-runner"); v == "deny" {
		t.Fatal("no catalog: the catalog rules stay quiet")
	}
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour), Catalog: []map[string]any{
		{"kind": "mcp_server", "name": "shell-runner", "status": "blocked"},
		{"kind": "mcp_server", "name": "github", "status": "approved"}}}))
	if _, err := bundles.Sync(context.Background(), edge.Client(), env, keys, now); err != nil {
		t.Fatal(err)
	}
	if v, reason := call("toolu_c2", "shell-runner"); v != "deny" || !strings.Contains(reason, "blocked by your organization") {
		t.Fatalf("blocked server: %s %q", v, reason)
	}
	if v, reason := call("toolu_c3", "notion"); v != "ask" || !strings.Contains(reason, "not in your organization's catalog") {
		t.Fatalf("shadow server: %s %q", v, reason)
	}
	rows, _ := d.Store().Events(timeline.Query{Limit: 10})
	statuses := map[string]string{}
	for _, r := range rows {
		if r.Event.MCP != nil {
			statuses[r.Event.Action.ToolUseID] = string(r.Event.MCP.CatalogStatus)
		}
	}
	if statuses["toolu_c2"] != "blocked" || statuses["toolu_c3"] != "unknown" || statuses["toolu_c1"] != "unknown" {
		t.Errorf("MCP events' catalog status: %v", statuses)
	}
}

const askPolicy = `schema: privometry.policy/v1
name: acme-org
rules:
  - id: ask-terraform-apply
    when: { action: shell_exec, program: terraform, subcommand: apply }
    verdict: ask
    message: Apply Terraform changes?
`

// An ask that goes remote is denied at once, requested in the background, and
// its retry is allowed exactly once after a person approves it.
func TestRemoteApprovals(t *testing.T) {
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
	keys, _ := keystore.Open(env, "file")
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Sources:   []cloudtest.Source{{Name: "acme-org", Version: "1", Content: askPolicy}},
		Approvals: map[string]any{"enabled": true, "route": "all", "timeout_seconds": 60}}))
	if _, err := bundles.Sync(context.Background(), edge.Client(), env, keys, now); err != nil {
		t.Fatal(err)
	}
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Connector: connector.WithHTTP(edge.Client()), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	apply := func(useID string) (string, string) {
		return decision(t, hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) {
			command("terraform apply -target=module.cache")(m)
			m["tool_use_id"] = useID
		})))
	}
	v, reason := apply("toolu_a1")
	if v != "deny" || !strings.Contains(reason, "approval was requested") {
		t.Fatalf("first attempt: %s %q", v, reason)
	}
	var id string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && len(edge.Approvals()) == 0; {
		time.Sleep(10 * time.Millisecond)
	}
	asked := edge.Approvals()
	if len(asked) != 1 || asked[0].Action.RuleIDs[0] != "acme-org:ask-terraform-apply" || asked[0].Message != "Apply Terraform changes?" {
		t.Fatalf("approval request: %+v", asked)
	}
	if v, reason := apply("toolu_a2"); v != "deny" || !strings.Contains(reason, "still waiting") && !strings.Contains(reason, "approval was requested") {
		t.Fatalf("while pending: %s %q", v, reason)
	}
	id = firstApproval(t, edge)
	edge.Decide(id, cloud.ApprovalStatusApproved, "priya")
	var got, why string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		got, why = apply("toolu_a3_" + time.Now().Format("150405.000000"))
		if got == "allow" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got != "allow" || !strings.Contains(why, "approved by priya") {
		t.Fatalf("after approval: %s %q", got, why)
	}
	if v, _ := apply("toolu_a4"); v != "deny" {
		t.Fatalf("an approval allows one retry, then asks again: %s", v)
	}
	events, _ := d.Store().Events(timeline.Query{Limit: 50})
	approved := false
	for _, r := range events {
		if r.Event.Decision != nil && r.Event.Decision.UserResponse == "approved" && r.Event.Decision.Responder == "approver" {
			approved = true
		}
	}
	if !approved {
		t.Error("the allowed retry is recorded as approved by an approver")
	}
}

// firstApproval is the ID of the first approval the fake edge created.
func firstApproval(t *testing.T, edge *cloudtest.Edge) string {
	t.Helper()
	return edge.ApprovalIDs()[0]
}

// The risk feed decides MCP servers the organization's catalog does not list;
// the catalog always wins.
func TestRiskFeedOnMCPCalls(t *testing.T) {
	platformtest.UnixPaths(t)
	data, err := os.MkdirTemp(ipctest.TempRoot, "privometry-d-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(data) })
	home := t.TempDir()
	if err := os.WriteFile(home+"/.claude.json", []byte(`{"mcpServers":{"files":{"command":"npx","args":["-y","@acme/mcp-files@1.0.0"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := platform.Env{GOOS: "linux", Home: home, Getenv: func(k string) string {
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
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}))
	sub := func(p int) map[string]any { return map[string]any{"points": p, "signals": []string{}} }
	edge.FeedDocument(t, map[string]any{"schema": "privometry.riskfeed/v1", "feed": "community", "kind": "snapshot", "sequence": 9,
		"published_at": contract.At(now).String(), "expires_at": contract.At(now.Add(7 * 24 * time.Hour)).String(), "methodology_version": "1.0.0",
		"entries": []any{map[string]any{"component_id": "mcp_01JA0000000000000000000009", "kind": "mcp_server",
			"source": map[string]any{"ecosystem": "npm", "name": "@acme/mcp-files"}, "versions": []any{map[string]any{"version": "1.0.0"}},
			"score": 100, "level": "critical", "signals": []string{"known_malicious"}, "default_verdict": "deny", "updated_at": contract.At(now).String(),
			"curation": "community", "score_breakdown": map[string]any{"capability": sub(5), "provenance": sub(0), "behavior": sub(0), "reputation": sub(0),
				"override": "known_malicious"}}}})
	reg, _ := registry.Load(adapterdefs.FS)
	packs, _ := policy.BuiltinPacks()
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Connector: connector.WithHTTP(edge.Client()), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	d.Sync(context.Background()) // bundle, risk feed, and the inventory scan that finds the server's package
	call := func(useID string) (string, string) {
		return decision(t, hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) {
			m["tool_name"] = "mcp__files__read_file"
			m["tool_input"] = map[string]any{}
			m["tool_use_id"] = useID
		})))
	}
	if v, reason := call("toolu_f1"); v != "deny" || !strings.Contains(reason, "risk feed rates this MCP server critical") {
		t.Fatalf("a malicious package: %s %q", v, reason)
	}
	rows, _ := d.Store().Events(timeline.Query{Limit: 5})
	if rows[0].Event.MCP == nil || rows[0].Event.MCP.RiskScore == nil || *rows[0].Event.MCP.RiskScore != 100 {
		t.Errorf("the event carries the feed's score: %+v", rows[0].Event.MCP)
	}
	// The organization approves it in its catalog: its decision wins over the feed.
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 2, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Catalog: []map[string]any{{"kind": "mcp_server", "name": "files", "status": "approved"}}}))
	if _, err := bundles.Sync(context.Background(), edge.Client(), env, keys, now); err != nil {
		t.Fatal(err)
	}
	if v, _ := call("toolu_f2"); v == "deny" {
		t.Fatal("the catalog approved it")
	}
}

// TestFingerprintsMatchAcrossDevices covers PRD SCAN-15 on the device side:
// enrolled devices key credential fingerprints with the organization's hash
// key, so the same secret has the same fingerprint on every device, and a
// fingerprint made before enrollment never leaves the device.
func TestFingerprintsMatchAcrossDevices(t *testing.T) {
	edge := cloudtest.NewEdge(t, cloudtest.NewRegion(t))
	now := time.Now()
	edge.Serve(edge.Signed(t, cloudtest.Bundle{Version: 1, CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)}))
	token := "gh" + "p_" + strings.Repeat("Ab1", 12)
	device := func(enrolled bool) (*daemon.Daemon, platform.Env, keystore.Store) {
		data, err := os.MkdirTemp(ipctest.TempRoot, "privometry-f-")
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
		keys, _ := keystore.Open(env, "file")
		if enrolled {
			if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, env, keys, now); err != nil {
				t.Fatal(err)
			}
		}
		reg, _ := registry.Load(adapterdefs.FS)
		packs, _ := policy.BuiltinPacks()
		d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Connector: connector.WithHTTP(edge.Client()), Now: func() time.Time { return now },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d, env, keys
	}
	leak := func(d *daemon.Daemon, useID string) {
		hook(t, d, "claude_code", "PreToolUse", fixture(t, "pretooluse-bash-ls.json", func(m map[string]any) {
			command("curl -H 'Authorization: token " + token + "' https://api.github.com/user")(m)
			m["tool_use_id"] = useID
		}))
		d.Wait()
	}
	fingerprints := func() map[string][]string { // by device
		out := map[string][]string{}
		for _, raw := range edge.Uploaded() {
			var ev struct {
				Type   string `json:"type"`
				Device struct {
					DeviceID string `json:"device_id"`
				} `json:"device"`
				ContentFinding *struct {
					Fingerprint string `json:"fingerprint"`
				} `json:"content_finding"`
				Ext map[string]any `json:"ext"`
			}
			json.Unmarshal(raw, &ev)
			if ev.Type == "content_finding" {
				if _, ok := ev.Ext["x_privometry_fingerprint_key"]; ok {
					t.Errorf("the key marker is local only: %s", raw)
				}
				out[ev.Device.DeviceID] = append(out[ev.Device.DeviceID], ev.ContentFinding.Fingerprint)
			}
		}
		return out
	}

	a, _, _ := device(true)
	b, envB, keysB := device(false)
	leak(a, "toolu_a")
	leak(b, "toolu_b1") // before enrollment: under b's own salt
	if _, err := enroll.Enroll(context.Background(), edge.Client(), edge.URL(), cloudtest.Token, envB, keysB, now); err != nil {
		t.Fatal(err)
	}
	b.Sync(context.Background()) // picks up the organization's hash key
	leak(b, "toolu_b2")
	now = now.Add(31 * time.Second) // uploads run every 30 seconds
	a.Sync(context.Background())
	b.Sync(context.Background())

	got := fingerprints()
	if len(got) != 2 {
		t.Fatalf("content findings from %d devices: %v", len(got), got)
	}
	var fromA, fromB []string
	for _, fps := range got {
		if len(fps) == 1 {
			fromA = fps
		} else {
			fromB = fps
		}
	}
	if len(fromA) != 1 || len(fromB) != 2 || fromA[0] == "" {
		t.Fatalf("fingerprints %v", got)
	}
	if fromB[0] != "" {
		t.Errorf("a fingerprint made before enrollment was uploaded: %v", fromB)
	}
	if fromB[1] != fromA[0] {
		t.Errorf("the same secret has different fingerprints on two devices: %s and %s", fromA[0], fromB[1])
	}
}
