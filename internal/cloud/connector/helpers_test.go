package connector_test

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/ipc"
)

// Helpers shared with internal/daemon's tests.

const fixtures = "../../../test/fixtures/claude_code/2.1.304/hooks/"

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func fixture(t *testing.T, name string, edit func(map[string]any)) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(fixtures + name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	out, _ := json.Marshal(m)
	return out
}

func hook(t *testing.T, d *daemon.Daemon, agent, event string, payload json.RawMessage) ipc.Response {
	t.Helper()
	resp := d.Handle(ipc.Request{V: ipc.Version, Op: "hook", Hook: &ipc.HookRequest{Agent: agent, Event: event, Payload: payload}})
	if !resp.OK {
		t.Fatalf("hook failed: %s", resp.Error)
	}
	return resp
}

func decision(t *testing.T, resp ipc.Response) (string, string) {
	t.Helper()
	var out struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(resp.Stdout), &out); err != nil {
		t.Fatalf("stdout %q: %v", resp.Stdout, err)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

func command(cmd string) func(map[string]any) {
	return func(m map[string]any) { m["tool_input"].(map[string]any)["command"] = cmd }
}
