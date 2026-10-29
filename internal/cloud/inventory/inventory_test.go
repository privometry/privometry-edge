package inventory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/scanner/posture"
	"github.com/privometry/privometry-edge/specs"
)

func TestSnapshotOfAScan(t *testing.T) {
	res := &scanner.Result{ScannedAt: contract.At(time.Now()), Agents: []discover.Agent{
		{Product: "claude_code", Installed: true, Version: "2.1.304",
			MCPServers: []discover.MCPServer{
				{Name: "github", Tier: "user", Transport: "stdio", Command: "npx -y @modelcontextprotocol/server-github@0.6.2", Package: "@modelcontextprotocol/server-github@0.6.2"},
				{Name: "linear", Tier: "project", Transport: "http", URL: "https://user:secret@mcp.linear.app/sse?token=abc"},
			},
			Skills:  []discover.Skill{{Name: "release-notes", Tier: "project", Path: "/home/dev/work/api/.claude/skills/release-notes/SKILL.md"}},
			Plugins: []discover.Plugin{{ID: "acme@market", Name: "acme", Version: "1.0.0", Tier: "user"}},
			Hooks: []discover.Hook{{Tier: "user", Event: "PreToolUse", Command: "privometry-hook claude_code", Privometry: true},
				{Tier: "user", Event: "PreToolUse", Command: "/home/dev/bin/lint.sh"}}},
		{Product: "cursor", Installed: false},
	}, Findings: []posture.Finding{{Check: "auto_approve_mode", Severity: "high", Agent: "claude_code", Tier: "user", Message: "Runs commands without asking"}}}
	snap := Snapshot(res, 42)
	raw, _ := json.Marshal(snap)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/InventorySnapshot", "snap.json", raw); err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, leak := range []string{"secret", "token=abc", "lint.sh", "/home/dev", "npx", "privometry-hook"} {
		if strings.Contains(text, leak) {
			t.Errorf("the snapshot carries %q: %s", leak, text)
		}
	}
	kinds := map[string]int{}
	for _, it := range snap.Items {
		kinds[string(it.Kind)]++
	}
	want := map[string]int{"agent": 1, "mcp_server": 2, "skill": 1, "plugin": 1, "hook": 1, "posture_issue": 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s: %d items, want %d (%v)", k, kinds[k], n, kinds)
		}
	}
	for _, it := range snap.Items {
		switch it.Name {
		case "github":
			if it.Package != "@modelcontextprotocol/server-github" || it.MCPTransport != "stdio" {
				t.Errorf("github: %+v", it)
			}
		case "linear":
			if it.Host != "mcp.linear.app" || it.MCPTransport != "http" {
				t.Errorf("linear: %+v", it)
			}
		}
	}
	if Snapshot(res, 0).DeviceSeq != 1 {
		t.Error("device_seq is at least 1")
	}
}
