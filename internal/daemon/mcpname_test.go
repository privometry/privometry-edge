package daemon

import (
	"testing"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
)

// Copilot CLI names MCP tools <server>-<tool>, and server names may hold
// hyphens: the split uses the longest server the last scan found.
func TestCopilotMCPServerSplit(t *testing.T) {
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		t.Fatal(err)
	}
	copilot, _ := reg.Get(contract.AgentProductCopilotCLI)
	for _, tc := range []struct {
		tool, server, mcpTool string
		known                 []string
	}{
		{"tickets-lookup_ticket", "tickets", "lookup_ticket", nil},
		{"github-mcp-server-list_issues", "github-mcp-server", "list_issues", []string{"github", "github-mcp-server"}},
		{"github-mcp-server-list_issues", "github", "mcp-server-list_issues", nil}, // a server the scan has not seen
	} {
		c := call{adapter: copilot, field: func(name string) any {
			if name == "tool_name" {
				return tc.tool
			}
			return nil
		}, servers: func() []string { return tc.known }}
		_, actions := c.actions()
		if len(actions) != 1 || actions[0].Kind != "mcp_call" || actions[0].MCPServer != tc.server || actions[0].MCPTool != tc.mcpTool {
			t.Errorf("%s with %v: %+v", tc.tool, tc.known, actions)
		}
	}
}
