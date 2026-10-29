package bundles

import (
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
)

func TestCatalogStatus(t *testing.T) {
	now := time.Now()
	past := contract.At(now.Add(-time.Hour))
	cat := BundleCatalog{Entries: []BundleCatalogEntry{
		{Kind: BundleCatalogEntryKindMCPServer, Name: "github", Status: BundleCatalogEntryStatusApproved,
			Match: &BundleCatalogEntryMatch{Package: "@modelcontextprotocol/server-github"}},
		{Kind: BundleCatalogEntryKindMCPServer, Name: "shell-runner", Status: BundleCatalogEntryStatusBlocked,
			Match: &BundleCatalogEntryMatch{Command: "*mcp-shell-runner*"}},
		{Kind: BundleCatalogEntryKindMCPServer, Name: "linear", Status: BundleCatalogEntryStatusApproved,
			Match: &BundleCatalogEntryMatch{Transport: "http", URL: "https://mcp.linear.app/*"}},
		{Kind: BundleCatalogEntryKindMCPServer, Name: "postgres", Status: BundleCatalogEntryStatusApproved, Versions: []string{"0.6.2"}},
		{Kind: BundleCatalogEntryKindMCPServer, Name: "old", Status: BundleCatalogEntryStatusApproved, ExpiresAt: &past},
	}}
	for _, tc := range []struct {
		it   CatalogItem
		want contract.CatalogStatus
	}{
		{CatalogItem{Kind: "mcp_server", Name: "GitHub"}, contract.CatalogStatusApproved},
		{CatalogItem{Kind: "mcp_server", Name: "gh", Package: "@modelcontextprotocol/server-github"}, contract.CatalogStatusApproved},
		{CatalogItem{Kind: "mcp_server", Name: "tools", Command: "/opt/bin/mcp-shell-runner --all"}, contract.CatalogStatusBlocked},
		{CatalogItem{Kind: "mcp_server", Name: "linear", Transport: "stdio"}, contract.CatalogStatusUnknown},
		{CatalogItem{Kind: "mcp_server", Name: "issues", Transport: "http", URL: "https://mcp.linear.app/sse"}, contract.CatalogStatusApproved},
		{CatalogItem{Kind: "mcp_server", Name: "postgres", Version: "0.7.0"}, contract.CatalogStatusUnapproved},
		{CatalogItem{Kind: "mcp_server", Name: "postgres"}, contract.CatalogStatusApproved},
		{CatalogItem{Kind: "mcp_server", Name: "old"}, contract.CatalogStatusUnknown},
		{CatalogItem{Kind: "mcp_server", Name: "notion"}, contract.CatalogStatusUnknown},
		{CatalogItem{Kind: "skill", Name: "release-notes"}, ""},
	} {
		if got, _ := cat.CatalogStatus(tc.it, now); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.it, got, tc.want)
		}
	}
}
