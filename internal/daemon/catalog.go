package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
)

// catalogState is the organization catalog from the bundle this device holds,
// reloaded when the bundle file changes, and the MCP servers the last scan
// found, so a call can be matched by package, URL or command as well as name.
type catalogState struct {
	stamp   string
	catalog *bundles.BundleCatalog
	servers map[string]discover.MCPServer // by agent and server name
}

// mcpCatalogStatus is the catalog status of the MCP server an action calls:
// empty when the action is not an MCP call or the device holds no catalog.
func (d *Daemon) mcpCatalogStatus(product contract.AgentProduct, a intent.Action) string {
	if a.Kind != "mcp_call" || a.MCPServer == "" {
		return ""
	}
	cat := d.catalog()
	if cat == nil {
		return ""
	}
	it := bundles.CatalogItem{Kind: "mcp_server", Name: a.MCPServer}
	d.mu.Lock()
	if m, ok := d.catalogState.servers[string(product)+"\x00"+a.MCPServer]; ok {
		it.Transport, it.Package, it.URL, it.Command = m.Transport, scanner.PackageName(m.Package), m.URL, m.Command
		if it.Transport == "sse" || it.Transport == "streamable-http" {
			it.Transport = "http"
		}
	}
	d.mu.Unlock()
	st, _ := cat.CatalogStatus(it, d.cfg.Now())
	return string(st)
}

// catalog returns the held bundle's catalog, or nil.
func (d *Daemon) catalog() *bundles.BundleCatalog {
	stamp := ""
	if info, err := os.Stat(filepath.Join(d.dataDir, bundles.File)); err == nil {
		stamp = fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
	}
	d.mu.Lock()
	if d.catalogState.stamp == stamp {
		cat := d.catalogState.catalog
		d.mu.Unlock()
		return cat
	}
	d.mu.Unlock()
	var cat *bundles.BundleCatalog
	if stamp != "" {
		if held, err := bundles.Load(d.cfg.Env, d.cfg.Now()); err == nil && held != nil {
			cat = &held.Bundle.Catalog
		}
	}
	d.mu.Lock()
	d.catalogState.stamp, d.catalogState.catalog = stamp, cat
	d.mu.Unlock()
	return cat
}

// serverNames lists the MCP servers the last scan found for product.
func (d *Daemon) serverNames(product contract.AgentProduct) []string {
	prefix := string(product) + "\x00"
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for k := range d.catalogState.servers {
		if name, ok := strings.CutPrefix(k, prefix); ok {
			out = append(out, name)
		}
	}
	return out
}

// rememberServers keeps the MCP servers a scan found, for catalog matching.
func (d *Daemon) rememberServers(res *scanner.Result) {
	servers := map[string]discover.MCPServer{}
	for _, a := range res.Agents {
		for _, m := range a.MCPServers {
			servers[string(a.Product)+"\x00"+m.Name] = m
		}
	}
	d.mu.Lock()
	d.catalogState.servers = servers
	d.mu.Unlock()
}
