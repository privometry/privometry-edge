package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/riskfeed"
	"github.com/privometry/privometry-edge/internal/scanner"
)

// The risk feed on MCP calls (PRD CP-22; riskfeed/v1 draft.2): the
// organization's catalog decision always wins; for a server the catalog does
// not list, the feed's default_verdict applies, never weaker than the policy's,
// and a server whose tools hash to none of the feed's manifest hashes is asked
// about until someone reviews it.

type feedState struct {
	stamp string
	held  *riskfeed.Held
}

// feedEntry is the feed's entry for the MCP server an action calls, or nil.
func (d *Daemon) feedEntry(product contract.AgentProduct, a intent.Action) *riskfeed.Entry {
	if a.Kind != "mcp_call" {
		return nil
	}
	held := d.feed()
	if held == nil {
		return nil
	}
	d.mu.Lock()
	m, ok := d.catalogState.servers[string(product)+"\x00"+a.MCPServer]
	d.mu.Unlock()
	if !ok {
		return nil // the feed knows packages; a server we never scanned has none
	}
	if e := held.ByPackage(scanner.PackageName(m.Package)); e != nil {
		return e
	}
	return held.ByPackage(m.URL)
}

// feedAdjust raises an MCP call's verdict to what the feed says.
func (d *Daemon) feedAdjust(product contract.AgentProduct, a intent.Action, dec policy.Decision) policy.Decision {
	if a.Kind != "mcp_call" {
		return dec
	}
	switch d.mcpCatalogStatus(product, a) {
	case "approved", "blocked", "unapproved":
		return dec // the organization's catalog decides
	}
	e := d.feedEntry(product, a)
	if e == nil {
		return dec
	}
	verdict, rule := string(e.DefaultVerdict), "privometry/riskfeed:"+string(e.Level)+"-risk"
	message := fmt.Sprintf("The risk feed rates this MCP server %s (score %d", e.Level, e.Score)
	if len(e.Signals) > 0 {
		var names []string
		for _, s := range e.Signals {
			names = append(names, string(s))
		}
		message += ": " + strings.Join(names, ", ")
	}
	message += ")."
	if observed, _ := d.store.State("mcp_manifest:" + string(product) + ":" + a.MCPServer); observed != "" {
		var known []string
		for _, v := range e.Versions {
			if v.ToolManifestHash != "" {
				known = append(known, v.ToolManifestHash)
			}
		}
		if len(known) > 0 && !slices.Contains(known, observed) && strength[verdict] < strength["ask"] {
			verdict, rule = "ask", "privometry/riskfeed:tool-manifest-changed"
			message = "This MCP server's tools differ from every version the risk feed knows; review them before trusting it."
		}
	}
	if strength[verdict] > strength[dec.Verdict] {
		dec.Verdict, dec.RuleIDs, dec.Message, dec.Source, dec.WouldVerdict, dec.WouldRuleIDs = verdict, []string{rule}, message, "policy", "", nil
	}
	return dec
}

// feed returns the risk feed this device holds, reloaded when its file changes.
func (d *Daemon) feed() *riskfeed.Held {
	stamp := ""
	if info, err := os.Stat(filepath.Join(d.dataDir, riskfeed.File)); err == nil {
		stamp = fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
	}
	d.mu.Lock()
	if d.feedState.stamp == stamp {
		h := d.feedState.held
		d.mu.Unlock()
		return h
	}
	d.mu.Unlock()
	var h *riskfeed.Held
	if stamp != "" {
		h, _ = riskfeed.Load(d.cfg.Env)
	}
	d.mu.Lock()
	d.feedState = feedState{stamp: stamp, held: h}
	d.mu.Unlock()
	return h
}
