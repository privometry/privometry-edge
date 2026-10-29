package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/riskfeed"
)

// MCP tool calls relayed by privometry-mcp-shim (PRD EDGE-25). The shim wraps a
// local stdio MCP server and reports each tools/call before forwarding it,
// each call's result, and each tools/list result.
//
// When the agent that launched the shim has an active Privometry hook, that
// hook already decides its MCP calls, so the shim only watches: calls are
// allowed without a second decision or event. The shim always reports tool
// definitions, which hooks never see: their descriptions are scanned as
// model-facing text, and a server whose tools change is reported.

// hookActiveFor is how recently an agent's hook must have called the daemon
// for the shim to leave its MCP calls to the hook. An installed hook that
// never runs (Codex before its hooks are trusted) does not count.
const hookActiveFor = 7 * 24 * time.Hour

// shimEvent is the hook event the shim's calls are decided as. MCP servers
// cannot ask, so ask is sent as deny, as for Codex.
var shimEvent = registry.HookEvent{
	Name:     "MCPShim",
	Role:     registry.HookEventRolePreMCP,
	Verdicts: []contract.Verdict{contract.VerdictAllow, contract.VerdictDeny},
	Fallback: map[string]contract.Verdict{"ask": contract.VerdictDeny},
	Request: map[string]string{"session_id": "/session_id", "cwd": "/cwd", "tool_use_id": "/tool_use_id",
		"tool_name": "/tool_name", "mcp_server": "/mcp_server", "tool_input": "/tool_input", "tool_response": "/tool_response"},
	Responses: map[string]registry.Response{
		"allow": {Stdout: &map[string]any{"verdict": "allow"}},
		"deny":  {Stdout: &map[string]any{"verdict": "deny", "message": "{message}"}},
		"none":  {},
	},
}

// shimProducts are the agents whose configs the shim may be launched from.
var shimProducts = map[contract.AgentProduct]bool{contract.AgentProductClaudeCode: true, contract.AgentProductCursor: true,
	contract.AgentProductCodexCLI: true, contract.AgentProductGeminiCLI: true, contract.AgentProductCopilotCLI: true,
	contract.AgentProductAntigravity: true}

func (d *Daemon) mcp(r ipc.MCPRequest) (ipc.Response, error) {
	product := contract.AgentProduct(r.Agent)
	if !shimProducts[product] {
		product = contract.AgentProductOther
	}
	var body any
	if len(r.Body) > 0 {
		if err := json.Unmarshal(r.Body, &body); err != nil {
			return ipc.Response{}, fmt.Errorf("mcp body: %w", err)
		}
	}
	payload := map[string]any{"session_id": "mcp-shim:" + r.Session, "cwd": r.Cwd, "tool_use_id": "mcp-shim:" + r.Session + ":" + r.CallID,
		"tool_name": r.Tool, "mcp_server": r.Server}
	switch r.Phase {
	case "call":
		payload["tool_input"] = body
	case "result":
		payload["tool_response"] = body
	}
	shim := registry.Adapter{Agent: product, ToolKinds: map[string]contract.ActionKind{"*": contract.ActionKindMCPCall}}
	c := call{adapter: shim, tools: shim, event: shimEvent, product: product, payload: payload}
	c.field = func(name string) any {
		if ptr, ok := shimEvent.Request[name]; ok {
			return lookup(payload, ptr)
		}
		return nil
	}
	enforced := !d.hookActive(product) || !d.hookSeesMCP(product)

	switch r.Phase {
	case "call":
		if !enforced {
			return mcpReply(ipc.MCPDecision{Verdict: "allow"})
		}
		resp, err := d.decide(c)
		if err != nil {
			return ipc.Response{}, err
		}
		var out struct {
			Verdict string `json:"verdict"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal([]byte(resp.Stdout), &out)
		if out.Verdict == "" {
			out.Verdict = "allow"
		}
		if resp.Verdict == "ask" {
			// The policy wanted a person to approve; say why it was blocked instead.
			out.Message = strings.Replace(out.Message, "Privometry asks because", "This call needs a person's approval because", 1) +
				" An MCP server cannot ask for approval, so Privometry blocked it. Allow the tool in ~/.privometry/policy.yaml if it is safe."
		}
		reply, err := mcpReply(ipc.MCPDecision{Verdict: out.Verdict, Message: out.Message, Enforced: true})
		reply.EventID = resp.EventID
		return reply, err
	case "result":
		if enforced {
			if _, err := d.postTool(c); err != nil {
				return ipc.Response{}, err
			}
		}
		return mcpReply(ipc.MCPDecision{Verdict: "allow", Enforced: enforced})
	case "tools":
		return mcpReply(ipc.MCPDecision{Verdict: "allow", Enforced: enforced}, d.mcpTools(c, r, body))
	}
	return ipc.Response{}, fmt.Errorf("mcp phase %q", r.Phase)
}

func mcpReply(dec ipc.MCPDecision, errs ...error) (ipc.Response, error) {
	for _, err := range errs {
		if err != nil {
			return ipc.Response{}, err
		}
	}
	data, err := json.Marshal(dec)
	return ipc.Response{Data: data}, err
}

// mcpTools scans the tool definitions of a tools/list result as model-facing
// text and reports a server whose definitions changed since it was last seen.
func (d *Daemon) mcpTools(c call, r ipc.MCPRequest, body any) error {
	sess, err := d.session(c)
	if err != nil {
		return err
	}
	list, _ := body.(map[string]any)
	tools, _ := list["tools"].([]any)
	remote := remoteOf(sess)
	for _, t := range tools {
		tool, _ := t.(map[string]any)
		name, _ := tool["name"].(string)
		text := content.Flatten(tool)
		if len(text) > maxOutputScan {
			text = text[:maxOutputScan]
		}
		fs, _ := d.allowlistFor(sess.Git).Filter(d.content.Scan(content.SourceToolDescription, text), text, "", d.cfg.Now())
		if len(fs) == 0 {
			continue
		}
		hs := make([]hit, len(fs))
		for i, f := range fs {
			hs[i] = hit{f, 0}
		}
		mcp := &events.MCP{ServerName: r.Server, Transport: events.MCPTransportStdio, Tool: name, CatalogStatus: contract.CatalogStatusUnknown}
		d.recordFindings(c, sess, nil, mcp, remote, hs, []piece{{source: content.SourceToolDescription, text: text}}, events.ContentFindingActionTakenNone)
	}
	return d.noteManifest(c.product, r.Server, tools)
}

// noteManifest remembers a digest of each server's tool definitions and raises
// an integrity event when a known server's definitions change: a server that
// was reviewed can start asking for more, or describe its tools differently
// to the model, without its name or version changing.
func (d *Daemon) noteManifest(product contract.AgentProduct, server string, tools []any) error {
	// The risk feed's tool_manifest_hash, compared with the feed on later calls.
	if err := d.store.SetState("mcp_manifest:"+string(product)+":"+server, riskfeed.ManifestHash(tools)); err != nil {
		return err
	}
	sort.Slice(tools, func(i, j int) bool { return toolName(tools[i]) < toolName(tools[j]) })
	raw, _ := json.Marshal(tools) // map keys marshal sorted, so the digest is canonical
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := "mcp_tools:" + string(product) + ":" + server
	prev, err := d.store.State(key)
	if err != nil || prev == digest {
		return err
	}
	if err := d.store.SetState(key, digest); err != nil {
		return err
	}
	if prev == "" {
		return nil
	}
	in := &events.Integrity{Check: events.IntegrityCheckOther, AgentProduct: product, ExpectedSHA256: prev, ObservedSHA256: digest,
		Detail: "MCP server " + strconv.Quote(server) + " changed its tool definitions (" + strconv.Itoa(len(tools)) + " tools). Review what changed before trusting it again."}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"user.local_user": contract.PrivacyLevelClear}}
	d.cfg.Logger.Warn("integrity alert", "agent", product, "check", "mcp_tools_changed", "server", server)
	return d.appendEvent(ev, "MCP server "+server+" changed its tools")
}

func toolName(t any) string {
	m, _ := t.(map[string]any)
	s, _ := m["name"].(string)
	return s
}

// hookSeesMCP reports whether an agent's hook can tell MCP calls apart: its
// adapter names MCP tools after their server. Copilot CLI and Antigravity pass
// bare tool names, so their hooks see MCP calls as unknown tools and the shim
// decides them even while the hook is active.
func (d *Daemon) hookSeesMCP(product contract.AgentProduct) bool {
	a, ok := d.cfg.Registry.Get(product)
	return ok && a.MCPTools != nil
}

// hookActive reports whether an agent's own Privometry hook is installed and
// has called the daemon recently, so it decides the agent's MCP calls.
func (d *Daemon) hookActive(product contract.AgentProduct) bool {
	if product == contract.AgentProductOther || !d.hookedNatively(product) {
		return false
	}
	last := d.lastHookCall(product)
	return !last.IsZero() && d.cfg.Now().Sub(last) < hookActiveFor
}

// noteHookCall records that an agent's hook called the daemon. It is kept in
// the timeline's state, written at most every ten minutes, so the shim's mode
// survives a daemon restart.
func (d *Daemon) noteHookCall(product contract.AgentProduct) {
	now := d.cfg.Now()
	d.mu.Lock()
	if d.lastHook == nil {
		d.lastHook = map[contract.AgentProduct]time.Time{}
	}
	prev := d.lastHook[product]
	d.lastHook[product] = now
	d.mu.Unlock()
	if prev.IsZero() || now.Sub(prev) > 10*time.Minute {
		if err := d.store.SetState("last_hook:"+string(product), contract.At(now).String()); err != nil {
			d.cfg.Logger.Warn("could not record hook call", "err", err)
		}
	}
}

func (d *Daemon) lastHookCall(product contract.AgentProduct) time.Time {
	d.mu.Lock()
	t, ok := d.lastHook[product]
	d.mu.Unlock()
	if ok {
		return t
	}
	v, err := d.store.State("last_hook:" + string(product))
	if err != nil || v == "" {
		return time.Time{}
	}
	t, _ = time.Parse(time.RFC3339Nano, v)
	return t
}
