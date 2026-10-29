package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/upload"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/redact"
)

const (
	// contentBudget bounds the scan before a decision (PRD SCAN-11); what
	// is left is scanned after the reply and raises findings only.
	contentBudget = 5 * time.Millisecond
	// maxOutputScan bounds how much of a tool's output is scanned.
	maxOutputScan = 256 << 10
	// maxFindingEvents caps the findings recorded for one tool call.
	maxFindingEvents = 20
)

// piece is one text a tool call sends or writes, with where it goes.
type piece struct {
	source content.Source
	text   string
	path   string // file_write: the file written
}

// pieces returns what a tool call carries that the detectors should see:
// the command, the URL, the arguments of an MCP call, or written content.
func (c call) pieces(actions []intent.Action) []piece {
	var out []piece
	toolName := c.str("tool_name")
	target, _ := c.tools.ToolTarget(toolName)
	input := c.field("tool_input")
	written := ""
	if target.Content != "" {
		written = content.Flatten(lookup(input, target.Content))
	}
	for _, a := range actions {
		switch a.Kind {
		case "shell_exec":
			out = append(out, piece{source: content.SourceActionArgument, text: a.Command})
		case "network_fetch":
			out = append(out, piece{source: content.SourceActionArgument, text: a.URL})
		case "mcp_call":
			out = append(out, piece{source: content.SourceActionArgument, text: content.Flatten(input)})
		case "file_write":
			if written != "" {
				out = append(out, piece{source: content.SourceFileWrite, text: written, path: a.Path})
			}
		}
	}
	patch := lookup(input, target.Patch)
	if s, ok := input.(string); ok {
		patch = s // Copilot CLI sends apply_patch's patch as the whole of toolArgs
	}
	if patch != nil && len(actions) > 0 {
		// apply_patch: scan the lines the patch adds, once for the call.
		if added := addedLines(content.Flatten(patch)); added != "" {
			out = append(out, piece{source: content.SourceFileWrite, text: added, path: actions[0].Path})
		}
	}
	return out
}

func lookup(v any, ptr string) any {
	if ptr == "" {
		return nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

func addedLines(patch string) string {
	var b strings.Builder
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			b.WriteString(line[1:])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hit is a finding with the piece it came from.
type hit struct {
	content.Finding
	piece int
}

// scanPieces runs the detectors over every piece until the deadline (zero
// means none) and reports whether it finished. Findings the allowlist covers
// are dropped; written files match its paths relative to repo.
func (d *Daemon) scanPieces(ps []piece, deadline time.Time, allow *content.Allowlist, repo string) ([]hit, bool) {
	var out []hit
	for i, p := range ps {
		text := p.text
		if len(text) > content.PreActionLimit && !deadline.IsZero() {
			text = text[:content.PreActionLimit]
		}
		fs, complete := d.content.ScanWithin(p.source, text, deadline)
		where := ""
		if p.path != "" {
			where = platform.DisplayPath(p.path, d.cfg.Env.Home, repo)
		}
		fs, _ = allow.Filter(fs, text, where, d.cfg.Now())
		for _, f := range fs {
			out = append(out, hit{f, i})
		}
		if !complete || (len(text) < len(p.text)) {
			return out, false
		}
	}
	return out, true
}

func summarize(hs []hit) content.Summary {
	fs := make([]content.Finding, len(hs))
	for i, h := range hs {
		fs[i] = h.Finding
	}
	return content.Summarize(fs)
}

// injects reports whether a finding in content an agent read should mark
// the session: injected or safety-weakening instructions of at least
// medium level, or instructions to send data out.
func injects(f content.Finding) bool {
	switch f.Category {
	case content.CategoryInjectedInstructions, content.CategorySafetyWeakening:
		return f.InjectionLevel == "medium" || f.InjectionLevel == "high"
	case content.CategoryExfiltration:
		return true
	}
	return false
}

// background runs fn after the reply, at most two at a time; Close waits.
func (d *Daemon) background(fn func()) {
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		d.bgSlots <- struct{}{}
		defer func() { <-d.bgSlots }()
		fn()
	}()
}

// findingEvent builds the content_finding event for one hit.
func (d *Daemon) findingEvent(c call, sess *sessionInfo, action *events.Action, mcp *events.MCP, remote string, h hit, p piece, taken events.ContentFindingActionTaken) (*events.Event, string) {
	f := h.Finding
	cf := &events.ContentFinding{DetectorID: f.DetectorID, PackVersion: f.PackVersion, Category: events.ContentFindingCategory(f.Category),
		Severity: events.ContentFindingSeverity(f.Severity), Confidence: events.ContentFindingConfidence(f.Confidence),
		Source: events.ContentFindingSource(f.Source), ActionTaken: taken}
	if f.Category == content.CategoryCredential {
		cf.SecretType, cf.Fingerprint = f.SecretType, f.Fingerprint
	}
	line := int64(f.Line)
	loc := &events.ContentFindingLocation{Line: &line, AgentProduct: c.product}
	if p.path != "" {
		class, _ := (intent.Context{Home: d.cfg.Env.Home, RepoRoot: sess.Root}).Classify(p.path)
		loc.PathClass, loc.PathHash = contract.PathClass(class), d.content.Hash(p.path)
	}
	cf.Location = loc
	ev := &events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeContentFinding,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()},
		Agent:          &events.Agent{Product: c.product, Version: c.str("agent_version"), SessionID: sess.ID, NativeSessionID: sess.Native, Pattern: events.AgentPatternInteractive},
		Action:         action,
		MCP:            mcp,
		ContentFinding: cf,
		Redaction:      map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear},
		Ext:            findingExt(f),
	}
	if remote != "" {
		ev.Repo = &events.Repo{Remote: remote}
	}
	// Local only: where it was and the masked excerpt.
	where := fmt.Sprintf("line %d", f.Line)
	if p.path != "" {
		where = p.path + ":" + strconv.Itoa(f.Line)
	}
	return ev, where + "  " + f.Excerpt
}

// recordFindings appends a content_finding event per hit, up to the cap.
func (d *Daemon) recordFindings(c call, sess *sessionInfo, action *events.Action, mcp *events.MCP, remote string, hs []hit, ps []piece, taken events.ContentFindingActionTaken) {
	for i, h := range hs {
		if i == maxFindingEvents {
			d.cfg.Logger.Info("content findings capped", "found", len(hs), "recorded", maxFindingEvents)
			break
		}
		ev, targetClear := d.findingEvent(c, sess, action, mcp, remote, h, ps[h.piece], taken)
		if err := d.appendEvent(ev, targetClear); err != nil {
			d.cfg.Logger.Warn("could not record content finding", "err", err)
		}
	}
}

// actionTaken is what happened to an action carrying a finding.
func actionTaken(verdict string) events.ContentFindingActionTaken {
	switch verdict {
	case "deny":
		return events.ContentFindingActionTakenBlocked
	case "ask":
		return events.ContentFindingActionTakenAsked
	}
	return events.ContentFindingActionTakenNone
}

// scanOutput checks what a finished tool brought into the session: injected
// instructions mark the session, and every finding is recorded.
func (d *Daemon) scanOutput(c call, sess *sessionInfo, toolName string) {
	switch c.tools.ToolKind(toolName) {
	case "file_write", "file_delete":
		return // their output echoes the input, scanned before the action
	}
	text := content.Flatten(c.field("tool_response"))
	if len(text) > maxOutputScan {
		text = text[:maxOutputScan]
	}
	if strings.TrimSpace(text) == "" {
		return
	}
	d.background(func() {
		fs, _ := d.allowlistFor(sess.Git).Filter(d.content.Scan(content.SourceToolOutput, text), text, "", d.cfg.Now())
		if len(fs) == 0 {
			return
		}
		ps := []piece{{source: content.SourceToolOutput, text: text}}
		hs := make([]hit, len(fs))
		for i, f := range fs {
			hs[i] = hit{f, 0}
		}
		if slices.ContainsFunc(fs, injects) {
			if err := d.store.MarkInjected(sess.ID); err != nil {
				d.cfg.Logger.Warn("could not mark session", "err", err)
			}
		}
		_, actions := c.actions()
		action := &events.Action{Kind: contract.ActionKindOther, ToolName: toolName}
		var mcp *events.MCP
		if len(actions) > 0 {
			a := actions[0]
			action = &events.Action{Kind: contract.ActionKind(a.Kind), ToolName: toolName, ToolUseID: c.str("tool_use_id"),
				Target: redact.Redact(targetOf(a), redact.Context{Home: d.cfg.Env.Home, RepoRoot: sess.Root})}
			mcp = mcpOf(a)
		}
		d.recordFindings(c, sess, action, mcp, remoteOf(sess), hs, ps, events.ContentFindingActionTakenNone)
	})
}

// contentSalt is this device's key for fingerprints and path hashes. A Team
// device will use its organization's salt, so fingerprints match across
// devices.
func contentSalt(get func(string) (string, error), set func(string, string) error) ([]byte, error) {
	v, err := get("content_salt")
	if err == nil && v != "" {
		return hex.DecodeString(v)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, set("content_salt", hex.EncodeToString(b))
}

// findingExt is a finding's local-only ext: its title and, when the
// fingerprint is under the organization's hash key, that key's ID.
func findingExt(f content.Finding) map[string]any {
	ext := map[string]any{"x_privometry_title": f.Title}
	if f.FingerprintKey != "" && f.Fingerprint != "" {
		ext[upload.FingerprintKeyExt] = f.FingerprintKey
	}
	return ext
}
