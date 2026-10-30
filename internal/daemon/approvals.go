package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/extension"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/intent"
)

// Remote approvals (PRD CP-21; docs/spikes/remote-approvals.md), when the
// connector is an extension.Approver and the bundle turns them on: a hook
// cannot wait for a person, so an ask that goes remote is denied at once with
// a message, the approval is requested and awaited in the background, and the
// next attempt of the same action in the same session is allowed once if it
// was approved. State is in memory; a restart only means asking again.

// remembered is how long an approval's outcome applies to retries.
const remembered = 10 * time.Minute

type approval struct {
	id        string
	status    string // requesting, pending, approved, denied, timeout, failed
	responder string
	until     time.Time
}

// approvalStep is what remote approval changes about one hook answer.
type approvalStep struct {
	native   string // what the agent is told: allow or deny
	message  string
	response events.DecisionUserResponse // set once someone decided
	request  *approvalRequest            // set when this call starts a request
}

type approvalRequest struct {
	key     string
	create  extension.ApprovalRequest
	timeout time.Duration
}

// routeApproval decides whether this ask goes remote and what to answer now;
// nil means answer as usual.
func (d *Daemon) routeApproval(c call, sess *sessionInfo, a intent.Action, dec policy.Decision, native string) *approvalStep {
	if dec.Verdict != "ask" || len(dec.RuleIDs) == 0 || d.approver == nil {
		return nil // only rule asks have something to approve, and only a connector can route them
	}
	cfg := d.approvalsConfig()
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	canAsk := native == "ask"
	if cfg.Route != bundles.BundleApprovalsRouteAll && canAsk && !unattended(c) {
		return nil // an interactive ask the developer answers
	}
	key := approvalKey(sess.ID, a, dec.RuleIDs)
	now := d.cfg.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.approvals == nil {
		d.approvals = map[string]*approval{}
	}
	st := d.approvals[key]
	if st != nil && now.After(st.until) {
		delete(d.approvals, key)
		st = nil
	}
	switch {
	case st == nil:
		d.approvals[key] = &approval{status: "requesting", until: now.Add(time.Duration(cfg.TimeoutSeconds)*time.Second + time.Minute)}
		msg := strings.TrimSpace(dec.Message)
		if len(msg) > 280 {
			msg = msg[:280]
		}
		if msg == "" {
			msg = "Approve this agent action?"
		}
		return &approvalStep{native: "deny", message: "Privometry: an approval was requested in your organization's chat. Retry this step once it is approved.",
			request: &approvalRequest{key: key, timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
				create: extension.ApprovalRequest{SessionID: sess.ID, AgentProduct: c.product, Message: msg, TimeoutSeconds: cfg.TimeoutSeconds}}}
	case st.status == "approved":
		delete(d.approvals, key) // one use
		return &approvalStep{native: "allow", message: "Privometry: approved by " + st.responder, response: events.DecisionUserResponseApproved}
	case st.status == "denied":
		return &approvalStep{native: "deny", message: "Privometry: " + st.responder + " denied this step.", response: events.DecisionUserResponseDenied}
	case st.status == "timeout":
		return &approvalStep{native: "deny", message: "Privometry: nobody approved this step in time.", response: events.DecisionUserResponseTimeout}
	case st.status == "failed":
		return nil // the cloud is unreachable: answer as without approvals
	}
	return &approvalStep{native: "deny", message: "Privometry: still waiting for approval (" + st.id + "). Retry this step once it is approved."}
}

// startApproval requests the approval for an answered hook and follows it.
func (d *Daemon) startApproval(r *approvalRequest, ev *events.Event) {
	r.create.EventID = ev.EventID
	r.create.Kind, r.create.ToolName, r.create.Target = ev.Action.Kind, ev.Action.ToolName, ev.Action.Target
	r.create.RuleIDs, r.create.Risk = ev.Decision.RuleIDs, ev.Action.Risk
	if ev.Repo != nil {
		r.create.RepoRemote = ev.Repo.Remote
	}
	// Its own goroutine, not a background slot: waiting on a person must not hold up content scans.
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		ctx, cancel := context.WithTimeout(d.stop, r.timeout+time.Minute)
		defer cancel()
		set := func(f func(*approval)) {
			d.mu.Lock()
			if st := d.approvals[r.key]; st != nil {
				f(st)
			}
			d.mu.Unlock()
		}
		a, err := d.approver.RequestApproval(ctx, r.create)
		if err != nil {
			d.cfg.Logger.Warn("approval request failed; asks are answered as without approvals for a minute", "err", err)
			set(func(st *approval) { st.status, st.until = "failed", d.cfg.Now().Add(time.Minute) })
			return
		}
		set(func(st *approval) { st.id, st.status = a.ID, "pending" })
		for a.Status == extension.ApprovalPending && ctx.Err() == nil {
			next, err := d.approver.WaitApproval(ctx, a.ID, 30*time.Second)
			if err != nil {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
				continue
			}
			a = next
		}
		status := string(a.Status)
		if status == "pending" {
			status = "timeout" // gave up waiting: no answer means deny
		}
		responder := "an approver"
		if a.Responder != "" {
			responder = a.Responder
		}
		set(func(st *approval) { st.status, st.responder, st.until = status, responder, d.cfg.Now().Add(remembered) })
	}()
}

// approvalsConfig is the held bundle's approvals section, or nil.
func (d *Daemon) approvalsConfig() *bundles.BundleApprovals {
	held, err := bundles.Load(d.cfg.Env, d.cfg.Now())
	if err != nil || held == nil {
		return nil
	}
	return held.Bundle.Approvals
}

// unattended reports whether nobody is at the agent to answer an ask.
func unattended(c call) bool {
	p := c.str("pattern")
	return p != "" && p != "interactive"
}

// approvalKey identifies one action in one session for approval purposes.
func approvalKey(session string, a intent.Action, rules []string) string {
	r := slices.Clone(rules)
	slices.Sort(r)
	sum := sha256.Sum256([]byte(strings.Join([]string{session, a.Kind, a.Command, a.Path, a.URL, a.MCPServer, a.MCPTool, strings.Join(r, ",")}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// applyApproval records what remote approval did on the event.
func (s *approvalStep) applyApproval(ev *events.Event) {
	if s.response != "" {
		ev.Decision.UserResponse = s.response
		ev.Decision.Responder = events.DecisionResponderApprover
	}
	if s.native != string(ev.Decision.Verdict) {
		ev.Decision.NativeVerdict = contract.Verdict(s.native)
	}
}
