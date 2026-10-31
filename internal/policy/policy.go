// Package policy decides agent actions: it extracts facts from an action,
// evaluates every request against the merged policy, and returns one verdict.
// Sub-packages: intent (extractors), compiler, engine, merge, rulepack.
package policy

import (
	"fmt"
	"slices"

	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/policy/engine"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/policy/merge"
)

// Policy is a merged policy ready to decide.
type Policy struct {
	merged *merge.Result
	eng    *engine.Engine
}

// New prepares a merged policy for decisions.
func New(res *merge.Result) (*Policy, error) {
	eng, err := engine.New(res.Enforce, res.Monitor, res.Unmatched)
	if err != nil {
		return nil, err
	}
	return &Policy{merged: res, eng: eng}, nil
}

// Merged returns the merged policy the decisions use.
func (p *Policy) Merged() *merge.Result { return p.merged }

// Input is one agent action to decide.
type Input struct {
	Agent              engine.Agent
	Repo               string // normalized remote, or empty outside a repo
	Action             intent.Action
	Context            intent.Context
	UntrustedInputSeen bool
	InjectionSeen      bool // the session has read injected instructions
	// Content is what the detectors found in the action's arguments or
	// written content; it applies to every request the action becomes.
	Content Content
	// CatalogStatus is what the organization's catalog says about the MCP
	// server an mcp_call goes to (approved, unapproved, blocked or unknown);
	// empty when the device has no catalog.
	CatalogStatus string
}

// Content is the detectors' findings for one action, as policy facts.
type Content struct {
	SecretTypes   []string
	Injection     string // none, low, medium, high
	HiddenContent bool
}

// Decision is the verdict for one action. Source is policy when a rule
// matched or the unmatched default asked, and auto_approve when no rule
// matched and the action was low enough risk to allow.
type Decision struct {
	Verdict      string
	Source       string
	RuleIDs      []string
	Message      string
	Category     string
	Risk         string
	Reason       string // why the deciding request got its risk
	Facts        engine.Facts
	Action       string
	WouldVerdict string
	WouldRuleIDs []string
	Requests     int
}

var strength = map[string]int{"allow": 1, "ask": 2, "deny": 3}
var riskOrder = map[string]int{"": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Step is one evaluated request: the facts sent to Cedar and its own outcome.
type Step struct {
	Request intent.Request
	Verdict string
	RuleIDs []string
}

// Decide extracts and evaluates every request in an action and returns the
// strongest verdict, with the rules that produced it.
func (p *Policy) Decide(in Input) (Decision, error) {
	d, _, err := p.Explain(in)
	return d, err
}

// Explain is Decide plus each request's own outcome, for "privometry policy test".
func (p *Policy) Explain(in Input) (Decision, []Step, error) {
	reqs := intent.Extract(in.Action, in.Context)
	var best Decision
	var steps []Step
	for i, r := range reqs {
		r.Facts.UntrustedInputSeen = in.UntrustedInputSeen
		r.Facts.InjectionSeen = in.InjectionSeen
		if r.Action == "mcp_call" && in.CatalogStatus != "" {
			r.Facts.CatalogStatus = in.CatalogStatus
		}
		r.Facts.SecretTypes, r.Facts.Injection, r.Facts.HiddenContent = in.Content.SecretTypes, in.Content.Injection, in.Content.HiddenContent
		d, err := p.eng.Decide(engine.Request{Agent: in.Agent, Repo: in.Repo, Action: r.Action, Facts: r.Facts})
		if err != nil {
			return Decision{}, nil, fmt.Errorf("policy: request %d: %w", i, err)
		}
		steps = append(steps, Step{Request: r, Verdict: d.Verdict, RuleIDs: d.RuleIDs})
		cur := Decision{Verdict: d.Verdict, RuleIDs: d.RuleIDs, Risk: r.Facts.Risk, Reason: r.Reason, Facts: r.Facts, Action: r.Action}
		if d.Would != nil {
			cur.WouldVerdict, cur.WouldRuleIDs = d.Would.Verdict, d.Would.RuleIDs
		}
		if strength[cur.WouldVerdict] < strength[best.WouldVerdict] {
			cur.WouldVerdict, cur.WouldRuleIDs = best.WouldVerdict, best.WouldRuleIDs
		}
		switch {
		case i == 0 || better(cur, best):
			best = cur
		case cur.Verdict == best.Verdict:
			for _, id := range cur.RuleIDs {
				if !slices.Contains(best.RuleIDs, id) {
					best.RuleIDs = append(best.RuleIDs, id)
				}
			}
			best.WouldVerdict, best.WouldRuleIDs = cur.WouldVerdict, cur.WouldRuleIDs
		default:
			best.WouldVerdict, best.WouldRuleIDs = cur.WouldVerdict, cur.WouldRuleIDs
		}
	}
	best.Requests = len(reqs)
	slices.Sort(best.RuleIDs)
	p.explain(&best)
	return best, steps, nil
}

// better reports whether a request's outcome should replace the current one:
// a stronger verdict wins; at the same verdict a rule match beats the
// unmatched default, and then the riskier request explains the decision.
func better(cur, best Decision) bool {
	if strength[cur.Verdict] != strength[best.Verdict] {
		return strength[cur.Verdict] > strength[best.Verdict]
	}
	if (len(cur.RuleIDs) > 0) != (len(best.RuleIDs) > 0) {
		return len(cur.RuleIDs) > 0
	}
	return len(best.RuleIDs) == 0 && riskOrder[cur.Risk] > riskOrder[best.Risk]
}

// explain fills Source, Message and Category.
func (p *Policy) explain(d *Decision) {
	d.Source = "policy"
	if len(d.RuleIDs) == 0 {
		if d.Verdict == "allow" && p.merged.Unmatched == "auto" {
			d.Source = "auto_approve"
		}
		if d.Verdict != "allow" {
			d.Message = "Privometry asks because this " + d.Reason + "."
		}
		d.Category = categoryOf(d.Facts)
		return
	}
	rule := p.rule(d.RuleIDs[0])
	d.Message, d.Category = rule.Message, string(rule.Category)
}

func (p *Policy) rule(id string) bundle.BundleRule { return p.merged.Rules[id] }

// categoryOf picks the fail-mode category for an unmatched request.
func categoryOf(f engine.Facts) string {
	for _, c := range []string{"catastrophic", "secrets", "exfiltration", "unapproved_mcp"} {
		if slices.Contains(f.Category, c) {
			return c
		}
	}
	return "other"
}
