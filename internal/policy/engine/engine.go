// Package engine evaluates compiled Cedar policy sets against extractor facts
// and maps Cedar's permit/deny answer to Privometry's allow, ask or deny.
package engine

import (
	"fmt"
	"slices"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/privometry/privometry-edge/internal/policy/facts"
)

// Agent is the session making the request (the Cedar principal).
type Agent struct {
	Product string
	Version string
	Pattern string
}

// Facts are one target of one action; see internal/policy/facts.
type Facts = facts.Facts

// Request is one Cedar request: one command and one target.
type Request struct {
	Agent  Agent
	Repo   string // normalized remote; empty means the machine is the resource
	Action string // action kind, for example shell_exec
	Facts  Facts
}

// Outcome is a verdict and the rules that produced it. RuleIDs is empty when
// no rule matched and the unmatched default decided.
type Outcome struct {
	Verdict string
	RuleIDs []string
}

// Decision is the enforced outcome plus, when a monitor rule matched, what it
// would have done.
type Decision struct {
	Outcome
	Would *Outcome
}

// Engine holds the enforce and monitor policy sets for one compiled policy.
type Engine struct {
	enforce   *cedar.PolicySet
	monitor   *cedar.PolicySet
	unmatched string
}

// New parses compiled Cedar. unmatched is auto, allow or ask.
func New(enforce, monitor, unmatched string) (*Engine, error) {
	switch unmatched {
	case "auto", "allow", "ask":
	default:
		return nil, fmt.Errorf("engine: unknown unmatched default %q", unmatched)
	}
	e := &Engine{unmatched: unmatched}
	var err error
	if e.enforce, err = cedar.NewPolicySetFromBytes("enforce.cedar", []byte(enforce)); err != nil {
		return nil, fmt.Errorf("engine: enforce set: %w", err)
	}
	if e.monitor, err = cedar.NewPolicySetFromBytes("monitor.cedar", []byte(monitor)); err != nil {
		return nil, fmt.Errorf("engine: monitor set: %w", err)
	}
	return e, nil
}

var riskLevels = map[string]types.Long{"": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Decide evaluates one request.
func (e *Engine) Decide(req Request) (Decision, error) {
	entities, creq, err := build(req)
	if err != nil {
		return Decision{}, err
	}
	out, matched := evaluate(e.enforce, entities, creq)
	if !matched {
		out = Outcome{Verdict: e.unmatchedVerdict(req.Facts.Risk)}
	}
	d := Decision{Outcome: out}
	// Monitor rules never use the unmatched default: no match, no would_verdict.
	if would, ok := evaluate(e.monitor, entities, creq); ok {
		d.Would = &would
	}
	return d, nil
}

func (e *Engine) unmatchedVerdict(risk string) string {
	if e.unmatched != "auto" {
		return e.unmatched
	}
	if riskLevels[risk] <= 1 {
		return "allow"
	}
	return "ask"
}

// evaluate applies the mapping from Contracts v1: a satisfied forbid gives
// deny; an allow gives ask if any satisfied permit is @verdict("ask"), else
// allow. matched is false when no policy was satisfied.
func evaluate(ps *cedar.PolicySet, entities types.EntityMap, req cedar.Request) (Outcome, bool) {
	decision, diag := cedar.Authorize(ps, entities, req)
	if len(diag.Reasons) == 0 {
		return Outcome{}, false
	}
	byVerdict := map[string][]string{}
	for _, r := range diag.Reasons {
		a := ps.Get(r.PolicyID).Annotations()
		v := string(a["verdict"])
		byVerdict[v] = append(byVerdict[v], string(a["id"]))
	}
	verdict := "allow"
	switch {
	case decision == cedar.Deny:
		verdict = "deny"
	case len(byVerdict["ask"]) > 0:
		verdict = "ask"
	}
	ids := byVerdict[verdict]
	slices.Sort(ids)
	return Outcome{Verdict: verdict, RuleIDs: ids}, true
}

func build(req Request) (types.EntityMap, cedar.Request, error) {
	f := req.Facts
	risk, ok := riskLevels[f.Risk]
	if !ok {
		return nil, cedar.Request{}, fmt.Errorf("engine: unknown risk %q", f.Risk)
	}
	injection := f.Injection
	if injection == "" {
		injection = "none"
	}
	ctx := types.NewRecord(types.RecordMap{
		"intent":               set(f.Intent),
		"category":             set(f.Category),
		"risk":                 risk,
		"program":              types.String(f.Program),
		"subcommand":           types.String(f.Subcommand),
		"flags":                set(f.Flags),
		"path_class":           types.String(f.PathClass),
		"target_path":          types.String(f.TargetPath),
		"host":                 types.String(f.Host),
		"mcp_server":           types.String(f.MCPServer),
		"mcp_tool":             types.String(f.MCPTool),
		"catalog_status":       types.String(f.CatalogStatus),
		"untrusted_input_seen": types.Boolean(f.UntrustedInputSeen),
		"secret_detected":      set(f.SecretTypes),
		"injection_detected":   types.String(injection),
		"injection_seen":       types.Boolean(f.InjectionSeen),
		"hidden_content":       types.Boolean(f.HiddenContent),
		"target_class":         types.String(f.TargetClass),
	})

	principal := types.NewEntityUID("Privometry::Agent", "session")
	entities := types.EntityMap{
		principal: {UID: principal, Attributes: types.NewRecord(types.RecordMap{
			"product": types.String(req.Agent.Product),
			"version": types.String(req.Agent.Version),
			"pattern": types.String(req.Agent.Pattern),
		})},
	}
	resource := types.NewEntityUID("Privometry::Machine", "local")
	if req.Repo != "" {
		resource = types.NewEntityUID("Privometry::Repo", types.String(req.Repo))
		entities[resource] = types.Entity{UID: resource, Attributes: types.NewRecord(types.RecordMap{"remote": types.String(req.Repo)})}
	} else {
		entities[resource] = types.Entity{UID: resource}
	}
	return entities, cedar.Request{
		Principal: principal,
		Action:    types.NewEntityUID("Privometry::Action", types.String(req.Action)),
		Resource:  resource,
		Context:   ctx,
	}, nil
}

func set(values []string) types.Set {
	items := make([]types.Value, len(values))
	for i, v := range values {
		items[i] = types.String(v)
	}
	return types.NewSet(items...)
}
