// Package merge combines rule packs and policy layers into one compiled policy.
//
// Layers, from least to most authority: built-in packs, user policy
// (~/.privometry/policy.yaml), repo policy (.privometry/policy.yaml), organization
// bundle. All rules are evaluated together and the strongest verdict wins.
// Changing an existing rule follows Contracts v1:
//
//   - Any layer may tighten any rule (stronger verdict, enforce instead of
//     monitor, stricter fail mode).
//   - A rule may be loosened, including by an exception, only if it is a
//     built-in rule, an organization rule marked overridable, or the change
//     comes from the organization itself.
//   - Locked organization rules cannot be changed by lower layers at all.
//   - Repo and user overrides of the same rule combine by the strongest
//     setting, so a developer cannot undo a repo's tightening; an
//     organization override then replaces them.
//
// A setting that breaks these rules is ignored with a diagnostic, never a
// failure: a bad repo file must not switch protection off.
package merge

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/cloud/bundles"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/internal/policy/rulepack"
)

// Layer names.
const (
	Builtin = "builtin"
	User    = "user"
	Repo    = "repo"
	Org     = "org"
)

var authority = map[string]int{Builtin: 0, User: 1, Repo: 2, Org: 3}

// Source is one policy file and the layer it was loaded from.
type Source struct {
	Layer   string // user, repo or org
	Version string // for display, for example a bundle version
	Policy  compiler.Policy
}

// Input is everything to merge.
type Input struct {
	Packs    []rulepack.Pack // packs available on this sensor
	Policies []Source
	Now      time.Time
}

// Diagnostic explains a setting that was ignored or adjusted.
type Diagnostic struct {
	Layer   string `json:"layer"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

// Result is a merged, compiled policy.
type Result struct {
	Enforce     string
	Monitor     string
	Rules       map[string]bundles.BundleRule // by qualified ID
	Unmatched   string                        // auto, allow or ask
	FailModes   map[string]contract.FailMode  // by rule category
	Packs       []string                      // id@version of every pack in use
	Diagnostics []Diagnostic
}

var verdictStrength = map[string]int{"allow": 1, "ask": 2, "deny": 3}
var failStrength = map[contract.FailMode]int{contract.FailModeOpen: 1, contract.FailModeAsk: 2, contract.FailModeClosed: 3}
var unmatchedStrength = map[string]int{"allow": 1, "auto": 2, "ask": 3}

type entry struct {
	compiler.Entry
	meta       bundles.BundleRule
	exceptions []*compiler.Conditions
	disabled   bool
}

type merger struct {
	in      Input
	entries map[string]*entry
	order   []string
	diags   []Diagnostic
}

func (m *merger) warn(layer, source, format string, args ...any) {
	m.diags = append(m.diags, Diagnostic{Layer: layer, Source: source, Message: fmt.Sprintf(format, args...)})
}

// Merge combines packs and policies.
func Merge(in Input) (*Result, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	m := &merger{in: in, entries: map[string]*entry{}}
	sources := slices.Clone(in.Policies)
	sort.SliceStable(sources, func(i, j int) bool { return authority[sources[i].Layer] < authority[sources[j].Layer] })

	packs := m.selectPacks(sources)
	for _, p := range packs {
		m.addPack(p)
	}
	for _, s := range sources {
		m.addPolicy(s)
	}
	m.applyOverrides(sources)
	m.applyExceptions(sources)

	res := &Result{Rules: map[string]bundles.BundleRule{}, Unmatched: "auto", FailModes: map[string]contract.FailMode{}}
	for k, v := range contract.DefaultFailModes() {
		res.FailModes[k] = v
	}
	for _, p := range packs {
		res.Packs = append(res.Packs, p.Manifest.ID+"@"+p.Manifest.Version)
		for cat, fm := range p.Manifest.DefaultFailModes {
			if failStrength[fm] > failStrength[res.FailModes[cat]] {
				res.FailModes[cat] = fm
			}
		}
	}
	for _, s := range sources {
		name := s.Policy.Name
		if u := s.Policy.Defaults.Unmatched; u != "" && unmatchedStrength[u] > unmatchedStrength[res.Unmatched] {
			res.Unmatched = u
		}
		for cat, fm := range s.Policy.Defaults.FailModes {
			fm := contract.FailMode(fm)
			if s.Layer == Org || failStrength[fm] >= failStrength[res.FailModes[cat]] {
				res.FailModes[cat] = fm
			} else {
				m.warn(s.Layer, name, "fail mode for %s cannot be loosened to %s outside the organization policy", cat, fm)
			}
		}
	}

	var entries []compiler.Entry
	for _, id := range m.order {
		e := m.entries[id]
		if e.disabled {
			continue
		}
		e.Exceptions = e.exceptions
		e.Rule.Verdict = string(e.meta.Verdict)
		e.Mode = string(e.meta.Mode)
		entries = append(entries, e.Entry)
		res.Rules[id] = e.meta
	}
	out, err := compiler.CompileEntries(entries)
	if err != nil {
		return nil, err
	}
	res.Enforce, res.Monitor = out.Enforce, out.Monitor
	// Fill rules' fail modes from their category where no rule or override set one.
	for id, r := range res.Rules {
		if r.FailMode == "" {
			r.FailMode = res.FailModes[string(r.Category)]
			res.Rules[id] = r
		}
	}
	res.Diagnostics = m.diags
	return res, nil
}

// selectPacks returns Privometry's own packs plus those named by extends, at a
// version satisfying every range that names them.
func (m *merger) selectPacks(sources []Source) []rulepack.Pack {
	byID := map[string]rulepack.Pack{}
	for _, p := range m.in.Packs {
		byID[p.Manifest.ID] = p
	}
	want := map[string]bool{}
	for id := range byID {
		if strings.HasPrefix(id, "privometry/") {
			want[id] = true
		}
	}
	for _, s := range sources {
		for _, ref := range s.Policy.Extends {
			id, rng, _ := strings.Cut(ref, "@")
			p, ok := byID[id]
			switch {
			case !ok:
				m.warn(s.Layer, s.Policy.Name, "pack %s is not installed", id)
			case !rulepack.Satisfies(p.Manifest.Version, rng):
				m.warn(s.Layer, s.Policy.Name, "pack %s is at %s, which does not satisfy %s; using it anyway", id, p.Manifest.Version, rng)
				want[id] = true
			default:
				want[id] = true
			}
		}
	}
	var out []rulepack.Pack
	for _, p := range m.in.Packs {
		if want[p.Manifest.ID] {
			out = append(out, p)
		}
	}
	return out
}

func (m *merger) add(id, layer, source string, r compiler.Rule, mode string, failMode contract.FailMode) {
	if r.Category == "" {
		r.Category = "other"
	}
	if r.FailMode != "" {
		failMode = contract.FailMode(r.FailMode)
	}
	if mode == "" {
		mode = "enforce"
	}
	m.entries[id] = &entry{
		Entry: compiler.Entry{ID: id, Layer: layer, Mode: mode, Rule: r},
		meta: bundles.BundleRule{ID: id, Layer: bundles.BundleRuleLayer(layer), Verdict: contract.Verdict(r.Verdict),
			Category: contract.RuleCategory(r.Category), Mode: bundles.BundleRuleMode(mode), FailMode: failMode,
			Message: r.Message, Source: source},
	}
	m.order = append(m.order, id)
}

func (m *merger) addPack(p rulepack.Pack) {
	src := p.Manifest.ID + "@" + p.Manifest.Version
	for _, r := range p.Rules {
		m.add(p.Manifest.ID+":"+r.ID, Builtin, src, r, r.Mode, p.Manifest.DefaultFailModes[r.Category])
	}
}

func (m *merger) addPolicy(s Source) {
	name := s.Policy.Name
	src := name
	if s.Version != "" {
		src += "@" + s.Version
	}
	for _, r := range s.Policy.Rules {
		if s.Layer != Org && (r.Locked || r.Overridable) {
			m.warn(s.Layer, name, "rule %s: locked and overridable apply only to organization rules; ignored", r.ID)
			r.Locked, r.Overridable = false, false
		}
		id := name + ":" + r.ID
		if _, dup := m.entries[id]; dup {
			m.warn(s.Layer, name, "rule %s is defined twice; the second definition is ignored", id)
			continue
		}
		mode := r.Mode
		if mode == "" {
			mode = s.Policy.Defaults.Mode
		}
		m.add(id, s.Layer, src, r, mode, "")
		e := m.entries[id]
		if r.Locked {
			e.meta.Locked = &r.Locked
		}
		if r.Overridable {
			e.meta.Overridable = &r.Overridable
		}
	}
}

// mayLoosen reports whether a change from layer may weaken rule e.
func mayLoosen(e *entry, layer string) bool {
	switch {
	case layer == Org:
		return true
	case string(e.meta.Layer) == Builtin:
		return true
	case string(e.meta.Layer) == Org:
		return e.meta.Overridable != nil && *e.meta.Overridable
	}
	return layer == string(e.meta.Layer) // a layer may change its own rules
}

func locked(e *entry) bool { return e.meta.Locked != nil && *e.meta.Locked }

// resolve turns a rule reference into a qualified ID: bare IDs refer to the
// policy's own rules.
func resolve(ref, policy string) string {
	if strings.Contains(ref, ":") {
		return ref
	}
	return policy + ":" + ref
}

// applyOverrides applies user and repo overrides combined by strength, then
// organization overrides as written.
func (m *merger) applyOverrides(sources []Source) {
	type change struct {
		layer, policy string
		o             compiler.Override
	}
	byRule := map[string][]change{}
	var ids []string
	for _, s := range sources {
		keys := make([]string, 0, len(s.Policy.Overrides))
		for k := range s.Policy.Overrides {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			id := resolve(k, s.Policy.Name)
			if _, seen := byRule[id]; !seen {
				ids = append(ids, id)
			}
			byRule[id] = append(byRule[id], change{s.Layer, s.Policy.Name, s.Policy.Overrides[k]})
		}
	}
	for _, id := range ids {
		e, ok := m.entries[id]
		if !ok {
			for _, c := range byRule[id] {
				m.warn(c.layer, c.policy, "override for unknown rule %s ignored", id)
			}
			continue
		}
		base := e.meta
		lower := bundles.BundleRule{}
		overridden := false
		for _, c := range byRule[id] {
			if c.layer == Org {
				continue
			}
			if locked(e) {
				m.warn(c.layer, c.policy, "rule %s is locked by the organization; override ignored", id)
				continue
			}
			if !m.permitted(e, c.layer, c.policy, c.o, base) {
				continue
			}
			overridden = true
			if v := c.o.Verdict; v != "" && verdictStrength[v] > verdictStrength[string(lower.Verdict)] {
				lower.Verdict = contract.Verdict(v)
			}
			if md := c.o.Mode; md != "" && (lower.Mode == "" || md == "enforce") {
				lower.Mode = bundles.BundleRuleMode(md)
			}
			if fm := contract.FailMode(c.o.FailMode); fm != "" && failStrength[fm] > failStrength[lower.FailMode] {
				lower.FailMode = fm
			}
			if c.o.Message != "" {
				lower.Message = c.o.Message
			}
		}
		if overridden {
			apply(&e.meta, lower)
		}
		for _, c := range byRule[id] {
			if c.layer == Org {
				apply(&e.meta, bundles.BundleRule{Verdict: contract.Verdict(c.o.Verdict), Mode: bundles.BundleRuleMode(c.o.Mode),
					FailMode: contract.FailMode(c.o.FailMode), Message: c.o.Message})
			}
		}
		if (e.meta.Verdict == contract.VerdictAsk || e.meta.Verdict == contract.VerdictDeny) && e.meta.Message == "" {
			e.meta.Message = "Blocked by " + id
		}
	}
}

func apply(dst *bundles.BundleRule, o bundles.BundleRule) {
	if o.Verdict != "" {
		dst.Verdict = o.Verdict
	}
	if o.Mode != "" {
		dst.Mode = o.Mode
	}
	if o.FailMode != "" {
		dst.FailMode = o.FailMode
	}
	if o.Message != "" {
		dst.Message = o.Message
	}
}

// permitted checks one non-organization override against the loosening rules.
func (m *merger) permitted(e *entry, layer, policy string, o compiler.Override, base bundles.BundleRule) bool {
	loosens := []string{}
	if o.Verdict != "" && verdictStrength[o.Verdict] < verdictStrength[string(base.Verdict)] {
		loosens = append(loosens, "verdict "+o.Verdict)
	}
	if o.Mode == "monitor" && base.Mode != "monitor" {
		loosens = append(loosens, "monitor mode")
	}
	if fm := contract.FailMode(o.FailMode); fm != "" && base.FailMode != "" && failStrength[fm] < failStrength[base.FailMode] {
		loosens = append(loosens, "fail mode "+o.FailMode)
	}
	if len(loosens) > 0 && !mayLoosen(e, layer) {
		m.warn(layer, policy, "override of %s ignored: a %s policy cannot loosen a %s rule (%s)", e.ID, layer, e.meta.Layer, strings.Join(loosens, ", "))
		return false
	}
	return true
}

// applyExceptions attaches unexpired, permitted exceptions to their rules.
func (m *merger) applyExceptions(sources []Source) {
	for _, s := range sources {
		name := s.Policy.Name
		for _, x := range s.Policy.Exceptions {
			id := resolve(x.Rule, name)
			e, ok := m.entries[id]
			switch {
			case !ok:
				m.warn(s.Layer, name, "exception for unknown rule %s ignored", id)
				continue
			case s.Layer == Org && x.ApprovedBy == "":
				m.warn(s.Layer, name, "organization exception for %s has no approved_by; ignored", id)
				continue
			case s.Layer != Org && locked(e):
				m.warn(s.Layer, name, "rule %s is locked by the organization; exception ignored", id)
				continue
			case !mayLoosen(e, s.Layer):
				m.warn(s.Layer, name, "exception for %s ignored: a %s policy cannot loosen a %s rule", id, s.Layer, e.meta.Layer)
				continue
			}
			expires, err := time.Parse(time.RFC3339, x.ExpiresAt)
			if err != nil {
				m.warn(s.Layer, name, "exception for %s has an invalid expires_at %q; ignored", id, x.ExpiresAt)
				continue
			}
			if !m.in.Now.Before(expires) {
				m.warn(s.Layer, name, "exception for %s expired at %s; ignored", id, x.ExpiresAt)
				continue
			}
			cond := x.Conditions
			if cond.Empty() {
				e.disabled = true
				continue
			}
			e.exceptions = append(e.exceptions, &cond)
		}
	}
}

// NextExpiry returns when the earliest active exception expires, so the
// caller can merge again at that moment. Zero when none expire.
func NextExpiry(in Input) time.Time {
	var next time.Time
	for _, s := range in.Policies {
		for _, x := range s.Policy.Exceptions {
			t, err := time.Parse(time.RFC3339, x.ExpiresAt)
			if err == nil && t.After(in.Now) && (next.IsZero() || t.Before(next)) {
				next = t
			}
		}
	}
	return next
}
