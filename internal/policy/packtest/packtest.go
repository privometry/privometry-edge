// Package packtest runs rule pack and policy tests. It is the release gate for
// packs (rulepacks/rulepacks_test.go) and backs "privometry policy test".
package packtest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/internal/policy/engine"
	"github.com/privometry/privometry-oss/internal/policy/merge"
	"github.com/privometry/privometry-oss/internal/policy/rulepack"
	"github.com/privometry/privometry-oss/specs"
)

// Report is the outcome of testing one pack or policy.
type Report struct {
	Kind      string // pack or policy
	Name      string // pack ID or policy name
	Rules     int
	Tests     int
	Failures  []string // tests that did not get the expected outcome
	Problems  []string // schema, compile, type-check and coverage errors
	Notes     []string // merge diagnostics and coverage hints that do not fail
	Uncovered []string // rules without a matching and a non-matching test
}

// OK reports whether the pack or policy passed.
func (r *Report) OK() bool { return len(r.Failures) == 0 && len(r.Problems) == 0 }

func (r *Report) problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Pack tests a rule pack folder: every file must match its schema, rules must
// compile to Cedar that type-checks against privometry.cedarschema, rule
// categories must be listed in the manifest, every test must pass with the
// pack evaluated alone (unmatched: auto), and every rule needs a matching and
// a non-matching test.
func Pack(dir string) *Report {
	r := &Report{Kind: "pack", Name: dir}
	var m rulepack.Manifest
	if err := decode(filepath.Join(dir, "pack.yaml"), "rulepack/v1/pack.schema.json", &m); err != nil {
		r.problem("%v", err)
		return r
	}
	r.Name = m.ID
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		r.problem("README.md is required")
	}
	ruleFiles, _ := filepath.Glob(filepath.Join(dir, "rules", "*.yaml"))
	if len(ruleFiles) == 0 {
		r.problem("no files in rules/")
		return r
	}
	var rules []compiler.Rule
	for _, f := range ruleFiles {
		raw, err := os.ReadFile(f)
		if err == nil {
			err = specs.Validate("rulepack/v1/rules.schema.json", f, raw)
		}
		var doc struct {
			Rules []compiler.Rule `yaml:"rules"`
		}
		if err == nil {
			err = yaml.Unmarshal(raw, &doc)
		}
		if err != nil {
			r.problem("%v", err)
			continue
		}
		rules = append(rules, doc.Rules...)
	}
	r.Rules = len(rules)
	for _, rule := range rules {
		if !slices.Contains(m.Categories, contract.RuleCategory(rule.Category)) {
			r.problem("rule %s: category %q is not in pack.yaml categories", rule.ID, rule.Category)
		}
	}
	out, err := compiler.Compile(rules, compiler.Options{Qualifier: m.ID, Layer: merge.Builtin})
	if err != nil {
		r.problem("%v", err)
		return r
	}
	typeCheck(r, out.Enforce, out.Monitor)
	eng, err := engine.New(out.Enforce, out.Monitor, "auto")
	if err != nil {
		r.problem("%v", err)
		return r
	}
	local := make([]string, len(rules))
	for i, rule := range rules {
		local[i] = rule.ID
	}
	runTests(r, filepath.Join(dir, "tests"), eng, m.ID, local, true)
	if len(r.Uncovered) > 0 {
		r.problem("rules without a matching and a non-matching test: %v", r.Uncovered)
	}
	return r
}

// Policy tests a policy file merged with packs, as the given layer. Tests
// come from testsDir (*.test.yaml); there, expect.rule names a rule of this
// policy that must be among the deciding rules, and an omitted rule checks
// the verdict only. Merge diagnostics and uncovered rules are notes.
func Policy(src merge.Source, packs []rulepack.Pack, testsDir string) *Report {
	r := &Report{Kind: "policy", Name: src.Policy.Name}
	r.Rules = len(src.Policy.Rules)
	res, err := merge.Merge(merge.Input{Packs: packs, Policies: []merge.Source{src}})
	if err != nil {
		r.problem("%v", err)
		return r
	}
	for _, d := range res.Diagnostics {
		r.Notes = append(r.Notes, d.Message)
	}
	typeCheck(r, res.Enforce, res.Monitor)
	eng, err := engine.New(res.Enforce, res.Monitor, res.Unmatched)
	if err != nil {
		r.problem("%v", err)
		return r
	}
	local := make([]string, len(src.Policy.Rules))
	for i, rule := range src.Policy.Rules {
		local[i] = rule.ID
	}
	runTests(r, testsDir, eng, src.Policy.Name, local, false)
	if len(r.Uncovered) > 0 && r.Tests > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("rules without a matching and a non-matching test: %v", r.Uncovered))
	}
	return r
}

// runTests runs every *.test.yaml in dir. exact means expect.rule must be the
// only deciding rule and an omitted rule means none may match (pack tests).
func runTests(r *Report, dir string, eng *engine.Engine, qualifier string, rules []string, exact bool) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.test.yaml"))
	sort.Strings(files)
	if len(files) == 0 && exact {
		r.problem("no files in tests/")
	}
	matches, nonMatches := map[string]int{}, map[string]int{}
	for _, f := range files {
		var file rulepack.TestFile
		if err := decode(f, "rulepack/v1/ruletest.schema.json", &file); err != nil {
			r.problem("%v", err)
			continue
		}
		for _, tc := range file.Tests {
			r.Tests++
			if tc.Covers != "" {
				if !slices.Contains(rules, tc.Covers) {
					r.problem("%s: %q covers unknown rule %q", filepath.Base(f), tc.Name, tc.Covers)
				}
				if tc.Expect.Rule == tc.Covers || slices.Contains(tc.Expect.Rules, qualifier+":"+tc.Covers) {
					matches[tc.Covers]++
				} else {
					nonMatches[tc.Covers]++
				}
			}
			if err := check(eng, qualifier, tc, exact); err != nil {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: %s: %v", filepath.Base(f), tc.Name, err))
			}
		}
	}
	for _, id := range rules {
		if matches[id] == 0 || nonMatches[id] == 0 {
			r.Uncovered = append(r.Uncovered, id)
		}
	}
}

func check(eng *engine.Engine, qualifier string, tc rulepack.TestFileTest, exact bool) error {
	d, err := eng.Decide(Request(tc.Facts))
	if err != nil {
		return err
	}
	want := ""
	if tc.Expect.Rule != "" {
		want = qualifier + ":" + tc.Expect.Rule
	}
	ok := d.Verdict == string(tc.Expect.Verdict)
	if tc.Expect.Rules != nil {
		wantSet := slices.Sorted(slices.Values(tc.Expect.Rules))
		if !ok || !slices.Equal(d.RuleIDs, wantSet) {
			return fmt.Errorf("got %s %v, want %s %v", d.Verdict, d.RuleIDs, tc.Expect.Verdict, wantSet)
		}
		return nil
	}
	switch {
	case exact && want == "":
		ok = ok && len(d.RuleIDs) == 0
	case exact:
		ok = ok && slices.Equal(d.RuleIDs, []string{want})
	case want != "":
		ok = ok && slices.Contains(d.RuleIDs, want)
	}
	if !ok {
		w := string(tc.Expect.Verdict)
		if want != "" {
			w += " " + want
		}
		return fmt.Errorf("got %s %v, want %s", d.Verdict, d.RuleIDs, w)
	}
	return nil
}

// Request turns test facts into an engine request.
func Request(f rulepack.Facts) engine.Request {
	return engine.Request{
		Agent:  engine.Agent{Product: string(f.Agent), Pattern: "interactive"},
		Repo:   f.Repo,
		Action: string(f.Action),
		Facts: engine.Facts{
			Intent: strs(f.Intent), Category: strs(f.Category), Risk: string(f.Risk), Program: f.Program,
			Subcommand: f.Subcommand, Flags: f.Flags, PathClass: string(f.PathClass),
			TargetPath: f.TargetPath, Host: f.Host, MCPServer: f.MCPServer, MCPTool: f.MCPTool,
			CatalogStatus: string(f.CatalogStatus), UntrustedInputSeen: f.UntrustedInputSeen != nil && *f.UntrustedInputSeen,
			SecretTypes: f.SecretDetected, Injection: string(f.InjectionDetected), InjectionSeen: f.InjectionSeen != nil && *f.InjectionSeen,
			HiddenContent: f.HiddenContent != nil && *f.HiddenContent, TargetClass: string(f.TargetClass),
		},
	}
}

func strs[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

func decode(path, schemaPath string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return specs.DecodeInto(schemaPath, path, raw, out)
}

var validator *validate.Validator

// typeCheck validates compiled Cedar against privometry.cedarschema.
func typeCheck(r *Report, sets ...string) {
	if validator == nil {
		var s schema.Schema
		if err := s.UnmarshalCedar(specs.CedarSchema); err != nil {
			r.problem("privometry.cedarschema: %v", err)
			return
		}
		res, err := s.Resolve()
		if err != nil {
			r.problem("privometry.cedarschema: %v", err)
			return
		}
		validator = validate.New(res, validate.WithStrict())
	}
	for _, text := range sets {
		ps, err := cedar.NewPolicySetFromBytes("compiled.cedar", []byte(text))
		if err != nil {
			r.problem("compiled Cedar does not parse: %v", err)
			continue
		}
		for id, p := range ps.All() {
			if err := validator.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
				r.problem("%s: %v", p.Annotations()["id"], err)
			}
		}
	}
}
