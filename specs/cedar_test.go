package specs_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"go.yaml.in/yaml/v3"
)

// cedarValidator parses privometry.cedarschema. cedar-go's validator is
// experimental; the Java bindings remain the authority before a bundle is signed.
func cedarValidator(t *testing.T) *validate.Validator {
	t.Helper()
	raw, err := os.ReadFile("policy/v1/privometry.cedarschema")
	if err != nil {
		t.Fatal(err)
	}
	var s schema.Schema
	s.SetFilename("privometry.cedarschema")
	if err := s.UnmarshalCedar(raw); err != nil {
		t.Fatalf("parse privometry.cedarschema: %v", err)
	}
	res, err := s.Resolve()
	if err != nil {
		t.Fatalf("resolve privometry.cedarschema: %v", err)
	}
	return validate.New(res, validate.WithStrict())
}

// TestCompiledPolicies checks every compiled example against the Cedar schema
// and the annotation contract: @id, @verdict, @layer and @category, with
// forbid only for deny and permit only for allow or ask.
func TestCompiledPolicies(t *testing.T) {
	v := cedarValidator(t)
	files, _ := filepath.Glob("policy/v1/examples/compiled/*.cedar")
	if len(files) == 0 {
		t.Fatal("no compiled examples")
	}
	for _, f := range files {
		for id, p := range loadPolicies(t, f).All() {
			if err := v.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
				t.Errorf("%s %s: %v", f, id, err)
			}
			a := p.Annotations()
			for _, k := range []types.Ident{"id", "verdict", "layer", "category"} {
				if a[k] == "" {
					t.Errorf("%s %s: missing @%s", f, id, k)
				}
			}
			verdict := string(a["verdict"])
			if (p.Effect() == cedar.Forbid) != (verdict == "deny") {
				t.Errorf("%s %s: effect does not match @verdict(%q)", f, id, verdict)
			}
		}
	}
}

type vectorFile struct {
	Schema          string   `yaml:"schema"`
	Policies        string   `yaml:"policies"`
	MonitorPolicies string   `yaml:"monitor_policies"`
	Unmatched       string   `yaml:"unmatched"`
	Tests           []vector `yaml:"tests"`
}

type vector struct {
	Name    string `yaml:"name"`
	Request struct {
		Agent struct {
			Product string `yaml:"product"`
			Version string `yaml:"version"`
			Pattern string `yaml:"pattern"`
		} `yaml:"agent"`
		Repo    string         `yaml:"repo"`
		Machine bool           `yaml:"machine"`
		Action  string         `yaml:"action"`
		Facts   map[string]any `yaml:"facts"`
	} `yaml:"request"`
	Expect struct {
		Verdict      string   `yaml:"verdict"`
		RuleIDs      []string `yaml:"rule_ids"`
		WouldVerdict string   `yaml:"would_verdict"`
		WouldRuleIDs []string `yaml:"would_rule_ids"`
	} `yaml:"expect"`
}

// TestVerdictVectors runs the shared conformance vectors. The verdict mapping
// below is the reference the Go engine (M3) and the Java engine must match.
func TestVerdictVectors(t *testing.T) {
	v := cedarValidator(t)
	files, _ := filepath.Glob("conformance/policy-verdicts/*.yaml")
	if len(files) == 0 {
		t.Fatal("no verdict vectors")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var vf vectorFile
		if err := yaml.Unmarshal(raw, &vf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if vf.Schema != "privometry.verdicttest/v1" {
			t.Fatalf("%s: schema is %q", f, vf.Schema)
		}
		dir := filepath.Dir(f)
		enforce := loadPolicies(t, filepath.Join(dir, vf.Policies))
		var monitor *cedar.PolicySet
		if vf.MonitorPolicies != "" {
			monitor = loadPolicies(t, filepath.Join(dir, vf.MonitorPolicies))
		}
		for _, tc := range vf.Tests {
			t.Run(filepath.Base(f)+"/"+tc.Name, func(t *testing.T) {
				entities, req := buildRequest(t, tc)
				if err := v.Request(req); err != nil {
					t.Fatalf("request does not match privometry.cedarschema: %v", err)
				}
				verdict, rules := evaluate(enforce, entities, req, vf.Unmatched)
				if verdict != tc.Expect.Verdict || !sameIDs(rules, tc.Expect.RuleIDs) {
					t.Errorf("got %s %v, want %s %v", verdict, rules, tc.Expect.Verdict, tc.Expect.RuleIDs)
				}
				if monitor == nil {
					return
				}
				// Monitor rules never use the unmatched default: no match means no would_verdict.
				would, wouldRules := evaluate(monitor, entities, req, "")
				if would != tc.Expect.WouldVerdict || !sameIDs(wouldRules, tc.Expect.WouldRuleIDs) {
					t.Errorf("monitor: got %s %v, want %s %v", would, wouldRules, tc.Expect.WouldVerdict, tc.Expect.WouldRuleIDs)
				}
			})
		}
	}
}

// evaluate applies Contracts v1's three-step mapping:
//  1. deny with a satisfied forbid -> deny
//  2. allow -> ask if any satisfied permit is @verdict("ask"), else allow
//  3. deny with nothing satisfied -> the unmatched default
func evaluate(ps *cedar.PolicySet, entities types.EntityMap, req cedar.Request, unmatched string) (string, []string) {
	decision, diag := cedar.Authorize(ps, entities, req)
	byVerdict := map[string][]string{}
	for _, r := range diag.Reasons {
		a := ps.Get(r.PolicyID).Annotations()
		byVerdict[string(a["verdict"])] = append(byVerdict[string(a["verdict"])], string(a["id"]))
	}
	switch {
	case decision == cedar.Deny && len(diag.Reasons) > 0:
		return "deny", byVerdict["deny"]
	case decision == cedar.Allow && len(byVerdict["ask"]) > 0:
		return "ask", byVerdict["ask"]
	case decision == cedar.Allow:
		return "allow", byVerdict["allow"]
	}
	switch unmatched {
	case "allow", "ask":
		return unmatched, nil
	case "auto":
		risk, _ := req.Context.Get("risk")
		if risk.(types.Long) <= 1 {
			return "allow", nil
		}
		return "ask", nil
	}
	return "", nil
}

var riskLevels = map[string]types.Long{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// buildRequest fills every Facts attribute, using the empty value for facts the
// vector leaves out, exactly as the extractors must.
func buildRequest(t *testing.T, tc vector) (types.EntityMap, cedar.Request) {
	t.Helper()
	r := tc.Request
	ctx := types.RecordMap{
		"intent": types.NewSet(), "category": types.NewSet(), "flags": types.NewSet(),
		"risk": types.Long(0), "untrusted_input_seen": types.False,
		"secret_detected": types.NewSet(), "injection_detected": types.String("none"),
		"injection_seen": types.False, "hidden_content": types.False,
	}
	for _, k := range []types.String{"program", "subcommand", "path_class", "target_path", "host", "mcp_server", "mcp_tool", "catalog_status", "target_class"} {
		ctx[k] = types.String("")
	}
	for k, val := range r.Facts {
		switch x := val.(type) {
		case string:
			if k == "risk" {
				level, ok := riskLevels[x]
				if !ok {
					t.Fatalf("unknown risk %q", x)
				}
				ctx["risk"] = level
			} else {
				ctx[types.String(k)] = types.String(x)
			}
		case bool:
			ctx[types.String(k)] = types.Boolean(x)
		case []any:
			items := make([]types.Value, 0, len(x))
			for _, s := range x {
				items = append(items, types.String(s.(string)))
			}
			ctx[types.String(k)] = types.NewSet(items...)
		default:
			t.Fatalf("fact %s has unsupported type %T", k, val)
		}
	}

	pattern := r.Agent.Pattern
	if pattern == "" {
		pattern = "interactive"
	}
	principal := types.NewEntityUID("Privometry::Agent", "session")
	entities := types.EntityMap{
		principal: {UID: principal, Attributes: types.NewRecord(types.RecordMap{
			"product": types.String(r.Agent.Product),
			"version": types.String(r.Agent.Version),
			"pattern": types.String(pattern),
		})},
	}
	var resource types.EntityUID
	switch {
	case r.Repo != "" && !r.Machine:
		resource = types.NewEntityUID("Privometry::Repo", types.String(r.Repo))
		entities[resource] = types.Entity{UID: resource, Attributes: types.NewRecord(types.RecordMap{"remote": types.String(r.Repo)})}
	case r.Machine && r.Repo == "":
		resource = types.NewEntityUID("Privometry::Machine", "local")
		entities[resource] = types.Entity{UID: resource}
	default:
		t.Fatal("request needs exactly one of repo or machine")
	}
	return entities, cedar.Request{
		Principal: principal,
		Action:    types.NewEntityUID("Privometry::Action", types.String(r.Action)),
		Resource:  resource,
		Context:   types.NewRecord(ctx),
	}
}

func loadPolicies(t *testing.T, path string) *cedar.PolicySet {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := cedar.NewPolicySetFromBytes(filepath.Base(path), raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return ps
}

func sameIDs(got, want []string) bool {
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	return slices.Equal(g, w)
}
