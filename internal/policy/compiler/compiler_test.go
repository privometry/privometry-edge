package compiler_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/internal/policy/engine"
	"github.com/privometry/privometry-oss/specs"
)

const specsDir = "../../../specs"

func loadPolicy(t *testing.T, path string) compiler.Policy {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := specs.Validate("policy/v1/policy.schema.json", path, raw); err != nil {
		t.Fatal(err)
	}
	var p compiler.Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return p
}

func compile(t *testing.T, p compiler.Policy, layer string) compiler.Output {
	t.Helper()
	out, err := compiler.Compile(p.Rules, compiler.Options{Qualifier: p.Name, Layer: layer, DefaultMode: p.Defaults.Mode})
	if err != nil {
		t.Fatalf("%s: %v", p.Name, err)
	}
	return out
}

// TestCompiledOutputTypeChecks compiles every valid policy example and checks
// the result against privometry.cedarschema.
func TestCompiledOutputTypeChecks(t *testing.T) {
	var s schema.Schema
	if err := s.UnmarshalCedar(specs.CedarSchema); err != nil {
		t.Fatal(err)
	}
	res, err := s.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	v := validate.New(res, validate.WithStrict())
	files, _ := filepath.Glob(filepath.Join(specsDir, "policy/v1/examples/valid/*.yaml"))
	for _, f := range files {
		out := compile(t, loadPolicy(t, f), "org")
		for _, text := range []string{out.Enforce, out.Monitor} {
			ps, err := cedar.NewPolicySetFromBytes(filepath.Base(f), []byte(text))
			if err != nil {
				t.Fatalf("%s: compiled Cedar does not parse: %v\n%s", f, err, text)
			}
			for id, p := range ps.All() {
				if err := v.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
					t.Errorf("%s %s: %v", f, p.Annotations()["id"], err)
				}
			}
		}
	}
}

// TestConformanceVectors runs the shared verdict vectors against the compiler's
// own output for the YAML the hand-written goldens were derived from.
func TestConformanceVectors(t *testing.T) {
	cases := map[string]string{
		"acme-default.yaml":     "org",
		"monitor-rollout.yaml":  "repo",
		"content-scanning.yaml": "org",
	}
	for name, layer := range cases {
		p := loadPolicy(t, filepath.Join(specsDir, "policy/v1/examples/valid", name))
		out := compile(t, p, layer)
		vf := loadVectors(t, filepath.Join(specsDir, "conformance/policy-verdicts", name))
		eng, err := engine.New(out.Enforce, out.Monitor, vf.Unmatched)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range vf.Tests {
			t.Run(name+"/"+tc.Name, func(t *testing.T) {
				d, err := eng.Decide(tc.request())
				if err != nil {
					t.Fatal(err)
				}
				if d.Verdict != tc.Expect.Verdict || !equal(d.RuleIDs, tc.Expect.RuleIDs) {
					t.Errorf("got %s %v, want %s %v", d.Verdict, d.RuleIDs, tc.Expect.Verdict, tc.Expect.RuleIDs)
				}
				var would string
				var wouldIDs []string
				if d.Would != nil {
					would, wouldIDs = d.Would.Verdict, d.Would.RuleIDs
				}
				if would != tc.Expect.WouldVerdict || !equal(wouldIDs, tc.Expect.WouldRuleIDs) {
					t.Errorf("monitor: got %q %v, want %q %v", would, wouldIDs, tc.Expect.WouldVerdict, tc.Expect.WouldRuleIDs)
				}
			})
		}
	}
}

func TestExpressions(t *testing.T) {
	yes := true
	rules := []compiler.Rule{{
		ID:      "r",
		Verdict: "deny",
		Message: `Say "no"`,
		When: &compiler.Conditions{
			Action:             compiler.List{"shell_exec", "file_delete"},
			Subcommand:         compiler.List{"push * main"},
			Program:            compiler.List{"git", "git-*"},
			Repo:               compiler.List{"github.com/acme/*"},
			UntrustedInputSeen: &yes,
			RiskAtLeast:        "high",
		},
		Unless: &compiler.Conditions{Action: compiler.List{"file_delete"}, PathClass: compiler.List{"temp"}},
	}}
	out, err := compiler.Compile(rules, compiler.Options{Qualifier: "p", Layer: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`forbid (principal, action in [Privometry::Action::"shell_exec", Privometry::Action::"file_delete"], resource)`,
		`(context.subcommand like "push * main" || context.subcommand like "push * main *")`,
		`(context.program == "git" || context.program like "git-*")`,
		`(resource is Privometry::Repo && resource.remote like "github.com/acme/*")`,
		`context.untrusted_input_seen`,
		`context.risk >= 3`,
		`unless { action == Privometry::Action::"file_delete" && context.path_class == "temp" }`,
	} {
		if !strings.Contains(out.Enforce, want) {
			t.Errorf("missing %s in:\n%s", want, out.Enforce)
		}
	}
	if _, err := compiler.Compile(append(rules, rules[0]), compiler.Options{}); err == nil {
		t.Error("duplicate rule IDs should fail")
	}
}

type vectorFile struct {
	Unmatched string   `yaml:"unmatched"`
	Tests     []vector `yaml:"tests"`
}

type vector struct {
	Name    string `yaml:"name"`
	Request struct {
		Agent struct {
			Product string `yaml:"product"`
		} `yaml:"agent"`
		Repo   string `yaml:"repo"`
		Action string `yaml:"action"`
		Facts  struct {
			Intent             []string `yaml:"intent"`
			Category           []string `yaml:"category"`
			Risk               string   `yaml:"risk"`
			Program            string   `yaml:"program"`
			Subcommand         string   `yaml:"subcommand"`
			Flags              []string `yaml:"flags"`
			PathClass          string   `yaml:"path_class"`
			TargetPath         string   `yaml:"target_path"`
			Host               string   `yaml:"host"`
			UntrustedInputSeen bool     `yaml:"untrusted_input_seen"`
			SecretDetected     []string `yaml:"secret_detected"`
			InjectionDetected  string   `yaml:"injection_detected"`
			InjectionSeen      bool     `yaml:"injection_seen"`
			HiddenContent      bool     `yaml:"hidden_content"`
			TargetClass        string   `yaml:"target_class"`
		} `yaml:"facts"`
	} `yaml:"request"`
	Expect struct {
		Verdict      string   `yaml:"verdict"`
		RuleIDs      []string `yaml:"rule_ids"`
		WouldVerdict string   `yaml:"would_verdict"`
		WouldRuleIDs []string `yaml:"would_rule_ids"`
	} `yaml:"expect"`
}

func (v vector) request() engine.Request {
	f := v.Request.Facts
	return engine.Request{
		Agent:  engine.Agent{Product: v.Request.Agent.Product, Pattern: "interactive"},
		Repo:   v.Request.Repo,
		Action: v.Request.Action,
		Facts: engine.Facts{
			Intent: f.Intent, Category: f.Category, Risk: f.Risk, Program: f.Program,
			Subcommand: f.Subcommand, Flags: f.Flags, PathClass: f.PathClass,
			TargetPath: f.TargetPath, Host: f.Host, UntrustedInputSeen: f.UntrustedInputSeen,
			SecretTypes: f.SecretDetected, Injection: f.InjectionDetected, InjectionSeen: f.InjectionSeen,
			HiddenContent: f.HiddenContent, TargetClass: f.TargetClass,
		},
	}
}

func loadVectors(t *testing.T, path string) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := yaml.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	return vf
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCompileVectorsAreCurrent keeps specs/conformance/policy-compile in step
// with this compiler: the Java compiler is held to those files byte for byte.
// Regenerate them with go run ./scripts/gen-conformance.
func TestCompileVectorsAreCurrent(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(specsDir, "policy/v1/examples/valid/*.yaml"))
	if len(files) == 0 {
		t.Fatal("no policy examples")
	}
	for _, f := range files {
		out := compile(t, loadPolicy(t, f), "org")
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		for file, want := range map[string]string{name + ".cedar": out.Enforce, name + ".monitor.cedar": out.Monitor} {
			got, err := os.ReadFile(filepath.Join(specsDir, "conformance/policy-compile", file))
			if err != nil || string(got) != want {
				t.Errorf("conformance/policy-compile/%s is stale (%v); run go run ./scripts/gen-conformance", file, err)
			}
		}
	}
}
