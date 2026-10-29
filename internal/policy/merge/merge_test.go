package merge_test

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/policy/compiler"
	"github.com/privometry/privometry-edge/internal/policy/engine"
	"github.com/privometry/privometry-edge/internal/policy/merge"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/rulepacks"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const forcePush = "privometry/core-catastrophic:git-force-push"

func policy(t *testing.T, layer, src string) merge.Source {
	t.Helper()
	var p compiler.Policy
	if err := yaml.Unmarshal([]byte("schema: privometry.policy/v1\n"+src), &p); err != nil {
		t.Fatal(err)
	}
	return merge.Source{Layer: layer, Policy: p}
}

func run(t *testing.T, sources ...merge.Source) *merge.Result {
	t.Helper()
	packs, err := rulepack.Load(rulepacks.FS)
	if err != nil {
		t.Fatal(err)
	}
	res, err := merge.Merge(merge.Input{Packs: packs, Policies: sources, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func verdictOf(t *testing.T, res *merge.Result, id string) string {
	t.Helper()
	r, ok := res.Rules[id]
	if !ok {
		return "absent"
	}
	return string(r.Verdict)
}

func hasDiag(res *merge.Result, substr string) bool {
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

// decide runs a force push to a feature branch through the merged policy.
func decide(t *testing.T, res *merge.Result, f engine.Facts, action string) engine.Decision {
	t.Helper()
	eng, err := engine.New(res.Enforce, res.Monitor, res.Unmatched)
	if err != nil {
		t.Fatalf("%v\n%s", err, res.Enforce)
	}
	d, err := eng.Decide(engine.Request{Agent: engine.Agent{Product: "claude_code", Pattern: "interactive"}, Action: action, Facts: f})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var push = engine.Facts{Program: "git", Subcommand: "push origin feature", Flags: []string{"--force"}, Intent: []string{"force_push"}, Risk: "critical"}

func TestPacksAlone(t *testing.T) {
	res := run(t)
	if verdictOf(t, res, forcePush) != "ask" || res.Unmatched != "auto" || len(res.Diagnostics) != 0 {
		t.Fatalf("verdict %s unmatched %s diags %v", verdictOf(t, res, forcePush), res.Unmatched, res.Diagnostics)
	}
	if res.Rules[forcePush].FailMode != contract.FailModeClosed {
		t.Errorf("pack default fail mode not applied: %s", res.Rules[forcePush].FailMode)
	}
	if d := decide(t, res, push, "shell_exec"); d.Verdict != "ask" {
		t.Errorf("force push: %s", d.Verdict)
	}
}

func TestOverrides(t *testing.T) {
	cases := []struct {
		name    string
		sources []merge.Source
		want    string
		diag    string
	}{
		{"repo tightens a built-in rule", []merge.Source{policy(t, "repo", "name: web\noverrides:\n  "+forcePush+": deny\n")}, "deny", ""},
		{"user loosens a built-in rule", []merge.Source{policy(t, "user", "name: me\noverrides:\n  "+forcePush+": allow\n")}, "allow", ""},
		{"repo tighten beats user loosen", []merge.Source{
			policy(t, "repo", "name: web\noverrides:\n  "+forcePush+": deny\n"),
			policy(t, "user", "name: me\noverrides:\n  "+forcePush+": allow\n")}, "deny", ""},
		{"org overrides everyone", []merge.Source{
			policy(t, "user", "name: me\noverrides:\n  "+forcePush+": deny\n"),
			policy(t, "org", "name: acme\noverrides:\n  "+forcePush+": allow\n")}, "allow", ""},
		{"unknown rule", []merge.Source{policy(t, "repo", "name: web\noverrides:\n  privometry/core-catastrophic:nope: deny\n")}, "ask", "unknown rule"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, tc.sources...)
			if got := verdictOf(t, res, forcePush); got != tc.want {
				t.Errorf("verdict %s, want %s (diags %v)", got, tc.want, res.Diagnostics)
			}
			if tc.diag != "" && !hasDiag(res, tc.diag) {
				t.Errorf("missing diagnostic %q in %v", tc.diag, res.Diagnostics)
			}
			if d := decide(t, res, push, "shell_exec"); tc.want != "absent" && d.Verdict != tc.want {
				t.Errorf("engine verdict %s, want %s", d.Verdict, tc.want)
			}
		})
	}
}

const orgPolicy = `name: acme
rules:
  - id: no-prod-kubectl
    category: catastrophic
    when: { action: shell_exec, program: kubectl, subcommand: "delete *" }
    verdict: deny
    message: Not from an agent.
    locked: true
  - id: ask-docker
    when: { action: shell_exec, program: docker }
    verdict: ask
    message: Confirm docker.
  - id: ask-helm
    when: { action: shell_exec, program: helm }
    verdict: ask
    message: Confirm helm.
    overridable: true
`

func TestOrgRules(t *testing.T) {
	org := policy(t, "org", orgPolicy)
	cases := []struct {
		name, repo, rule, want, diag string
	}{
		{"locked rule cannot change", "overrides:\n  acme:no-prod-kubectl: allow\n", "acme:no-prod-kubectl", "deny", "locked"},
		{"locked rule cannot be tightened either", "overrides:\n  acme:no-prod-kubectl:\n    message: other\n", "acme:no-prod-kubectl", "deny", "locked"},
		{"non-overridable rule cannot be loosened", "overrides:\n  acme:ask-docker: allow\n", "acme:ask-docker", "ask", "cannot loosen"},
		{"non-overridable rule can be tightened", "overrides:\n  acme:ask-docker: deny\n", "acme:ask-docker", "deny", ""},
		{"overridable rule can be loosened", "overrides:\n  acme:ask-helm: allow\n", "acme:ask-helm", "allow", ""},
		{"monitor counts as loosening", "overrides:\n  acme:ask-docker:\n    mode: monitor\n", "acme:ask-docker", "ask", "monitor mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, org, policy(t, "repo", "name: web\n"+tc.repo))
			if got := verdictOf(t, res, tc.rule); got != tc.want {
				t.Errorf("verdict %s, want %s (diags %v)", got, tc.want, res.Diagnostics)
			}
			if tc.diag != "" && !hasDiag(res, tc.diag) {
				t.Errorf("missing diagnostic %q in %v", tc.diag, res.Diagnostics)
			}
		})
	}

	res := run(t, policy(t, "user", "name: me\nrules:\n  - id: r\n    when: { action: shell_exec, program: x }\n    verdict: allow\n    locked: true\n"))
	if !hasDiag(res, "apply only to organization rules") || res.Rules["me:r"].Locked != nil {
		t.Errorf("locked outside the org must be ignored: %v", res.Diagnostics)
	}
}

func TestExceptions(t *testing.T) {
	const home = "privometry/core-catastrophic:home-recursive-delete"
	rmScratch := engine.Facts{Program: "rm", Intent: []string{"recursive_delete"}, PathClass: "home", TargetPath: "/home/dev/scratch/x", Risk: "critical"}
	rmDocs := rmScratch
	rmDocs.TargetPath = "/home/dev/Documents"

	exc := func(layer, extra string) merge.Source {
		return policy(t, layer, "name: p\nexceptions:\n  - rule: "+home+"\n    reason: scratch space\n"+extra)
	}
	res := run(t, exc("user", "    target_path: \"/home/dev/scratch/*\"\n    expires_at: 2026-12-31T00:00:00Z\n"))
	if d := decide(t, res, rmScratch, "shell_exec"); d.Verdict != "ask" || len(d.RuleIDs) != 0 {
		t.Errorf("excepted path should fall to unmatched (critical risk asks): %+v", d)
	}
	if d := decide(t, res, rmDocs, "shell_exec"); d.Verdict != "deny" {
		t.Errorf("exception must not cover other paths: %+v", d)
	}

	res = run(t, exc("user", "    target_path: \"/home/dev/scratch/*\"\n    expires_at: 2026-01-01T00:00:00Z\n"))
	if d := decide(t, res, rmScratch, "shell_exec"); d.Verdict != "deny" || !hasDiag(res, "expired") {
		t.Errorf("expired exception must be ignored: %+v %v", d, res.Diagnostics)
	}

	res = run(t, exc("org", "    target_path: \"/home/dev/scratch/*\"\n    expires_at: 2026-12-31T00:00:00Z\n"))
	if !hasDiag(res, "no approved_by") {
		t.Errorf("org exception without approved_by: %v", res.Diagnostics)
	}

	res = run(t, exc("repo", "    expires_at: 2026-12-31T00:00:00Z\n"))
	if verdictOf(t, res, home) != "absent" {
		t.Errorf("an exception without conditions disables the rule")
	}

	org := policy(t, "org", orgPolicy)
	res = run(t, org, policy(t, "repo", "name: web\nexceptions:\n  - rule: acme:ask-docker\n    reason: x\n    expires_at: 2026-12-31T00:00:00Z\n"))
	if verdictOf(t, res, "acme:ask-docker") != "ask" || !hasDiag(res, "cannot loosen") {
		t.Errorf("repo exception on a non-overridable org rule: %v", res.Diagnostics)
	}

	in := merge.Input{Now: now, Policies: []merge.Source{exc("user", "    target_path: \"/x\"\n    expires_at: 2026-11-30T00:00:00Z\n")}}
	if got := merge.NextExpiry(in); !got.Equal(time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("NextExpiry = %v", got)
	}
}

func TestDefaultsAndPacks(t *testing.T) {
	res := run(t,
		policy(t, "user", "name: me\ndefaults:\n  unmatched: allow\n  fail_modes:\n    catastrophic: open\n"),
		policy(t, "repo", "name: web\nextends: [privometry/core-catastrophic@^2, acme/missing@^1]\ndefaults:\n  unmatched: ask\n"))
	if res.Unmatched != "ask" {
		t.Errorf("strictest unmatched should win: %s", res.Unmatched)
	}
	if res.FailModes["catastrophic"] != contract.FailModeClosed || !hasDiag(res, "cannot be loosened") {
		t.Errorf("user cannot loosen a fail mode: %s %v", res.FailModes["catastrophic"], res.Diagnostics)
	}
	if !hasDiag(res, "does not satisfy ^2") || !hasDiag(res, "acme/missing is not installed") {
		t.Errorf("pack diagnostics: %v", res.Diagnostics)
	}

	res = run(t, policy(t, "org", "name: acme\ndefaults:\n  fail_modes:\n    catastrophic: ask\n"))
	if res.FailModes["catastrophic"] != contract.FailModeAsk {
		t.Errorf("org may set any fail mode: %s", res.FailModes["catastrophic"])
	}

	res = run(t, policy(t, "user", "name: me\noverrides:\n  "+forcePush+":\n    mode: monitor\n"))
	annotation := `@id("` + forcePush + `")`
	if !strings.Contains(res.Monitor, annotation) || strings.Contains(res.Enforce, annotation) {
		t.Errorf("monitor override should move the rule to the monitor set")
	}
	if d := decide(t, res, push, "shell_exec"); d.Would == nil || d.Would.Verdict != "ask" {
		t.Errorf("monitored rule should record would_verdict: %+v", d)
	}
}
