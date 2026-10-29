package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/engine"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/policy/merge"
	"github.com/privometry/privometry-edge/internal/policy/packtest"
)

const policyUsage = `Usage: privometry policy test [flags] [PATH...]

Test rule packs and policy files:
  PATH is a rule pack folder (with pack.yaml) or a policy file. A policy file is
  merged with the shipped packs and tested against tests/*.test.yaml next to it.
  With no PATH, the repo policy (.privometry/policy.yaml) and ~/.privometry/policy.yaml
  are tested.

Explain one action under the current policies:
  privometry policy test --command "rm -rf ~/old"
  privometry policy test --read .env
  privometry policy test --fetch https://webhook.site/x --untrusted

Flags:
`

func policyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprint(stderr, policyUsage)
		return 2
	}
	return policyTest(args[1:], stdout, stderr)
}

func policyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, policyUsage); fs.PrintDefaults() }
	tests := fs.String("tests", "", "tests folder for a policy file (default: tests/ next to it)")
	layer := fs.String("layer", merge.Repo, "layer to test a policy file as: user, repo or org")
	command := fs.String("command", "", "explain a shell command")
	read := fs.String("read", "", "explain reading a file")
	write := fs.String("write", "", "explain writing a file")
	fetch := fs.String("fetch", "", "explain fetching a URL")
	untrusted := fs.Bool("untrusted", false, "explain as if the session had read untrusted content")
	agent := fs.String("agent", "claude_code", "agent product to explain for")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *layer != merge.User && *layer != merge.Repo && *layer != merge.Org {
		fmt.Fprintln(stderr, "privometry policy test: --layer must be user, repo or org")
		return 2
	}

	var action *intent.Action
	switch {
	case *command != "":
		action = &intent.Action{Kind: "shell_exec", Command: *command}
	case *read != "":
		action = &intent.Action{Kind: "file_read", Path: *read}
	case *write != "":
		action = &intent.Action{Kind: "file_write", Path: *write}
	case *fetch != "":
		action = &intent.Action{Kind: "network_fetch", URL: *fetch}
	}
	if action != nil {
		return explain(*action, fs.Args(), *layer, *untrusted, *agent, stdout, stderr)
	}
	return runPolicyTests(fs.Args(), *layer, *tests, stdout, stderr)
}

func runPolicyTests(paths []string, layer, testsDir string, stdout, stderr io.Writer) int {
	env, err := platform.CurrentEnv()
	if err != nil {
		return fail(stderr, err)
	}
	packs, err := availablePacks(env, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	if len(paths) == 0 {
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		for _, p := range []string{filepath.Join(platform.GitRoot(cwd), policy.RepoPolicyPath), filepath.Join(home, policy.UserPolicyPath)} {
			if _, err := os.Stat(p); err == nil && filepath.IsAbs(p) {
				paths = append(paths, p)
			}
		}
		if len(paths) == 0 {
			fmt.Fprintln(stdout, "No policy files found (looked for .privometry/policy.yaml in this repo and ~/.privometry/policy.yaml).")
			return 0
		}
	}
	failed := false
	for _, p := range paths {
		var r *packtest.Report
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			r = packtest.Pack(p)
		} else {
			src, err := policy.LoadFile(p, layer)
			if err != nil {
				fmt.Fprintf(stdout, "FAIL %s\n  %v\n", p, err)
				failed = true
				continue
			}
			dir := testsDir
			if dir == "" {
				dir = filepath.Join(filepath.Dir(p), "tests")
			}
			r = packtest.Policy(src, packs, dir)
			r.Problems = append(r.Problems, allowlistProblems(src)...)
			if n := len(src.Policy.Allowlist); n > 0 {
				r.Notes = append(r.Notes, fmt.Sprintf("%d content allowlist entries", n))
			}
		}
		status := "PASS"
		if !r.OK() {
			status, failed = "FAIL", true
		}
		fmt.Fprintf(stdout, "%s %s %s: %d rules, %d tests\n", status, r.Kind, r.Name, r.Rules, r.Tests)
		for _, l := range r.Problems {
			fmt.Fprintf(stdout, "  problem: %s\n", l)
		}
		for _, l := range r.Failures {
			fmt.Fprintf(stdout, "  failed: %s\n", l)
		}
		for _, l := range r.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", l)
		}
	}
	if failed {
		return 1
	}
	return 0
}

// allowlistProblems names allowlist entries that cover no detector in the
// packs in use, usually a misspelled detector or pack ID.
func allowlistProblems(src merge.Source) []string {
	env, err := platform.CurrentEnv()
	if err != nil {
		return []string{err.Error()}
	}
	detectors, err := loadDetectors(env)
	if err != nil {
		return []string{err.Error()}
	}
	known := map[string]bool{}
	for _, p := range detectors {
		known[p.Manifest.ID+":*"] = true
		for _, d := range p.Detectors {
			known[d.QID] = true
		}
	}
	var out []string
	for i, e := range src.Policy.Allowlist {
		for _, id := range e.Detectors {
			if !known[id] {
				out = append(out, fmt.Sprintf("allowlist entry %d: no detector %s in the detector packs in use", i+1, id))
			}
		}
	}
	return out
}

// explain decides one action with the shipped packs, the local policies and
// any extra policy files, and prints every request and the decision.
func explain(a intent.Action, extra []string, layer string, untrusted bool, agent string, stdout, stderr io.Writer) int {
	env, err := platform.CurrentEnv()
	if err != nil {
		return fail(stderr, err)
	}
	cwd, _ := os.Getwd()
	repoRoot := platform.GitRoot(cwd)
	packs, err := availablePacks(env, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	sources, errs := policy.Sources(env, repoRoot, time.Now())
	for _, p := range extra {
		src, err := policy.LoadFile(p, layer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sources = append(sources, src)
	}
	res, err := merge.Merge(merge.Input{Packs: packs, Policies: sources})
	if err != nil {
		return fail(stderr, err)
	}
	p, err := policy.New(res)
	if err != nil {
		return fail(stderr, err)
	}
	ctx := intent.Context{Cwd: cwd, Home: env.Home, RepoRoot: intent.WorkspaceRoot(cwd, env.Home, repoRoot), TempDirs: []string{os.TempDir()}}
	d, steps, err := p.Explain(policy.Input{Agent: engine.Agent{Product: agent, Pattern: "interactive"},
		Repo: platform.GitRemote(repoRoot), Action: a, Context: ctx, UntrustedInputSeen: untrusted})
	if err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, "Verdict: %s (%s)\n", d.Verdict, strings.ReplaceAll(d.Source, "_", "-"))
	if len(d.RuleIDs) > 0 {
		fmt.Fprintf(stdout, "Rules:   %s\n", strings.Join(d.RuleIDs, ", "))
	}
	if d.Message != "" {
		fmt.Fprintf(stdout, "Message: %s\n", d.Message)
	}
	if d.WouldVerdict != "" {
		fmt.Fprintf(stdout, "Monitor: would %s (%s)\n", d.WouldVerdict, strings.Join(d.WouldRuleIDs, ", "))
	}
	fmt.Fprintf(stdout, "\nRequests (%d):\n", len(steps))
	for i, s := range steps {
		f := s.Request.Facts
		var facts []string
		add := func(k, v string) {
			if v != "" {
				facts = append(facts, k+"="+v)
			}
		}
		add("program", f.Program)
		add("subcommand", f.Subcommand)
		add("flags", strings.Join(f.Flags, ","))
		add("intent", strings.Join(f.Intent, ","))
		add("path", f.TargetPath)
		add("class", f.PathClass)
		add("host", f.Host)
		add("mcp", strings.Trim(f.MCPServer+"/"+f.MCPTool, "/"))
		verdict := s.Verdict
		if len(s.RuleIDs) > 0 {
			verdict += " by " + strings.Join(s.RuleIDs, ", ")
		}
		fmt.Fprintf(stdout, "  %d. %s: %s\n     risk %s: %s\n     %s\n", i+1, s.Request.Action, verdict, f.Risk, s.Request.Reason, strings.Join(facts, " "))
	}

	fmt.Fprintf(stdout, "\nPolicies: %s", strings.Join(res.Packs, ", "))
	for _, s := range sources {
		fmt.Fprintf(stdout, ", %s policy %s", s.Layer, s.Policy.Name)
	}
	fmt.Fprintln(stdout)
	for _, e := range errs {
		fmt.Fprintf(stdout, "Warning: %v\n", e)
	}
	for _, diag := range res.Diagnostics {
		fmt.Fprintf(stdout, "Note: %s policy %s: %s\n", diag.Layer, diag.Source, diag.Message)
	}
	return 0
}
