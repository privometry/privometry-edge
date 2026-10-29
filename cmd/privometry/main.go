// Command privometry is the Privometry CLI: scan, guard, daemon, timeline, policy,
// doctor, and signing up with an organization (login, console).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/scanner/posture"
	"github.com/privometry/privometry-edge/internal/scanner/report"
)

const usage = `Usage: privometry <command> [flags]

Commands:
  scan         Find coding agents, MCP servers, hooks and risky settings
  guard        Install, remove or check Privometry's hook in each coding agent
  daemon       Run privometryd in the background at login, or check on it
  timeline     Show what agents did and what Privometry decided
  policy       Test rule packs and policies, or explain a decision
  doctor       Check that Privometry is protecting this machine
  update       Install the latest signed release
  definitions  Show or update the signed adapter definitions and detector packs
  memory       Show the kept versions of agents' memory files, or restore one
  packs        Install, list or remove community rule and detector packs; sign your own
  trust        Trust a publisher's key to sign community packs
  mcp          Run local MCP servers through Privometry's shim
  login        Sign this machine up with your organization and enroll it
  console      Open the Privometry console in your browser, signed in
  enroll       Enroll this device with a token from an admin or your MDM
  device       Show this device's enrollment, or renew its certificate
  bundle       Show or fetch the organization's signed policy bundle
  version      Print the version

Run "privometry scan -h" for scan flags.
`

// Exit codes: 0 success, 1 findings at or above --fail-on, 2 usage or runtime error.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "policy":
		return policyCmd(args[1:], stdout, stderr)
	case "guard":
		return guardCmd(args[1:], stdout, stderr)
	case "daemon":
		return daemonCmd(args[1:], stdout, stderr)
	case "timeline":
		return timelineCmd(args[1:], stdout, stderr)
	case "doctor":
		return doctorCmd(args[1:], stdout, stderr)
	case "update":
		return updateCmd(args[1:], stdout, stderr)
	case "definitions":
		return definitionsCmd(args[1:], stdout, stderr)
	case "packs":
		return packsCmd(args[1:], stdout, stderr)
	case "memory":
		return memoryCmd(args[1:], stdout, stderr)
	case "trust":
		return trustCmd(args[1:], stdout, stderr)
	case "mcp":
		return mcpCmd(args[1:], stdout, stderr)
	case "login":
		return loginCmd(args[1:], stdout, stderr)
	case "console":
		return consoleCmd(args[1:], stdout, stderr)
	case "enroll":
		return enrollCmd(args[1:], stdout, stderr)
	case "device":
		return deviceCmd(args[1:], stdout, stderr)
	case "bundle":
		return bundleCmd(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, buildinfo.String("privometry"))
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "privometry: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "table", "output format: table, json or sarif")
	repo := fs.String("repo", "", "repo to scan for project config (default: the git repo containing the current directory)")
	noRepo := fs.Bool("no-repo", false, "do not scan any repo")
	noMachine := fs.Bool("no-machine", false, "skip user and managed config and installed agents (for CI)")
	failOn := fs.String("fail-on", "", "exit 1 if a finding is at least this severity: low, medium, high or critical")
	out := fs.String("output", "", "write the report to this file instead of stdout")
	changed := fs.String("changed", "", "file listing the repo files a merge or pull request changes (git diff --name-status output, or one path per line; - for stdin): flag changed agent files and scan every changed file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *failOn != "" && posture.Rank(contract.Risk(*failOn)) == 0 {
		fmt.Fprintf(stderr, "privometry scan: --fail-on must be low, medium, high or critical\n")
		return 2
	}

	env, err := platform.CurrentEnv()
	if err != nil {
		return fail(stderr, err)
	}
	opts := discover.Options{Env: env, Machine: !*noMachine}
	if !*noRepo {
		root := *repo
		if root == "" {
			cwd, _ := os.Getwd()
			root = platform.GitRoot(cwd)
		}
		if root != "" {
			if opts.RepoRoot, err = filepath.Abs(root); err != nil {
				return fail(stderr, err)
			}
			if info, err := os.Stat(opts.RepoRoot); err != nil || !info.IsDir() {
				return fail(stderr, fmt.Errorf("--repo %s is not a directory", root))
			}
		}
	}
	if !opts.Machine && opts.RepoRoot == "" {
		return fail(stderr, errors.New("nothing to scan: --no-machine needs a repo"))
	}

	sopts := scanner.Options{Options: opts}
	if *changed != "" {
		if opts.RepoRoot == "" {
			return fail(stderr, errors.New("--changed needs a repo"))
		}
		var r io.Reader = os.Stdin
		if *changed != "-" {
			f, err := os.Open(*changed)
			if err != nil {
				return fail(stderr, err)
			}
			defer f.Close()
			r = f
		}
		if sopts.Changed, err = scanner.ParseChanges(r); err != nil {
			return fail(stderr, fmt.Errorf("--changed: %w", err))
		}
	}
	reg, err := loadAdapters(env)
	if err != nil {
		return fail(stderr, err)
	}
	if sopts.Detectors, err = loadDetectors(env); err != nil {
		return fail(stderr, err)
	}
	// Allowlists from the policies that cover what is scanned: the user's
	// for a machine scan, the repo's for a repo scan.
	home := ""
	if opts.Machine {
		home = env.Home
	}
	sources, errs := policy.LocalSources(home, opts.RepoRoot)
	for _, err := range errs {
		fmt.Fprintln(stderr, "privometry scan:", err)
	}
	sopts.Allowlist = policy.Allowlist(sources)
	res, err := scanner.Scan(reg, sopts)
	if err != nil {
		return fail(stderr, err)
	}

	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fail(stderr, err)
		}
		defer f.Close()
		w = f
	}
	if err := report.Write(w, *format, res); err != nil {
		return fail(stderr, err)
	}

	if *failOn != "" {
		threshold := posture.Rank(contract.Risk(*failOn))
		for _, f := range res.Findings {
			if posture.Rank(f.Severity) >= threshold {
				return 1
			}
		}
		for _, f := range res.ContentFindings {
			if posture.Rank(f.Severity) >= threshold {
				return 1
			}
		}
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "privometry:", err)
	return 2
}
