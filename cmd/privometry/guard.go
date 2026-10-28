package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/daemon"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/ipc"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
)

const guardUsage = `Usage: privometry guard <install|uninstall|status> [flags]

  install     Register privometry-hook in each supported agent's user config
  uninstall   Remove Privometry's hook entries (other hooks are left alone)
  status      Show whether the hook is in place for each agent

Flags:
`

// guardEnv lets tests point guard at a fixture home.
var guardEnv = platform.CurrentEnv

func guardCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, guardUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("guard "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, guardUsage); fs.PrintDefaults() }
	agentFlag := fs.String("agent", "", "only this agent, for example claude_code (default: every detected agent)")
	dryRun := fs.Bool("dry-run", false, "show the change without writing it")
	hookPath := fs.String("hook", "", "path of privometry-hook (default: next to this privometry binary)")
	format := fs.String("format", "table", "status output: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if sub != "install" && sub != "uninstall" && sub != "status" {
		fmt.Fprint(stderr, guardUsage)
		return 2
	}

	env, err := guardEnv()
	if err != nil {
		return fail(stderr, err)
	}
	reg, err := loadAdapters(env)
	if err != nil {
		return fail(stderr, err)
	}
	hook, err := resolveHook(*hookPath)
	if err != nil && sub == "install" {
		return fail(stderr, err)
	}
	agents, versions, err := guardTargets(reg, env, *agentFlag)
	if err != nil {
		return fail(stderr, err)
	}

	if sub == "status" {
		type row struct {
			guard.Status
			LastCall string `json:"last_call,omitempty"`
		}
		last := map[string]time.Time{}
		running := false
		if st, err := queryStatus(env); err == nil {
			running = true
			for _, a := range st.Agents {
				last[a.Agent] = a.LastCall
			}
		}
		var all []row
		for _, a := range agents {
			r := row{Status: guard.Check(a, guard.Options{Env: env, HookCommand: hook})}
			switch t, ok := last[string(a.Agent)]; {
			case ok:
				r.LastCall = time.Since(t).Round(time.Second).String() + " ago"
			case r.State == "installed" && r.TrustRequired:
				r.LastCall = "no calls yet: " + strings.TrimSuffix(r.Detail, ".")
			case r.State == "installed" && running:
				r.LastCall = "no calls yet"
			}
			all = append(all, r)
		}
		if *format == "json" {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(all)
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tSTATE\tFAIL CLOSED\tLAST HOOK CALL\tCONFIG")
		for _, s := range all {
			fc := "no"
			if s.FailClosed {
				fc = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Agent, s.State, fc, orDash(s.LastCall), discover.Display(s.Path, env.Home, ""))
		}
		tw.Flush()
		fmt.Fprintln(stdout, "\nDaemon: "+daemonState(env))
		return 0
	}

	code := 0
	for _, a := range agents {
		opts := guard.Options{Env: env, HookCommand: hook, AgentVersion: versions[a.Agent]}
		var c *guard.Change
		if sub == "install" {
			c, err = guard.Install(a, opts)
		} else {
			c, err = guard.Uninstall(a, opts)
		}
		if errors.Is(err, guard.ErrUnsupported) {
			fmt.Fprintf(stdout, "%s: not supported yet; skipped\n", a.DisplayName)
			continue
		}
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", a.DisplayName, err)
			code = 1
			continue
		}
		path := discover.Display(c.Path, env.Home, "")
		switch {
		case !c.Changed():
			fmt.Fprintf(stdout, "%s: %s already up to date\n", a.DisplayName, path)
		case *dryRun:
			fmt.Fprintf(stdout, "%s: would change %s\n%s", a.DisplayName, path, guard.Diff(c.Before, c.After))
		default:
			if err := c.Apply(); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", a.DisplayName, err)
				code = 1
				continue
			}
			verb := "installed in"
			if sub == "uninstall" {
				verb = "removed from"
				if err := tellDaemon(env, daemon.Lifecycle{Event: "hook_removed", Agent: a.Agent}); err != nil {
					fmt.Fprintf(stderr, "%s: the daemon could not record the removal: %v\n", a.DisplayName, err)
				}
			}
			fmt.Fprintf(stdout, "%s: hook %s %s", a.DisplayName, verb, path)
			if sub == "install" && !c.FailClosed {
				if a.Hooks.FailClosedOption == nil {
					fmt.Fprint(stdout, " (this agent cannot fail closed: if privometry-hook crashes, the action proceeds)")
				} else {
					fmt.Fprint(stdout, " (without fail-closed; the agent version is unknown or too old)")
				}
			}
			fmt.Fprintln(stdout)
			if sub == "install" && c.TrustInstructions != "" {
				fmt.Fprintf(stdout, "  Next step: %s %s ignores new hooks until you approve them.\n", c.TrustInstructions, a.DisplayName)
			}
		}
		if c != nil {
			for _, w := range c.Warnings {
				fmt.Fprintf(stdout, "  Warning: %s\n", w)
			}
		}
	}
	if sub == "install" && !*dryRun {
		if state := daemonState(env); state != "running" {
			fmt.Fprintf(stdout, "\nThe Privometry daemon is %s. Until it runs, privometry-hook only applies fail modes (it still blocks catastrophic actions). Start it with: privometry daemon install\n", state)
		}
	}
	return code
}

// guardTargets returns the agents to act on, and detected versions.
func guardTargets(reg *registry.Registry, env platform.Env, only string) ([]registry.Adapter, map[contract.AgentProduct]string, error) {
	versions := map[contract.AgentProduct]string{}
	found, err := discover.Run(reg, discover.Options{Env: env, Machine: true})
	if err != nil {
		return nil, nil, err
	}
	installed := map[contract.AgentProduct]bool{}
	for _, a := range found {
		versions[a.Product] = a.Version
		installed[a.Product] = a.Installed
	}
	if only != "" {
		a, ok := reg.Get(contract.AgentProduct(only))
		if !ok {
			return nil, nil, fmt.Errorf("unknown agent %q", only)
		}
		return []registry.Adapter{a}, versions, nil
	}
	var out []registry.Adapter
	for _, a := range reg.All() {
		if installed[a.Agent] {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("no supported coding agents found; use --agent to choose one")
	}
	return out, versions, nil
}

// resolveHook finds privometry-hook: the flag, or next to this binary.
func resolveHook(flagPath string) (string, error) {
	p, err := sibling(flagPath, "privometry-hook")
	if err != nil {
		return "", fmt.Errorf("%w (use --hook)", err)
	}
	return p, nil
}

func daemonState(env platform.Env) string {
	addr, err := env.IPCAddress()
	if err != nil {
		return "not configured"
	}
	if _, err := ipc.Call(addr, ipc.Request{Op: "ping"}, 300*time.Millisecond); err != nil {
		return "not running"
	}
	return "running"
}

// tellDaemon reports what a person did with the CLI to a running daemon,
// which records it and waits up to five seconds to upload it. A daemon that is
// not running, or too old to know the operation, is not an error: the file
// watcher or device_stale reports the change later.
func tellDaemon(env platform.Env, q daemon.Lifecycle) error {
	addr, err := env.IPCAddress()
	if err != nil {
		return nil
	}
	body, _ := json.Marshal(q)
	resp, err := ipc.Call(addr, ipc.Request{Op: "lifecycle", Query: body}, 8*time.Second)
	if err != nil || resp.OK || strings.HasPrefix(resp.Error, "unknown op") {
		return nil
	}
	return errors.New(resp.Error)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
