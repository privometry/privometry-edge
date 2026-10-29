package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/daemon/service"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/platform"
)

const daemonUsage = `Usage: privometry daemon <install|uninstall|status|restart> [flags]

  install     Run privometryd in the background at login (launchd on macOS, systemd on Linux,
              a Task Scheduler logon task on Windows)
  uninstall   Stop privometryd and remove the service
  status      Show the service, the daemon and each agent's hook activity
  restart     Restart the service

Flags:
`

// Test hooks.
var (
	daemonEnv     = platform.CurrentEnv
	serviceRunner = func(name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).CombinedOutput()
		return string(out), err
	}
)

func daemonCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, daemonUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("daemon "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, daemonUsage); fs.PrintDefaults() }
	privometrydPath := fs.String("privometryd", "", "path of privometryd (default: next to this privometry binary)")
	dryRun := fs.Bool("dry-run", false, "show the service file and commands without changing anything")
	format := fs.String("format", "table", "status output: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	privometryd, err := sibling(*privometrydPath, "privometryd")
	if err != nil && sub == "install" {
		return fail(stderr, err)
	}
	opts := service.Options{Env: env, Privometryd: privometryd, Run: serviceRunner, UID: os.Getuid()}
	plan, err := service.For(opts)
	if err != nil {
		return fail(stderr, err)
	}
	display := func(p string) string { return strings.Replace(p, env.Home, "~", 1) }

	switch sub {
	case "install":
		if *dryRun {
			fmt.Fprintf(stdout, "Would write %s:\n\n%s\nThen run:\n", display(plan.Path), plan.Content)
			for _, c := range plan.Load {
				fmt.Fprintf(stdout, "  %s\n", strings.Join(c, " "))
			}
			if f := plan.Fallback; f != nil {
				fmt.Fprintf(stdout, "If Windows refuses the task, instead run:\n")
				for _, c := range f.Load {
					fmt.Fprintf(stdout, "  %s\n", strings.Join(c, " "))
				}
				fmt.Fprintf(stdout, "and start %s\n", strings.Join(f.Start, " "))
			}
			return 0
		}
		if err := service.Install(plan, opts); err != nil {
			return fail(stderr, err)
		}
		if plan.Note != "" {
			fmt.Fprintln(stdout, plan.Note)
		} else {
			fmt.Fprintf(stdout, "Installed %s\n", display(plan.Path))
		}
		if waitForDaemon(env, 5*time.Second) {
			fmt.Fprintln(stdout, "privometryd is running.")
			return 0
		}
		dir, _ := env.DataDir()
		fmt.Fprintf(stdout, "privometryd did not answer within 5 seconds; see %s\n", display(filepath.Join(dir, "privometryd.log")))
		return 1
	case "uninstall":
		if *dryRun {
			fmt.Fprintf(stdout, "Would run:\n")
			for _, c := range plan.Unload {
				fmt.Fprintf(stdout, "  %s\n", strings.Join(c, " "))
			}
			fmt.Fprintf(stdout, "and remove %s\n", display(plan.Path))
			return 0
		}
		if err := tellDaemon(env, daemon.Lifecycle{Event: "sensor_uninstalled"}); err != nil {
			fmt.Fprintf(stderr, "The daemon could not record the uninstall: %v\n", err)
		}
		if err := service.Uninstall(plan, opts); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "Removed %s; privometryd is stopped. Agent hooks now apply fail modes only (privometry guard uninstall removes them).\n", display(plan.Path))
		return 0
	case "restart":
		if err := service.Restart(opts); err != nil {
			return fail(stderr, err)
		}
		if waitForDaemon(env, 5*time.Second) {
			fmt.Fprintln(stdout, "privometryd restarted.")
			return 0
		}
		fmt.Fprintln(stdout, "privometryd did not answer after the restart.")
		return 1
	case "status":
		return daemonStatus(env, plan, opts, *format, display, stdout)
	}
	fmt.Fprint(stderr, daemonUsage)
	return 2
}

type daemonReport struct {
	Service service.Status `json:"service"`
	Daemon  *daemon.Status `json:"daemon,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func daemonStatus(env platform.Env, plan *service.Plan, opts service.Options, format string, display func(string) string, stdout io.Writer) int {
	r := daemonReport{Service: service.Check(plan, opts)}
	if st, err := queryStatus(env); err == nil {
		r.Daemon = st
	} else {
		r.Error = err.Error()
	}
	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return 0
	}
	svc := "not installed (run: privometry daemon install)"
	switch s := r.Service; {
	case s.Installed && s.Running:
		svc = fmt.Sprintf("running (pid %d)", s.PID)
	case s.Installed:
		svc = "installed, not running"
	}
	if r.Service.Installed && r.Service.RunKey {
		svc += "; started from the Run key, as Windows refused the logon task"
	}
	if r.Service.Installed && !r.Service.Current {
		svc += "; service file is out of date (run: privometry daemon install)"
	}
	fmt.Fprintf(stdout, "Service: %s\n", svc)
	if r.Daemon == nil {
		fmt.Fprintln(stdout, "Daemon:  not reachable; agent hooks apply fail modes only")
		return 0
	}
	d := r.Daemon
	fmt.Fprintf(stdout, "Daemon:  version %s, pid %d, up %s, data in %s\n", d.Version, d.PID,
		time.Since(d.StartedAt.Time).Round(time.Second), display(d.DataDir))
	if missing := missingOps(d.Ops); len(missing) > 0 {
		fmt.Fprintf(stdout, "         older than this CLI (no %s); run: privometry daemon restart\n", strings.Join(missing, ", "))
	}
	if len(d.Agents) == 0 {
		fmt.Fprintln(stdout, "No hook calls recorded yet.")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nAGENT\tLAST HOOK CALL\tDECISIONS")
	for _, a := range d.Agents {
		fmt.Fprintf(tw, "%s\t%s ago\t%d\n", a.Agent, time.Since(a.LastCall).Round(time.Second), a.Calls)
	}
	tw.Flush()
	return 0
}

// missingOps lists the operations this CLI uses that the daemon lacks.
func missingOps(have []string) []string {
	var out []string
	for _, op := range daemon.Ops {
		if !slices.Contains(have, op) {
			out = append(out, op)
		}
	}
	return out
}

// queryStatus asks the running daemon for its status.
func queryStatus(env platform.Env) (*daemon.Status, error) {
	addr, err := env.IPCAddress()
	if err != nil {
		return nil, err
	}
	resp, err := ipc.Call(addr, ipc.Request{Op: "status"}, time.Second)
	if err != nil {
		return nil, err
	}
	var st daemon.Status
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func waitForDaemon(env platform.Env, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if daemonState(env) == "running" {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// sibling finds a binary: the flag, or the named file next to this privometry.
func sibling(flagPath, name string) (string, error) {
	p := flagPath
	if p == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		p = filepath.Join(filepath.Dir(exe), name)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs) //nolint:gosec // the path is the user's own --binary flag or the CLI's sibling
	if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%s not found or not executable at %s (use --%s)", name, abs, strings.TrimSuffix(name, "-hook"))
	}
	return abs, nil
}
