package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/daemon"
	"github.com/privometry/privometry-oss/internal/daemon/service"
	"github.com/privometry/privometry-oss/internal/definitions"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/hookclient"
	"github.com/privometry/privometry-oss/internal/ipc"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/policy"
	"github.com/privometry/privometry-oss/internal/policy/merge"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
	"github.com/privometry/privometry-oss/internal/timeline"
)

const doctorUsage = `Usage: privometry doctor [flags]

Check that Privometry is protecting this machine: binaries, data folder, service,
daemon, a real hook decision, fail modes, each agent's hook, and policies.

  privometry doctor
  privometry doctor --bundle          also write a redacted diagnostic zip to share

Flags:
`

// Check is one doctor finding.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // ok, warn, fail or skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// doctorRun is what one doctor run found, plus what the bundle needs.
type doctorRun struct {
	env    platform.Env
	home   func(string) string
	checks []Check

	dataDir string
	plan    *service.Plan
	status  *daemon.Status
	guards  []guard.Status
	merged  *merge.Result
	repo    string
}

func (r *doctorRun) add(c Check) { r.checks = append(r.checks, c) }

func doctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, doctorUsage); fs.PrintDefaults() }
	format := fs.String("format", "table", "table or json")
	bundle := fs.Bool("bundle", false, "also write a redacted diagnostic zip")
	out := fs.String("output", "", "with --bundle, the zip to write (default: privometry-doctor-<time>.zip here)")
	noProbe := fs.Bool("no-probe", false, "skip the test hook call")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	r := diagnose(env, !*noProbe)

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r.checks)
	} else {
		printChecks(stdout, r.checks, useColor(stdout))
	}
	if *bundle {
		path := *out
		if path == "" {
			path = "privometry-doctor-" + time.Now().Format("20060102-150405") + ".zip"
		}
		if err := writeBundle(path, r); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "\nWrote %s. It has no full commands, and secrets are removed; see README.txt inside.\n", path)
	}
	for _, c := range r.checks {
		if c.Status == "fail" {
			return 1
		}
	}
	return 0
}

func diagnose(env platform.Env, probe bool) *doctorRun {
	r := &doctorRun{env: env, home: func(p string) string { return discover.Display(p, env.Home, "") }}
	r.checkBinaries()
	r.checkDataDir()
	r.checkService()
	r.checkDaemon()
	r.checkProbe(probe)
	r.checkFailModes()
	r.checkSpool()
	r.checkAgents()
	r.checkDefinitions()
	r.checkPolicy()
	r.checkAlerts()
	return r
}

var doctorBinaries = []string{"privometryd", "privometry-hook"}

func (r *doctorRun) checkBinaries() {
	c := Check{ID: "binaries", Title: "Binaries", Status: "ok"}
	var problems []string
	for _, name := range doctorBinaries {
		p, err := sibling("", name)
		if err != nil {
			problems = append(problems, name+" not found next to privometry")
			continue
		}
		v := binaryVersion(p)
		if v != buildinfo.Version {
			problems = append(problems, fmt.Sprintf("%s is version %q, privometry is %q", name, v, buildinfo.Version))
		}
	}
	self, _ := os.Executable()
	c.Detail = fmt.Sprintf("privometry %s in %s", buildinfo.Version, r.home(filepath.Dir(self)))
	if len(problems) > 0 {
		c.Status, c.Detail = "fail", strings.Join(problems, "; ")
		c.Fix = "Reinstall Privometry so privometry, privometryd and privometry-hook come from the same release."
	}
	r.add(c)
}

// binaryVersion runs "<binary> version" and returns the version word.
func binaryVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "unknown"
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return "unknown"
	}
	return f[1]
}

func (r *doctorRun) checkDataDir() {
	c := Check{ID: "data_dir", Title: "Data folder", Status: "ok"}
	dir, err := r.env.DataDir()
	if err != nil {
		c.Status, c.Detail = "fail", err.Error()
		r.add(c)
		return
	}
	r.dataDir = dir
	info, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		c.Status, c.Detail, c.Fix = "warn", r.home(dir)+" does not exist yet", "privometry daemon install creates it."
	case err != nil:
		c.Status, c.Detail = "fail", err.Error()
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		c.Status, c.Detail = "fail", r.home(dir)+" is not a plain folder"
	case info.Mode().Perm()&0o077 != 0:
		c.Status, c.Detail, c.Fix = "fail", fmt.Sprintf("%s is mode %o; other users could read the timeline", r.home(dir), info.Mode().Perm()), "chmod 700 "+r.home(dir)
	default:
		c.Detail = r.home(dir) + ", private to you"
		for _, f := range []string{"privometry.db", "privometryd.log", daemon.FailModesFile, daemon.SpoolFile} {
			if fi, err := os.Stat(filepath.Join(dir, f)); err == nil && fi.Mode().Perm()&0o077 != 0 {
				c.Status, c.Detail = "fail", fmt.Sprintf("%s is mode %o", f, fi.Mode().Perm())
				c.Fix = "chmod 600 " + r.home(filepath.Join(dir, f))
			}
		}
	}
	r.add(c)
}

func (r *doctorRun) checkService() {
	c := Check{ID: "service", Title: "Service", Status: "ok"}
	privometryd, _ := sibling("", "privometryd")
	opts := service.Options{Env: r.env, Privometryd: privometryd, Run: serviceRunner, UID: os.Getuid()}
	plan, err := service.For(opts)
	if err != nil {
		c.Status, c.Detail = "skip", err.Error()
		r.add(c)
		return
	}
	r.plan = plan
	st := service.Check(plan, opts)
	switch {
	case !st.Installed:
		c.Status, c.Detail, c.Fix = "fail", "not installed, so privometryd does not start at login", "privometry daemon install"
	case !st.Running:
		c.Status, c.Detail, c.Fix = "fail", "installed but not running", "privometry daemon restart, then check "+r.home(filepath.Join(r.dataDir, "privometryd.log"))
	case !st.Current:
		c.Status, c.Detail, c.Fix = "warn", fmt.Sprintf("running (pid %d), but %s no longer matches this install", st.PID, r.home(st.Path)), "privometry daemon install"
	default:
		c.Detail = fmt.Sprintf("running (pid %d) from %s", st.PID, r.home(st.Path))
	}
	r.add(c)
}

func (r *doctorRun) checkDaemon() {
	c := Check{ID: "daemon", Title: "Daemon", Status: "ok"}
	st, err := queryStatus(r.env)
	if err != nil {
		c.Status, c.Detail = "fail", "not reachable, so agent hooks apply fail modes only"
		c.Fix = "privometry daemon install"
		r.add(c)
		return
	}
	r.status = st
	c.Detail = fmt.Sprintf("version %s, up %s, %d policies cached", st.Version, time.Since(st.StartedAt.Time).Round(time.Second), st.Policies)
	if missing := missingOps(st.Ops); len(missing) > 0 {
		c.Status = "warn"
		c.Detail += fmt.Sprintf("; older than this CLI (no %s)", strings.Join(missing, ", "))
		c.Fix = "privometry daemon restart"
	}
	r.add(c)
}

// probePayload is a Claude Code PreToolUse call for rm -rf ~, which every
// Privometry install must block, even with the daemon down.
func probePayload(home string) []byte {
	b, _ := json.Marshal(map[string]any{
		"session_id": "privometry-doctor", "hook_event_name": "PreToolUse", "cwd": home, "permission_mode": "default",
		"tool_name": "Bash", "tool_input": map[string]any{"command": "rm -rf ~", "description": "privometry doctor test"},
		"tool_use_id": fmt.Sprintf("privometry-doctor-%d", time.Now().UnixNano()),
	})
	return b
}

func (r *doctorRun) checkProbe(enabled bool) {
	c := Check{ID: "hook_probe", Title: "Test decision", Status: "ok"}
	if !enabled {
		c.Status, c.Detail = "skip", "--no-probe"
		r.add(c)
		return
	}
	hook, err := sibling("", "privometry-hook")
	if err != nil {
		c.Status, c.Detail = "skip", "privometry-hook not found"
		r.add(c)
		return
	}
	var token string
	if r.status != nil {
		if missing := missingOps(r.status.Ops); len(missing) > 0 {
			c.Status, c.Detail = "skip", "the daemon is too old to take a test call without recording it"
			r.add(c)
			return
		}
		addr, _ := r.env.IPCAddress()
		resp, err := ipc.Call(addr, ipc.Request{Op: "probe"}, time.Second)
		var out struct{ Token string }
		if err == nil {
			err = json.Unmarshal(resp.Data, &out)
		}
		if err != nil || out.Token == "" {
			c.Status, c.Detail = "fail", fmt.Sprintf("the daemon did not issue a probe token: %v", err)
			r.add(c)
			return
		}
		token = out.Token
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, hook, "claude_code", "PreToolUse")
	cmd.Stdin = bytes.NewReader(probePayload(r.env.Home))
	cmd.Env = append(os.Environ(), hookclient.ProbeEnv+"="+token)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	start := time.Now()
	err = cmd.Run()
	took := time.Since(start)
	var reply struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &reply)
	verdict, reason := reply.HookSpecificOutput.PermissionDecision, reply.HookSpecificOutput.PermissionDecisionReason
	ms := float64(took.Microseconds()) / 1000
	switch {
	case err != nil:
		c.Status, c.Detail = "fail", fmt.Sprintf("privometry-hook failed: %v", err)
	case verdict != "deny":
		c.Status, c.Detail = "fail", fmt.Sprintf("rm -rf ~ was not blocked (reply %q)", strings.TrimSpace(stdout.String()))
		c.Fix = "Check your policies with privometry policy explain --command 'rm -rf ~'"
	case strings.Contains(reason, "could not reach its daemon"):
		c.Status = "warn"
		c.Detail = fmt.Sprintf("privometry-hook blocked rm -rf ~ on its own in %.1f ms (fail mode); recorded as a fail-mode event", ms)
		c.Fix = "Start the daemon so every action is decided by your policies: privometry daemon install"
	case took > hookclient.DefaultTimeout:
		c.Status, c.Detail = "warn", fmt.Sprintf("blocked rm -rf ~, but the round trip took %.0f ms (budget %s)", ms, hookclient.DefaultTimeout)
	default:
		c.Detail = fmt.Sprintf("privometry-hook and privometryd blocked rm -rf ~ in %.1f ms; nothing was recorded", ms)
	}
	r.add(c)
}

func (r *doctorRun) checkFailModes() {
	c := Check{ID: "fail_modes", Title: "Fail modes", Status: "ok"}
	modes := map[string]string{}
	for k, v := range contract.DefaultFailModes() {
		modes[k] = string(v)
	}
	source := "defaults"
	if raw, err := os.ReadFile(filepath.Join(r.dataDir, daemon.FailModesFile)); err == nil {
		var file daemon.FailModes
		if err := json.Unmarshal(raw, &file); err != nil {
			c.Status, c.Detail = "warn", daemon.FailModesFile+" is not valid JSON, so privometry-hook uses the defaults"
			r.add(c)
			return
		}
		for k, v := range file.FailModes {
			modes[k] = string(v)
		}
		source = "from your policy"
	}
	var parts []string
	for _, k := range []string{"catastrophic", "secrets", "exfiltration", "unapproved_mcp", "other"} {
		parts = append(parts, k+" "+modes[k])
	}
	c.Detail = strings.Join(parts, ", ") + " (" + source + ")"
	if modes["catastrophic"] != "closed" {
		c.Status = "warn"
		c.Fix = "With the daemon down, catastrophic actions are not blocked. Set fail_modes.catastrophic: closed."
	}
	r.add(c)
}

func (r *doctorRun) checkSpool() {
	c := Check{ID: "spool", Title: "Offline decisions", Status: "ok", Detail: "none waiting"}
	path := filepath.Join(r.dataDir, daemon.SpoolFile)
	f, err := os.Open(path)
	if err != nil {
		r.add(c)
		return
	}
	defer f.Close()
	info, _ := f.Stat()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	if n == 0 {
		r.add(c)
		return
	}
	c.Detail = fmt.Sprintf("%d decisions made while privometryd was down, waiting to be imported", n)
	if r.status != nil && time.Since(info.ModTime()) > 2*time.Minute {
		c.Status, c.Fix = "warn", "privometryd imports these every minute; see "+r.home(filepath.Join(r.dataDir, "privometryd.log"))
	}
	r.add(c)
}

func (r *doctorRun) checkAgents() {
	reg, err := loadAdapters(r.env)
	if err != nil {
		r.add(Check{ID: "agents", Title: "Agents", Status: "fail", Detail: err.Error()})
		return
	}
	agents, _, err := guardTargets(reg, r.env, "")
	if err != nil {
		r.add(Check{ID: "agents", Title: "Agents", Status: "warn", Detail: err.Error()})
		return
	}
	hook, _ := resolveHook("")
	last := map[string]timeline.AgentActivity{}
	if r.status != nil {
		for _, a := range r.status.Agents {
			last[a.Agent] = a
		}
	}
	for _, a := range agents {
		st := guard.Check(a, guard.Options{Env: r.env, HookCommand: hook})
		r.guards = append(r.guards, st)
		c := Check{ID: "agent:" + string(a.Agent), Title: a.DisplayName, Status: "ok"}
		act, called := last[string(a.Agent)]
		switch st.State {
		case "installed":
			c.Detail = "hooked in " + r.home(st.Path)
			if st.FailClosed {
				c.Detail += ", fail closed"
			}
			switch {
			case called:
				c.Detail += fmt.Sprintf("; last call %s ago", time.Since(act.LastCall).Round(time.Second))
			case st.TrustRequired:
				c.Status, c.Fix = "warn", st.Detail
				if engine := appEngine(a, r.env); engine != "" {
					c.Fix += " /hooks is in the terminal UI; if the codex command does not run, start the desktop app's engine: " + engine
				}
				c.Detail += "; no calls yet"
			}
		case "missing":
			c.Status, c.Detail, c.Fix = "fail", "not hooked: its actions are not checked", "privometry guard install --agent "+string(a.Agent)
		case "unsupported":
			c.Status, c.Detail = "skip", "not supported yet"
		default:
			c.Status, c.Detail, c.Fix = "warn", st.State+" ("+strings.Join(st.Missing, ", ")+")", "privometry guard install --agent "+string(a.Agent)
		}
		r.add(c)
	}
}

// appEngine is the agent binary inside its installed desktop app, if any.
func appEngine(a registry.Adapter, env platform.Env) string {
	paths, _ := a.Paths(a.Detect.AppBinaries, env, "")
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return strings.ReplaceAll(p, " ", `\ `)
		}
	}
	return ""
}

// checkDefinitions reports which adapter definitions and detector packs are
// in use, and warns when an installed signed set is ignored.
func (r *doctorRun) checkDefinitions() {
	c := Check{ID: "definitions", Title: "Definitions", Status: "ok"}
	var parts, problems []string
	for _, st := range definitions.Statuses(definitionOptions(r.env)) {
		parts = append(parts, fmt.Sprintf("%s: %s set %d", strings.ToLower(st.Kind.Label()), st.Source, st.SetVersion))
		if st.Problem != "" {
			problems = append(problems, strings.ToLower(st.Kind.Label())+": "+st.Problem)
		}
	}
	c.Detail = strings.Join(parts, "; ")
	if len(problems) > 0 {
		c.Status, c.Detail = "warn", c.Detail+"; "+strings.Join(problems, "; ")
		c.Fix = "privometry definitions update installs the latest signed sets; the built-in ones protect you meanwhile."
	}
	r.add(c)
}

func (r *doctorRun) checkPolicy() {
	c := Check{ID: "policy", Title: "Policy", Status: "ok"}
	cwd, _ := os.Getwd()
	r.repo = platform.GitRoot(cwd)
	packs, err := availablePacks(r.env, nil)
	if err != nil {
		c.Status, c.Detail = "fail", err.Error()
		r.add(c)
		return
	}
	sources, errs := policy.Sources(r.env, r.repo, time.Now())
	res, err := merge.Merge(merge.Input{Packs: packs, Policies: sources, Now: time.Now()})
	if err == nil {
		_, err = policy.New(res)
	}
	if err != nil {
		c.Status, c.Detail = "fail", "the policy does not compile: "+err.Error()
		r.add(c)
		return
	}
	r.merged = res
	var layers []string
	for _, s := range sources {
		layers = append(layers, s.Layer)
	}
	c.Detail = fmt.Sprintf("%d rules from %d packs", len(res.Rules), len(res.Packs))
	if len(layers) > 0 {
		c.Detail += " and the " + strings.Join(layers, " and ") + " policy"
	}
	var problems []string
	for _, e := range errs {
		problems = append(problems, e.Error())
	}
	for _, d := range res.Diagnostics {
		problems = append(problems, d.Layer+": "+d.Message)
	}
	if len(problems) > 0 {
		c.Status = "warn"
		c.Detail += "; " + strings.Join(problems, "; ")
		c.Fix = "privometry policy test <file> shows the problem in context."
	}
	r.add(c)
}

func (r *doctorRun) checkAlerts() {
	c := Check{ID: "alerts", Title: "Alerts", Status: "ok", Detail: "none in the last 24 hours"}
	dbPath, err := r.env.DBPath()
	if err != nil {
		return
	}
	store, err := timeline.OpenReadOnly(dbPath)
	if err != nil {
		c.Detail = "no timeline yet"
		r.add(c)
		return
	}
	defer store.Close()
	rows, err := store.Events(timeline.Query{Type: "integrity", Since: time.Now().Add(-24 * time.Hour), Limit: 20})
	if err != nil || len(rows) == 0 {
		r.add(c)
		return
	}
	var seen []string
	for _, row := range rows {
		seen = append(seen, fmt.Sprintf("%s %s (%s)", row.AgentName(), row.Why(), row.Event.OccurredAt.Local().Format("Jan 02 15:04")))
	}
	c.Status, c.Detail = "warn", strings.Join(seen, "; ")
	c.Fix = "If you did not make these changes, check the agent's config and run privometry guard install."
	r.add(c)
}

var marks = map[string]string{"ok": "✓", "warn": "!", "fail": "✗", "skip": "-"}
var markColors = map[string]string{"ok": "\x1b[32m", "warn": "\x1b[33m", "fail": "\x1b[31m", "skip": "\x1b[2m"}

func printChecks(w io.Writer, checks []Check, color bool) {
	width := 0
	for _, c := range checks {
		width = max(width, len([]rune(c.Title)))
	}
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.Status]++
		m := marks[c.Status]
		if color {
			m = markColors[c.Status] + m + "\x1b[0m"
		}
		fmt.Fprintf(w, "%s %-*s  %s\n", m, width, c.Title, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(w, "  %*s  Fix: %s\n", width, "", c.Fix)
		}
	}
	switch {
	case counts["fail"] == 1:
		fmt.Fprintln(w, "\n1 problem needs fixing; Privometry is not fully protecting this machine.")
	case counts["fail"] > 1:
		fmt.Fprintf(w, "\n%d problems need fixing; Privometry is not fully protecting this machine.\n", counts["fail"])
	case counts["warn"] == 1:
		fmt.Fprintln(w, "\nPrivometry is protecting this machine, with 1 warning.")
	case counts["warn"] > 1:
		fmt.Fprintf(w, "\nPrivometry is protecting this machine, with %d warnings.\n", counts["warn"])
	default:
		fmt.Fprintln(w, "\nPrivometry is protecting this machine.")
	}
}
