package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/redact"
)

const (
	// silentAfter is how long an agent runs before its silence counts.
	silentAfter = 3 * time.Minute
	// activeGrace is how long an agent's session files must have shown use
	// before its silence counts: agy and Codex fire their session-start hook
	// with the first prompt, around when the transcript appears.
	activeGrace = time.Minute
	// callerDepth bounds the walk from privometry-hook's parent up to the
	// agent: usually a shell, sometimes a wrapper script or two.
	callerDepth = 8
)

// Procs reads running processes. Tests replace them.
type Procs struct {
	List func() ([]platform.Process, error)
	Info func(pid int) (platform.Process, error)
	Env  func(pid int, names []string) (map[string]string, error)
	Cwd  func(pid int) (string, error)
}

func (p *Procs) defaults() {
	if p.List == nil {
		p.List = platform.Processes
	}
	if p.Info == nil {
		p.Info = platform.ProcessInfo
	}
	if p.Env == nil {
		p.Env = platform.ProcessEnv
	}
	if p.Cwd == nil {
		p.Cwd = platform.ProcessCwd
	}
}

// procState is what the daemon knows about running processes, guarded by mu.
type procState struct {
	called map[platform.ProcessKey]time.Time             // processes above a hook call, and when it came
	chains map[platform.ProcessKey][]platform.ProcessKey // a hook's parent and the processes above it
	silent map[platform.ProcessKey]bool                  // agents already reported as silent
	active map[platform.ProcessKey]time.Time             // agents whose session files changed since they started, first seen when
}

// noteCaller records the processes above a hook call, starting at
// privometry-hook's parent. The agent is one of them; which one does not
// matter, so nothing is matched here and the hook client stays as small as
// it is. Chains are cached by the parent's PID and start time.
func (d *Daemon) noteCaller(ppid int) {
	if ppid <= 1 {
		return // an older hook client, or an orphan
	}
	parent, err := d.cfg.Procs.Info(ppid)
	if err != nil {
		return
	}
	key := parent.Key()
	d.mu.Lock()
	chain, ok := d.procs.chains[key]
	d.mu.Unlock()
	if !ok {
		chain = []platform.ProcessKey{key}
		for _, p := range platform.Ancestors(parent.PPID, callerDepth-1, d.cfg.Procs.Info) {
			chain = append(chain, p.Key())
		}
	}
	now := d.cfg.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.procs.called == nil {
		d.procs.called, d.procs.chains = map[platform.ProcessKey]time.Time{}, map[platform.ProcessKey][]platform.ProcessKey{}
	}
	d.procs.chains[key] = chain
	for _, k := range chain {
		d.procs.called[k] = now
	}
}

// CheckSilent looks for agents that have run for three minutes, and been in
// use for one, without their hooks calling Privometry (EDGE-24): the backstop
// for whatever turned the hooks off, named or not. Each silent agent process
// is reported once, with a reason when one is known. Agents whose Privometry hook is not installed are
// left alone: nothing expects them to call. It returns how many events it
// recorded.
func (d *Daemon) CheckSilent() (int, error) {
	procs, err := d.cfg.Procs.List()
	if err != nil {
		return 0, err
	}
	now := d.cfg.Now()
	live := map[platform.ProcessKey]bool{}
	for _, p := range procs {
		live[p.Key()] = true
	}
	d.forgetGone(live)
	n := 0
	for _, p := range procs {
		a, ok := d.silentCandidate(p)
		if !ok || p.Start.IsZero() || now.Sub(p.Start) < silentAfter {
			continue
		}
		k := p.Key()
		d.mu.Lock()
		_, called := d.procs.called[k]
		reported := d.procs.silent[k]
		d.mu.Unlock()
		if called || reported {
			continue
		}
		env, vars := d.procEnv(a, p)
		if !d.inUse(a, p, env, now) {
			continue
		}
		reason, why, expected := d.silentReason(a, p, env, vars)
		if !expected {
			continue
		}
		mins := int(now.Sub(p.Start) / time.Minute)
		detail := fmt.Sprintf("%s has run for %d minutes and its hooks have not called Privometry: %s", a.DisplayName, mins, why)
		if err := d.recordSilent(a, reason, detail); err != nil {
			return n, err
		}
		d.mu.Lock()
		if d.procs.silent == nil {
			d.procs.silent = map[platform.ProcessKey]bool{}
		}
		d.procs.silent[k] = true
		d.mu.Unlock()
		n++
	}
	return n, nil
}

// forgetGone drops what the daemon kept about processes that have ended.
func (d *Daemon) forgetGone(live map[platform.ProcessKey]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.procs.called {
		if !live[k] {
			delete(d.procs.called, k)
		}
	}
	for k := range d.procs.chains {
		if !live[k] {
			delete(d.procs.chains, k)
		}
	}
	for k := range d.procs.silent {
		if !live[k] {
			delete(d.procs.silent, k)
		}
	}
	for k := range d.procs.active {
		if !live[k] {
			delete(d.procs.active, k)
		}
	}
}

// procEnv is the daemon's environment with the agent's env_overrides as the
// process has them; only those variables are read from it.
func (d *Daemon) procEnv(a registry.Adapter, p platform.Process) (platform.Env, map[string]string) {
	if len(a.EnvOverrides) == 0 {
		return d.cfg.Env, nil
	}
	var names []string
	for _, o := range a.EnvOverrides {
		names = append(names, o.Var)
	}
	vars, err := d.cfg.Procs.Env(p.PID, names)
	if err != nil || len(vars) == 0 {
		return d.cfg.Env, nil
	}
	return envWith(d.cfg.Env, vars), vars
}

// inUse reports whether an agent process has been in use for activeGrace: one
// of its session files (transcripts) changed after it started. An idle agent
// writes none, and agents that fire their session-start hook only at the
// first prompt make no hook call until then. The files are the agent's, not
// the process's, so another session of the same agent counts too. Without
// session_paths in the definition, every running agent counts as in use.
func (d *Daemon) inUse(a registry.Adapter, p platform.Process, env platform.Env, now time.Time) bool {
	if len(a.Detect.SessionPaths) == 0 {
		return true
	}
	k := p.Key()
	d.mu.Lock()
	since, seen := d.procs.active[k]
	d.mu.Unlock()
	if !seen {
		if !changedSince(a, env, p.Start) {
			return false
		}
		since = now
		d.mu.Lock()
		if d.procs.active == nil {
			d.procs.active = map[platform.ProcessKey]time.Time{}
		}
		d.procs.active[k] = now
		d.mu.Unlock()
	}
	return now.Sub(since) >= activeGrace
}

// changedSince reports whether any of the agent's session files was modified
// after t.
func changedSince(a registry.Adapter, env platform.Env, t time.Time) bool {
	patterns, err := a.Paths(a.Detect.SessionPaths, env, "")
	if err != nil {
		return false
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.ModTime().After(t) {
				return true
			}
		}
	}
	return false
}

// silentCandidate reports whether a process is an agent CLI that should be
// calling its hooks: found by its binary name or a process pattern, with a
// session-start hook, outside a desktop app bundle, not running a command
// that starts no session (claude mcp serve), and not started with a bypass
// flag (hooks_bypassed reports those). Cursor's CLI is left out until its
// sessions are known to start with a hook call.
func (d *Daemon) silentCandidate(p platform.Process) (registry.Adapter, bool) {
	a, byCLI, ok := d.agentOf(p.Args)
	if !ok || !byCLI || a.Agent == contract.AgentProductCursor {
		return a, false
	}
	if !slices.ContainsFunc(a.Hooks.Events, func(e registry.HookEvent) bool { return e.Role == registry.HookEventRoleSessionStart }) {
		return a, false
	}
	prog := strings.ReplaceAll(p.Args[0], `\`, "/")
	if strings.Contains(prog, ".app/") {
		return a, false
	}
	if hasArgs(p.Args, a.Detect.NoSessionArgs) || bypassFlag(p.Args, a.Detect.BypassFlags) != "" {
		return a, false
	}
	return a, true
}

// hasArgs reports whether args holds one of the space-separated argument
// sequences, consecutively, after the program (or a runtime's script).
func hasArgs(args []string, seqs []string) bool {
	for _, seq := range seqs {
		want := strings.Fields(seq)
		for i := 1; i+len(want) <= len(args); i++ {
			if slices.Equal(args[i:i+len(want)], want) {
				return true
			}
		}
	}
	return false
}

// silentReason says why an agent process may be silent, and whether a hook
// call was expected from it at all. A config folder from one of the agent's
// env_overrides without Privometry's hook is config_dir_override; a setting
// that turns hooks off (in its user, managed or working folder's project
// settings) is setting; a hook the agent must approve first (Codex) is
// untrusted_hook; anything else is unknown. Only the override variables are
// read from the process's environment, and only paths go into the detail,
// redacted.
func (d *Daemon) silentReason(a registry.Adapter, p platform.Process, env platform.Env, vars map[string]string) (events.IntegrityReason, string, bool) {
	if len(vars) > 0 {
		if st := guard.Check(a, guard.Options{Env: env}); st.State == "missing" {
			var set []string
			for _, o := range a.EnvOverrides {
				if v, ok := vars[o.Var]; ok {
					set = append(set, fmt.Sprintf("%s (%s)", o.Var, redact.Redact(v, redact.Context{Home: d.cfg.Env.Home})))
				}
			}
			return events.IntegrityReasonConfigDirOverride,
				fmt.Sprintf("it uses the config folder from %s, which has no Privometry hook.", strings.Join(set, ", ")), true
		}
	}
	project, _ := d.cfg.Procs.Cwd(p.PID)
	if git := platform.GitRoot(project); git != "" {
		project = git
	}
	st := guard.Check(a, guard.Options{Env: env, Project: project})
	switch {
	case st.State == "missing" || st.State == "unsupported":
		return "", "", false
	case st.State == "disabled" && st.DisabledBy != "":
		return events.IntegrityReasonSetting,
			fmt.Sprintf("a setting in %s turns its hooks off.", redact.Redact(st.DisabledBy, redact.Context{Home: d.cfg.Env.Home})), true
	case st.State == "disabled":
		return events.IntegrityReasonSetting, "Privometry's own hook entry is turned off.", true
	case st.TrustRequired:
		return events.IntegrityReasonUntrustedHook, "the agent runs new hooks only after they are approved, and Privometry's has not been.", true
	}
	return events.IntegrityReasonUnknown, "the reason is not known; the agent may have been started with hooks turned off in a way Privometry does not recognize.", true
}

// envWith is env with some variables set.
func envWith(env platform.Env, vars map[string]string) platform.Env {
	get := env.Getenv
	env.Getenv = func(k string) string {
		if v, ok := vars[k]; ok {
			return v
		}
		if get != nil {
			return get(k)
		}
		return ""
	}
	return env
}

func (d *Daemon) recordSilent(a registry.Adapter, reason events.IntegrityReason, detail string) error {
	in := &events.Integrity{Check: events.IntegrityCheckHooksSilent, Reason: reason, AgentProduct: a.Agent, Detail: detail}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"user.local_user": contract.PrivacyLevelClear}}
	d.cfg.Logger.Warn("agent running without calling its hooks", "agent", a.Agent, "reason", reason)
	return d.appendEvent(ev, "")
}
