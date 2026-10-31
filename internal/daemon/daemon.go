// Package daemon is privometryd: it answers hook calls from privometry-hook, keeps
// per-session state, and records every decision in the local timeline.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/privometry/privometry-edge/detectorpacks"
	"github.com/privometry/privometry-edge/internal/content"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/extension"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/merge"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/internal/redact"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// Files in the data directory shared with privometry-hook.
const (
	FailModesFile = "failmodes.json" // written by the daemon, read by privometry-hook
	SpoolFile     = "spool.jsonl"    // appended by privometry-hook, imported by the daemon
	DBFile        = "privometry.db"
)

// Config is what a daemon needs.
type Config struct {
	Env      platform.Env
	Registry *registry.Registry
	Packs    []rulepack.Pack
	// Detectors are the content detector packs; nil means the shipped ones.
	Detectors []*content.Pack
	Logger    *slog.Logger
	Now       func() time.Time // nil means time.Now
	// Procs reads running processes, for bypass flags and silent agents; nil
	// functions mean the platform's.
	Procs Procs
	// BootTime says when the system started, to tell a reboot from a stopped
	// daemon; nil means platform.BootTime.
	BootTime func() (time.Time, error)
	// LocalCapture controls target_clear in the local timeline. Empty defaults
	// to redacted; clear is retained for explicitly configured deployments.
	LocalCapture contract.PrivacyLevel
	// Connector links the device to a control plane; nil means the one the
	// build registered (internal/extension), if any. Without one the daemon
	// runs on its own.
	Connector extension.NewConnector
	// AdapterSetVersion is the adapter definition set in use, for heartbeats.
	AdapterSetVersion int64
}

// appendEvent applies the local persistence boundary before data reaches
// SQLite. The event payload is already redacted for upload; targetClear is
// additionally redacted here so every producer, including spool import, uses
// the same local-capture policy.
func (d *Daemon) appendEvent(ev *events.Event, targetClear string) error {
	if d.cfg.LocalCapture != contract.PrivacyLevelClear {
		targetClear = redact.Redact(targetClear, redact.Context{Home: d.cfg.Env.Home})
	}
	return d.store.Append(ev, targetClear)
}

// Daemon answers hook calls.
type Daemon struct {
	cfg      Config
	dataDir  string
	store    *timeline.Store
	deviceID string
	device   events.Device

	started time.Time

	mu       sync.Mutex
	policies map[string]*cachedPolicy // by repo root; "" is no repo
	recent   map[string]recentCall    // by tool_use_id, for dedupe
	hooked   map[contract.AgentProduct]hookedState
	probes   map[string]time.Time // one-time probe tokens and their expiry

	lastHook map[contract.AgentProduct]time.Time // when each agent's hook last called, for the MCP shim

	content     *content.Engine
	memMu       sync.Mutex           // memory file checks, snapshots and restores
	bypassSeen  map[string]bool      // "<agent> <flag>" running at the last bypass check; housekeeping only
	procs       procState            // which running processes call the hook, and silent agents already reported
	roots       map[string]time.Time // workspaces agents worked in, for project memory files
	agentWrites map[string]time.Time // memory files agents were allowed to write, for attribution
	bg          sync.WaitGroup       // background scans
	bgSlots     chan struct{}

	conn         extension.Connector  // the control plane connection, or nil
	approver     extension.Approver   // the connector, when it routes asks to people
	catalogState catalogState         // guarded by mu
	approvals    map[string]*approval // remote approvals by action, guarded by mu
	feedState    feedState            // the risk feed, guarded by mu
	stop         context.Context      // canceled by Close, for background work that waits on the cloud
	cancel       context.CancelFunc
}

type hookedState struct {
	stamp string
	on    bool
}

type cachedPolicy struct {
	p     *policy.Policy
	allow *content.Allowlist // content allowlist entries of the same files
	stamp string             // policy file mtimes and sizes when loaded
	until time.Time
}

type recentCall struct {
	resp ipc.Response
	at   time.Time
}

// New opens the timeline in the data directory.
func New(cfg Config) (*Daemon, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Procs.defaults()
	if cfg.BootTime == nil {
		cfg.BootTime = platform.BootTime
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	dir, err := cfg.Env.DataDir()
	if err != nil {
		return nil, err
	}
	if err := platform.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	// launchd and systemd create the log file with their default mode.
	_ = os.Chmod(filepath.Join(dir, "privometryd.log"), 0o600)
	store, err := timeline.Open(filepath.Join(dir, DBFile))
	if err != nil {
		return nil, err
	}
	id, err := store.DeviceID()
	if err != nil {
		store.Close()
		return nil, err
	}
	if cfg.Detectors == nil {
		if cfg.Detectors, err = content.Load(detectorpacks.FS); err != nil {
			store.Close()
			return nil, err
		}
	}
	salt, err := contentSalt(store.State, store.SetState)
	if err != nil {
		store.Close()
		return nil, err
	}
	d := &Daemon{cfg: cfg, dataDir: dir, store: store, deviceID: id, started: cfg.Now(),
		policies: map[string]*cachedPolicy{}, recent: map[string]recentCall{}, hooked: map[contract.AgentProduct]hookedState{},
		content: content.New(cfg.Detectors, content.Options{Salt: salt}), bgSlots: make(chan struct{}, 2),
		roots: map[string]time.Time{}, agentWrites: map[string]time.Time{}}
	d.device = events.Device{DeviceID: id, OS: contract.OS(cfg.Env.OS()), OSVersion: osVersion(), Arch: arch(), SensorVersion: sensorVersion()}
	d.stop, d.cancel = context.WithCancel(context.Background())
	newConn := cfg.Connector
	if newConn == nil {
		newConn = extension.Registered()
	}
	if newConn != nil {
		// Before the baseline policy: a connector may set the fingerprint key.
		if d.conn, err = newConn(host{d}, extension.Options{Env: cfg.Env, Logger: cfg.Logger}); err != nil {
			d.cancel()
			store.Close()
			return nil, err
		}
		d.approver, _ = d.conn.(extension.Approver)
	}
	if _, err := d.policyFor(""); err != nil {
		d.cfg.Logger.Warn("baseline policy failed to load", "err", err)
	}
	return d, nil
}

// Close waits for background scans and closes the timeline.
func (d *Daemon) Close() error {
	d.cancel()
	d.bg.Wait()
	return d.store.Close()
}

// Wait blocks until background scans finish, for tests.
func (d *Daemon) Wait() { d.bg.Wait() }

// Sync runs the connector's work that is due now, as the daemon's loop does
// every few seconds; tests call it instead of waiting. It reports whether the
// organization's bundle changed, and is false without a connector.
func (d *Daemon) Sync(ctx context.Context) bool {
	if d.conn == nil {
		return false
	}
	return d.conn.Sync(ctx, d.cfg.Now())
}

// Store exposes the timeline, for tests and the CLI.
func (d *Daemon) Store() *timeline.Store { return d.store }

// Run listens on the IPC socket until ctx ends, importing the hook client's
// spool and pruning old rows in the background.
func (d *Daemon) Run(ctx context.Context) error {
	release, err := lock(d.dataDir)
	if err != nil {
		return err
	}
	defer release()
	addr, err := d.cfg.Env.IPCAddress()
	if err != nil {
		return err
	}
	l, err := ipc.Listen(addr)
	if err != nil {
		return err
	}
	d.cfg.Logger.Info("privometryd listening", "socket", addr, "version", buildinfo.Version)
	if _, err := d.CheckLastRun(); err != nil {
		d.cfg.Logger.Warn("could not check the previous run", "err", err)
	}
	if err := d.MarkAlive(); err != nil {
		d.cfg.Logger.Warn("could not mark privometryd alive", "err", err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	go d.housekeeping(ctx)
	if d.conn != nil {
		go d.connectorLoop(ctx)
	}
	err = ipc.Serve(l, d.Handle, 5*time.Second)
	os.Remove(addr)
	if ctx.Err() != nil {
		if err := d.MarkStopped(); err != nil {
			d.cfg.Logger.Warn("could not mark the stop", "err", err)
		}
	}
	return err
}

func (d *Daemon) housekeeping(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastPrune, lastBypass := time.Time{}, time.Time{}
	for {
		if err := d.MarkAlive(); err != nil {
			d.cfg.Logger.Warn("could not mark privometryd alive", "err", err)
		}
		if _, err := d.CheckIntegrity(); err != nil {
			d.cfg.Logger.Warn("integrity check failed", "err", err)
		}
		if _, err := d.CheckMemory(); err != nil {
			d.cfg.Logger.Warn("memory check failed", "err", err)
		}
		if _, err := d.CheckSilent(); err != nil {
			d.cfg.Logger.Warn("silent agent check failed", "err", err)
		}
		if now := d.cfg.Now(); now.Sub(lastBypass) >= bypassEvery {
			if _, err := d.CheckBypass(); err != nil {
				d.cfg.Logger.Warn("bypass check failed", "err", err)
			}
			lastBypass = now
		}
		if n, err := d.ImportSpool(); err != nil {
			d.cfg.Logger.Warn("spool import failed", "err", err)
		} else if n > 0 {
			d.cfg.Logger.Info("imported fail-mode events", "count", n)
		}
		if now := d.cfg.Now(); now.Sub(lastPrune) > 24*time.Hour {
			if _, err := d.store.Prune(now.Add(-30*24*time.Hour), now.Add(-7*24*time.Hour)); err != nil {
				d.cfg.Logger.Warn("prune failed", "err", err)
			}
			if _, err := d.store.PruneMemory(keepVersions, now.Add(-keepFor)); err != nil {
				d.cfg.Logger.Warn("memory snapshot prune failed", "err", err)
			}
			lastPrune = now
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Handle answers one IPC request.
func (d *Daemon) Handle(req ipc.Request) ipc.Response {
	switch req.Op {
	case "ping":
		return ipc.Response{OK: true}
	case "status":
		st, err := d.Status()
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		data, _ := json.Marshal(st)
		return ipc.Response{OK: true, Data: data}
	case "events":
		var q timeline.Query
		if len(req.Query) > 0 {
			if err := json.Unmarshal(req.Query, &q); err != nil {
				return ipc.Response{Error: "bad query: " + err.Error()}
			}
		}
		rows, err := d.store.Events(q)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		if rows == nil {
			rows = []timeline.Row{}
		}
		data, _ := json.Marshal(rows)
		return ipc.Response{OK: true, Data: data}
	case "probe":
		data, _ := json.Marshal(map[string]string{"token": d.newProbe()})
		return ipc.Response{OK: true, Data: data}
	case "memory":
		var q MemoryQuery
		if err := json.Unmarshal(req.Query, &q); err != nil {
			return ipc.Response{Error: "bad query: " + err.Error()}
		}
		out, err := d.memoryOp(q)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		data, _ := json.Marshal(out)
		return ipc.Response{OK: true, Data: data}
	case "lifecycle":
		var q Lifecycle
		if err := json.Unmarshal(req.Query, &q); err != nil {
			return ipc.Response{Error: "bad query: " + err.Error()}
		}
		if err := d.lifecycle(q); err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{OK: true}
	case "mcp":
		if req.MCP == nil {
			return ipc.Response{Error: "mcp request without mcp"}
		}
		resp, err := d.mcp(*req.MCP)
		if err != nil {
			d.cfg.Logger.Error("mcp failed", "agent", req.MCP.Agent, "server", req.MCP.Server, "phase", req.MCP.Phase, "err", err)
			return ipc.Response{Error: err.Error()}
		}
		resp.OK = true
		return resp
	case "hook":
		if req.Hook == nil {
			return ipc.Response{Error: "hook request without hook"}
		}
		resp, err := d.hook(*req.Hook)
		if err != nil {
			d.cfg.Logger.Error("hook failed", "agent", req.Hook.Agent, "event", req.Hook.Event, "err", err)
			return ipc.Response{Error: err.Error()}
		}
		resp.OK = true
		return resp
	}
	return ipc.Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
}

// Ops are the IPC operations this build answers. A CLI newer than the
// running daemon finds the ones it needs missing and asks for a restart.
var Ops = []string{"ping", "status", "events", "hook", "mcp", "probe", "memory", "lifecycle"}

// Status is what "privometry daemon status" shows.
type Status struct {
	Version   string                   `json:"version"`
	Ops       []string                 `json:"ops"`
	PID       int                      `json:"pid"`
	StartedAt contract.Time            `json:"started_at"`
	DataDir   string                   `json:"data_dir"`
	DeviceID  string                   `json:"device_id"`
	Policies  int                      `json:"policies_cached"`
	Agents    []timeline.AgentActivity `json:"agents"`
}

// Status reports the daemon's state and each agent's hook activity.
func (d *Daemon) Status() (Status, error) {
	agents, err := d.store.Activity()
	if err != nil {
		return Status{}, err
	}
	d.mu.Lock()
	n := len(d.policies)
	d.mu.Unlock()
	return Status{Version: buildinfo.Version, Ops: Ops, PID: os.Getpid(), StartedAt: contract.At(d.started), DataDir: d.dataDir,
		DeviceID: d.deviceID, Policies: n, Agents: agents}, nil
}

// policyFor returns the merged policy for a repo: shipped packs, the user
// policy and the repo policy. It is reloaded when either file changes, and at
// the next exception expiry.
func (d *Daemon) policyFor(repoRoot string) (*policy.Policy, error) {
	stamp := stampOf(d.cfg.Env.Home, repoRoot, d.dataDir)
	d.mu.Lock()
	c, ok := d.policies[repoRoot]
	d.mu.Unlock()
	now := d.cfg.Now()
	if ok && c.stamp == stamp && (c.until.IsZero() || now.Before(c.until)) {
		return c.p, nil
	}
	sources, errs := policy.Sources(d.cfg.Env, repoRoot, now)
	for _, err := range errs {
		d.cfg.Logger.Warn("policy file ignored", "err", err)
	}
	in := merge.Input{Packs: d.cfg.Packs, Policies: sources, Now: now}
	res, err := merge.Merge(in)
	if err != nil {
		return nil, err
	}
	for _, diag := range res.Diagnostics {
		d.cfg.Logger.Warn("policy diagnostic", "layer", diag.Layer, "source", diag.Source, "message", diag.Message)
	}
	p, err := policy.New(res)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.policies[repoRoot] = &cachedPolicy{p: p, allow: policy.Allowlist(sources), stamp: stamp, until: merge.NextExpiry(in)}
	d.mu.Unlock()
	if repoRoot == "" {
		d.writeFailModes(res)
	}
	return p, nil
}

// allowlistFor returns the content allowlist of the user and repo policies
// (PRD SCAN-09), or nil when the policy does not load.
func (d *Daemon) allowlistFor(repoRoot string) *content.Allowlist {
	if _, err := d.policyFor(repoRoot); err != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.policies[repoRoot]; ok {
		return c.allow
	}
	return nil
}

func stampOf(home, repoRoot, dataDir string) string {
	var s string
	for _, p := range []string{filepath.Join(home, policy.UserPolicyPath), filepath.Join(repoRoot, policy.RepoPolicyPath), filepath.Join(dataDir, bundle.File)} {
		if info, err := os.Stat(p); err == nil {
			s += fmt.Sprintf("%s:%d:%d;", p, info.ModTime().UnixNano(), info.Size())
		}
	}
	return s
}

// FailModes is the file privometry-hook reads to decide alone when the daemon is
// unreachable.
type FailModes struct {
	UpdatedAt contract.Time                `json:"updated_at"`
	FailModes map[string]contract.FailMode `json:"fail_modes"`
}

func (d *Daemon) writeFailModes(res *merge.Result) {
	b, _ := json.MarshalIndent(FailModes{UpdatedAt: contract.At(d.cfg.Now()), FailModes: res.FailModes}, "", "  ")
	tmp := filepath.Join(d.dataDir, FailModesFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, filepath.Join(d.dataDir, FailModesFile))
		if err != nil {
			d.cfg.Logger.Warn("could not write fail modes", "err", err)
		}
	}
}

// hookedNatively reports whether an agent has its own Privometry hook installed,
// cached until its hook file changes.
func (d *Daemon) hookedNatively(agent contract.AgentProduct) bool {
	a, ok := d.cfg.Registry.Get(agent)
	if !ok {
		return false
	}
	stamp := ""
	if paths, err := a.Paths(a.Hooks.Install.Free.Paths, d.cfg.Env, ""); err == nil && len(paths) > 0 {
		if info, err := os.Stat(paths[0]); err == nil {
			stamp = fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
		}
	}
	d.mu.Lock()
	h, ok := d.hooked[agent]
	d.mu.Unlock()
	if ok && h.stamp == stamp {
		return h.on
	}
	on := stamp != "" && guard.Installed(a, guard.Options{Env: d.cfg.Env})
	d.mu.Lock()
	d.hooked[agent] = hookedState{stamp: stamp, on: on}
	d.mu.Unlock()
	return on
}

// remember caches a hook response by tool_use_id for two minutes, so the same
// tool call reported through two hook sources (Cursor runs Claude Code hooks
// too) is decided and recorded once.
// probeTTL is how long a probe token stays valid.
const probeTTL = 30 * time.Second

func (d *Daemon) newProbe() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	now := d.cfg.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.probes == nil {
		d.probes = map[string]time.Time{}
	}
	for t, exp := range d.probes {
		if now.After(exp) {
			delete(d.probes, t)
		}
	}
	d.probes[tok] = now.Add(probeTTL)
	return tok
}

// takeProbe consumes a probe token, reporting whether it was valid.
func (d *Daemon) takeProbe(tok string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.probes[tok]
	delete(d.probes, tok)
	return ok && !d.cfg.Now().After(exp)
}

func (d *Daemon) remember(id string, resp ipc.Response) {
	if id == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.cfg.Now()
	for k, v := range d.recent {
		if now.Sub(v.at) > 2*time.Minute {
			delete(d.recent, k)
		}
	}
	d.recent[id] = recentCall{resp: resp, at: now}
}

func (d *Daemon) recalled(id string) (ipc.Response, bool) {
	if id == "" {
		return ipc.Response{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.recent[id]
	if !ok || d.cfg.Now().Sub(r.at) > 2*time.Minute {
		return ipc.Response{}, false
	}
	return r.resp, true
}

func arch() contract.Arch {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return contract.Arch(runtime.GOARCH)
	}
	return contract.ArchOther
}

func sensorVersion() string {
	if v := buildinfo.Version; v != "dev" && registry.ParseVersion(v) == v {
		return v
	}
	return "0.0.0-dev"
}

var errUnknownAgent = errors.New("unknown agent")
