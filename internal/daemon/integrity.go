package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/redact"
	"github.com/privometry/privometry-edge/internal/scanner/parsers"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// watched is one config file the daemon keeps an eye on.
type watched struct {
	agent   registry.Adapter
	path    string
	tier    contract.ConfigTier
	format  string
	pointer string // for MCP sources: hash only the server map
	holds   []events.ConfigHold
	install bool // the file Privometry's hook is registered in
}

// watchList returns each agent's hook file, user and managed config files,
// and user MCP sources, and the project settings files that can turn an
// agent's hooks off in the workspaces agents worked in recently. Other
// project files are left out: the daemon does not know every repo, and the
// scanner covers them.
func (d *Daemon) watchList() []watched {
	var out []watched
	seen := map[string]bool{}
	add := func(w watched) {
		if !seen[w.path] {
			seen[w.path] = true
			out = append(out, w)
		}
	}
	for _, a := range d.cfg.Registry.All() {
		if paths, err := a.Paths(a.Hooks.Install.Free.Paths, d.cfg.Env, ""); err == nil && len(paths) > 0 {
			add(watched{agent: a, path: paths[0], tier: contract.ConfigTierUser, format: "json", holds: []events.ConfigHold{events.ConfigHoldHooks}, install: true})
		}
		for _, t := range a.ConfigTiers {
			if t.Tier == contract.ConfigTierProject {
				continue
			}
			switch t.Format {
			case registry.FileFormatJSON, registry.FileFormatJsonc, registry.FileFormatToml:
			default:
				continue // skills and rules are many small files; the scanner reports them
			}
			paths, err := a.Paths(t.Paths, d.cfg.Env, "")
			if err != nil {
				continue
			}
			for _, pattern := range paths {
				matches, _ := filepath.Glob(pattern)
				if len(matches) == 0 && !containsGlob(pattern) {
					matches = []string{pattern}
				}
				for _, p := range matches {
					add(watched{agent: a, path: p, tier: t.Tier, format: string(t.Format), holds: holdsOf(t.Holds)})
				}
			}
		}
		if len(a.Hooks.DisableSettings) > 0 {
			for _, root := range d.recentRoots() {
				for _, f := range guard.SettingsFiles(a, guard.Options{Env: d.cfg.Env}, root) {
					if f.Tier == string(contract.ConfigTierProject) {
						add(watched{agent: a, path: f.Path, tier: contract.ConfigTierProject, format: f.Format, holds: []events.ConfigHold{events.ConfigHoldSettings}})
					}
				}
			}
		}
		for _, src := range a.MCPSources {
			if src.Tier == contract.ConfigTierProject {
				continue
			}
			paths, _ := a.Paths(src.Paths, d.cfg.Env, "")
			for _, p := range paths {
				w := watched{agent: a, path: p, tier: src.Tier, format: string(src.Format), pointer: src.Pointer, holds: []events.ConfigHold{events.ConfigHoldMCPServers}}
				if seen[p] {
					// The same file is also a config tier (Codex config.toml); a whole-file hash already covers it.
					continue
				}
				add(w)
			}
		}
	}
	return out
}

func containsGlob(p string) bool {
	for _, c := range p {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

func holdsOf(h []registry.AdapterConfigTierHold) []events.ConfigHold {
	var out []events.ConfigHold
	for _, x := range h {
		switch x {
		case "settings", "permissions", "hooks", "mcp_servers", "skills", "plugins":
			out = append(out, events.ConfigHold(x))
		default:
			out = append(out, events.ConfigHoldOther)
		}
	}
	return out
}

// hashOf returns the file's digest, or of just its MCP server map, or "" if
// the file does not exist.
func hashOf(w watched) string {
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return ""
	}
	if w.pointer != "" {
		doc, err := parsers.Parse(w.format, raw)
		if err != nil {
			return digest(raw)
		}
		raw, _ = json.Marshal(parsers.Lookup(doc, w.pointer)) // map keys marshal sorted
	}
	return digest(raw)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CheckIntegrity compares every watched file with its last state and records
// config_change events for changed files, and integrity events when Privometry's
// hook disappears or changes. The first observation of a file records no
// config_change. A file that starts turning the agent's hooks off while
// Privometry's hook is installed records hooks_disabled, also when it is first
// seen (a project settings file from a new workspace). It returns how many
// events it recorded.
func (d *Daemon) CheckIntegrity() (int, error) {
	prev, err := d.store.ConfigHashes()
	if err != nil {
		return 0, err
	}
	n := 0
	now := d.cfg.Now()
	list := d.watchList()
	sort.Slice(list, func(i, j int) bool { return list[i].path < list[j].path })
	for _, w := range list {
		h := timeline.ConfigHash{Path: w.path, Tier: string(w.tier), Agent: string(w.agent.Agent), SHA256: hashOf(w)}
		var status guard.Status
		if w.install {
			status = guard.Check(w.agent, guard.Options{Env: d.cfg.Env})
			h.PrivometryHook = status.State != "missing" && status.State != "unsupported"
		}
		setting := guard.DisablesIn(w.agent, w.path, w.format)
		if setting == "" && w.install && status.State == "disabled" && status.DisabledBy == "" {
			setting = `"enabled": false on Privometry's own hook entry`
		}
		h.HooksOff = setting != ""
		old, known := prev[w.path]
		if err := d.store.SetConfigHash(h, now); err != nil {
			return n, err
		}
		if h.HooksOff && !old.HooksOff && d.hookedNatively(w.agent.Agent) {
			if err := d.recordHooksDisabled(w, setting, h.SHA256); err != nil {
				return n, err
			}
			n++
		}
		if !known || old.SHA256 == h.SHA256 {
			continue
		}
		if err := d.recordConfigChange(w, old.SHA256, h.SHA256); err != nil {
			return n, err
		}
		n++
		if w.install && old.PrivometryHook {
			check := ""
			switch {
			case !h.PrivometryHook:
				check = "hook_removed"
			case status.State == "partial", status.State == "disabled" && len(status.Missing) > 0:
				check = "hook_modified"
			}
			if check != "" {
				if err := d.recordIntegrity(w, check, old.SHA256, h.SHA256); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

func (d *Daemon) watcherSession(agent contract.AgentProduct) string {
	s, err := d.store.Session(string(agent), "privometry-file-watcher", "", d.cfg.Now())
	if err != nil {
		return ""
	}
	return s.ID
}

func (d *Daemon) recordConfigChange(w watched, before, after string) error {
	return d.recordConfigChangeBy(w, before, after, "")
}

// recordConfigChangeBy records a config_change event, with who made the
// change when it is known (memory files).
func (d *Daemon) recordConfigChangeBy(w watched, before, after string, by events.ConfigChangedBy) error {
	return d.appendEvent(d.configChangeEvent(w, before, after, by), w.path)
}

// configChangeEvent builds the config_change event for one file.
func (d *Daemon) configChangeEvent(w watched, before, after string, by events.ConfigChangedBy) *events.Event {
	change := events.ConfigChangeModified
	switch {
	case before == "":
		change = events.ConfigChangeCreated
	case after == "":
		change = events.ConfigChangeDeleted
	}
	cfg := &events.Config{Change: change, Tier: w.tier, Path: redact.Redact(w.path, redact.Context{Home: d.cfg.Env.Home}),
		Holds: w.holds, DetectedBy: events.ConfigDetectedByFileWatcher, ChangedBy: by}
	if before != "" {
		cfg.SHA256Before = before
	}
	if after != "" {
		cfg.SHA256After = after
	}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeConfigChange,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()},
		Agent:  &events.Agent{Product: w.agent.Agent, SessionID: d.watcherSession(w.agent.Agent), NativeSessionID: "privometry-file-watcher"},
		Config: cfg, Redaction: map[string]contract.PrivacyLevel{"config.path": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear}}
	return ev
}

func (d *Daemon) recordIntegrity(w watched, check, before, after string) error {
	detail := map[string]string{
		"hook_removed":  "Privometry's hook was removed from this file; the agent is no longer checked. Run: privometry guard install",
		"hook_modified": "Privometry's hook entries changed; some events are no longer checked. Run: privometry guard install",
	}[check]
	in := &events.Integrity{Check: events.IntegrityCheck(check), AgentProduct: w.agent.Agent, Tier: w.tier,
		Path: redact.Redact(w.path, redact.Context{Home: d.cfg.Env.Home}), Detail: detail}
	if before != "" {
		in.ExpectedSHA256 = before
	}
	if after != "" {
		in.ObservedSHA256 = after
	}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"integrity.path": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear}}
	d.cfg.Logger.Warn("integrity alert", "agent", w.agent.Agent, "check", check, "path", w.path)
	return d.appendEvent(ev, w.path)
}

// recordHooksDisabled records that a watched file turns the agent's hooks off,
// Privometry's included.
func (d *Daemon) recordHooksDisabled(w watched, setting, sha string) error {
	in := &events.Integrity{Check: events.IntegrityCheckHooksDisabled, Reason: events.IntegrityReasonSetting, AgentProduct: w.agent.Agent, Tier: w.tier,
		Path:   redact.Redact(w.path, redact.Context{Home: d.cfg.Env.Home}),
		Detail: fmt.Sprintf("%s in this file turns off %s's hooks, so Privometry neither sees nor decides what it does.", setting, w.agent.DisplayName)}
	if sha != "" {
		in.ObservedSHA256 = sha
	}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"integrity.path": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear}}
	d.cfg.Logger.Warn("agent hooks turned off", "agent", w.agent.Agent, "path", w.path)
	return d.appendEvent(ev, w.path)
}
