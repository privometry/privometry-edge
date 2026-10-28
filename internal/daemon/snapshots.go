package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/content"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/events"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/timeline"
)

// Memory file snapshots (PRD SCAN-14): the daemon keeps every version of a
// memory or instruction file it sees, so a person can go back to one that
// was known to be good. Snapshots stay on this machine.
const (
	// maxSnapshot is the largest file kept; bigger ones are hashed and
	// scanned but cannot be restored.
	maxSnapshot = 1 << 20
	// keepVersions and keepFor bound the history: per file, the newest
	// keepVersions versions and every version from the last keepFor.
	keepVersions = 20
	keepFor      = 90 * 24 * time.Hour
)

// Who changed a version, in memory_versions.changed_by.
const (
	changedFirst   = "first" // the first version the daemon saw
	changedRestore = "restore"
)

// snapshot records a version of m. findings is how many content findings its
// scan recorded; raw is nil when the file is gone.
func (d *Daemon) snapshot(m memoryFile, raw []byte, sum, by string, findings int, restoredFrom int64) {
	if len(raw) > maxSnapshot {
		d.cfg.Logger.Info("memory file too large to snapshot", "path", m.path, "bytes", len(raw))
		return
	}
	v := timeline.MemoryVersion{Path: m.path, Agent: string(m.agent.Agent), Tier: string(m.tier), SHA256: sum, Size: int64(len(raw)),
		ObservedAt: d.cfg.Now(), ChangedBy: by, Findings: findings, RestoredFrom: restoredFrom}
	if _, err := d.store.AddMemoryVersion(v, raw); err != nil {
		d.cfg.Logger.Warn("could not snapshot memory file", "path", m.path, "err", err)
	}
}

// MemoryQuery is the argument of the memory IPC operation.
type MemoryQuery struct {
	Action   string `json:"action"` // list, history, show or restore
	Path     string `json:"path,omitempty"`
	Version  int64  `json:"version,omitempty"`
	LastGood bool   `json:"last_good,omitempty"` // restore: the newest version that scans clean now
	DryRun   bool   `json:"dry_run,omitempty"`   // restore: say which version, change nothing
}

// MemoryFileState is one watched file in a memory list.
type MemoryFileState struct {
	timeline.MemoryVersion
	Display  string `json:"display"`
	Versions int    `json:"versions"`
	// Current is the file's digest now, "" when it is gone; it differs from
	// SHA256 when the file changed since the daemon last looked.
	Current string `json:"current"`
}

// MemoryVersionContent is a version with its content, for show.
type MemoryVersionContent struct {
	timeline.MemoryVersion
	Content string `json:"content"`
	Clean   bool   `json:"clean"` // no content findings with today's detectors
}

// RestoreResult says what a restore did.
type RestoreResult struct {
	Path     string `json:"path"`
	From     int64  `json:"from"`              // the version restored
	Version  int64  `json:"version,omitempty"` // the new version it became
	Deleted  bool   `json:"deleted,omitempty"` // the restored version is "no file"
	Previous int64  `json:"previous,omitempty"`
}

// ErrNoGoodVersion means no earlier version scans clean.
var ErrNoGoodVersion = errors.New("no earlier version of this file scans clean")

func (d *Daemon) memoryOp(q MemoryQuery) (any, error) {
	switch q.Action {
	case "list":
		latest, counts, err := d.store.LatestMemoryVersions()
		if err != nil {
			return nil, err
		}
		out := []MemoryFileState{}
		for _, v := range latest {
			cur := ""
			if raw, err := os.ReadFile(v.Path); err == nil {
				cur = digest(raw)
			}
			out = append(out, MemoryFileState{MemoryVersion: v, Display: platform.DisplayPath(v.Path, d.cfg.Env.Home, ""),
				Versions: counts[v.Path], Current: cur})
		}
		return out, nil
	case "history":
		vs, err := d.store.MemoryVersions(q.Path)
		if err != nil {
			return nil, err
		}
		if vs == nil {
			return nil, fmt.Errorf("no versions of %s: it is not a memory file Privometry has seen", q.Path)
		}
		return vs, nil
	case "show":
		v, raw, err := d.store.MemoryVersion(q.Version)
		if err != nil {
			return nil, fmt.Errorf("version %d: %w", q.Version, err)
		}
		return MemoryVersionContent{MemoryVersion: v, Content: string(raw), Clean: raw != nil && d.cleanNow(v, raw)}, nil
	case "restore":
		return d.restoreMemory(q)
	}
	return nil, fmt.Errorf("unknown memory action %q", q.Action)
}

// cleanNow scans a version's content with today's detectors and allowlists.
func (d *Daemon) cleanNow(v timeline.MemoryVersion, raw []byte) bool {
	text := string(raw)
	if len(text) > maxMemoryScan {
		text = text[:maxMemoryScan]
	}
	fs := d.content.Scan(content.SourceMemoryFile, text)
	repo := ""
	if v.Tier == string(contract.ConfigTierProject) {
		repo = platform.GitRoot(filepath.Dir(v.Path))
	}
	fs, _ = d.allowlistFor(repo).Filter(fs, text, platform.DisplayPath(v.Path, d.cfg.Env.Home, repo), d.cfg.Now())
	return len(fs) == 0
}

// restoreMemory writes an earlier version back. The current content is kept
// as a version first, so a restore never loses anything; the restore itself
// is recorded as a person's change with the version it came from.
func (d *Daemon) restoreMemory(q MemoryQuery) (RestoreResult, error) {
	d.memMu.Lock()
	defer d.memMu.Unlock()
	vs, err := d.store.MemoryVersions(q.Path)
	if err != nil {
		return RestoreResult{}, err
	}
	if len(vs) == 0 {
		return RestoreResult{}, fmt.Errorf("no versions of %s: it is not a memory file Privometry has seen", q.Path)
	}
	current, err := os.ReadFile(q.Path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return RestoreResult{}, err
	}
	curSum := ""
	if err == nil {
		curSum = digest(current)
	}

	var target timeline.MemoryVersion
	var raw []byte
	switch {
	case q.LastGood:
		for _, v := range vs {
			if v.SHA256 == "" || v.SHA256 == curSum {
				continue
			}
			_, c, err := d.store.MemoryVersion(v.ID)
			if err == nil && d.cleanNow(v, c) {
				target, raw = v, c
				break
			}
		}
		if target.ID == 0 {
			return RestoreResult{}, ErrNoGoodVersion
		}
	default:
		found := false
		for _, v := range vs {
			if v.ID == q.Version {
				found = true
				break
			}
		}
		if !found {
			return RestoreResult{}, fmt.Errorf("version %d is not a version of %s", q.Version, q.Path)
		}
		if target, raw, err = d.store.MemoryVersion(q.Version); err != nil {
			return RestoreResult{}, err
		}
	}
	res := RestoreResult{Path: q.Path, From: target.ID, Deleted: target.SHA256 == ""}
	if target.SHA256 == curSum {
		return res, fmt.Errorf("%s already matches version %d", q.Path, target.ID)
	}
	if q.DryRun {
		return res, nil
	}

	m := memoryFile{agent: d.adapterOr(target.Agent), path: q.Path, tier: contract.ConfigTier(target.Tier), kind: d.memoryKind(q.Path)}
	if vs[0].SHA256 != curSum {
		// Changed since the daemon last looked: keep that content first.
		by := string(d.attribute(q.Path))
		d.snapshot(m, current, curSum, by, 0, 0)
		if latest, err := d.store.MemoryVersions(q.Path); err == nil && len(latest) > 0 {
			res.Previous = latest[0].ID
		}
	}

	if res.Deleted {
		if err := os.Remove(q.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, err
		}
	} else if err := writeAtomic(q.Path, raw); err != nil {
		return res, err
	}

	findings := 0
	if !res.Deleted {
		findings = d.scanAtRest(m, raw)
	}
	d.snapshot(m, raw, target.SHA256, changedRestore, findings, target.ID)
	if latest, err := d.store.MemoryVersions(q.Path); err == nil && len(latest) > 0 {
		res.Version = latest[0].ID
	}
	h := timeline.ConfigHash{Path: q.Path, Tier: target.Tier, Agent: target.Agent, SHA256: target.SHA256, Kind: "memory",
		ChangedBy: string(events.ConfigChangedByPerson)}
	if err := d.store.SetConfigHash(h, d.cfg.Now()); err != nil {
		return res, err
	}
	w := watched{agent: m.agent, path: m.path, tier: m.tier, holds: []events.ConfigHold{memoryHolds[m.kind]}}
	ev := d.configChangeEvent(w, curSum, target.SHA256, events.ConfigChangedByPerson)
	ev.Ext = map[string]any{"x_privometry_restored_from_version": target.ID}
	if err := d.appendEvent(ev, q.Path); err != nil {
		return res, err
	}
	return res, nil
}

// adapterOr returns the adapter of a stored agent name, or the first one.
func (d *Daemon) adapterOr(agent string) registry.Adapter {
	if a, ok := d.cfg.Registry.Get(contract.AgentProduct(agent)); ok {
		return a
	}
	return d.cfg.Registry.All()[0]
}

// memoryKind is the kind of a watched path, instructions when unknown.
func (d *Daemon) memoryKind(path string) registry.AdapterMemoryFileKind {
	for _, m := range d.memoryList() {
		if m.path == path {
			return m.kind
		}
	}
	return registry.AdapterMemoryFileKindInstructions
}

// writeAtomic replaces a file, keeping its mode (0644 for a new file).
func writeAtomic(path string, raw []byte) error {
	mode := fs.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // restores an agent config folder, which agents create as 0755
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".privometry-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
