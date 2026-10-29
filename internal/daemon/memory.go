package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/timeline"
)

const (
	// agentWriteWindow is how long after an agent's write a change to the
	// same memory file is attributed to the agent.
	agentWriteWindow = 2 * time.Minute
	// rootTTL is how long a workspace stays watched after its last hook call.
	rootTTL = 24 * time.Hour
	// maxMemoryScan bounds how much of one memory file is scanned.
	maxMemoryScan = 1 << 20
	// memoryRescanInterval reapplies detector packs to unchanged instruction
	// files. The last scan time is persisted with the file hash.
	memoryRescanInterval = 24 * time.Hour
)

// memoryFile is one memory or instruction file the daemon watches.
type memoryFile struct {
	agent registry.Adapter
	path  string
	tier  contract.ConfigTier
	kind  registry.AdapterMemoryFileKind
}

// noteRoot remembers a workspace an agent works in, so its project memory
// files are watched.
func (d *Daemon) noteRoot(root string) {
	if root == "" {
		return
	}
	d.mu.Lock()
	d.roots[root] = d.cfg.Now()
	d.mu.Unlock()
}

// recentRoots returns the workspaces agents worked in recently, sorted, and
// forgets older ones.
func (d *Daemon) recentRoots() []string {
	d.mu.Lock()
	var roots []string
	for r, at := range d.roots {
		if d.cfg.Now().Sub(at) < rootTTL {
			roots = append(roots, r)
		} else {
			delete(d.roots, r)
		}
	}
	d.mu.Unlock()
	sort.Strings(roots)
	return roots
}

// noteAgentWrite records that an agent is about to write a memory file.
func (d *Daemon) noteAgentWrite(path string) {
	d.mu.Lock()
	d.agentWrites[path] = d.cfg.Now()
	d.mu.Unlock()
}

// noteMemoryWrites records each memory file the actions write, for
// attribution, using the same extractors as the decision.
func (d *Daemon) noteMemoryWrites(actions []intent.Action, ctx intent.Context) {
	for _, a := range actions {
		for _, r := range intent.Extract(a, ctx) {
			if r.Facts.TargetClass == "memory_file" && r.Facts.TargetPath != "" {
				d.noteAgentWrite(r.Facts.TargetPath)
			}
		}
	}
}

// memoryList returns every memory and instruction file to watch: user and
// managed files, and project files at the root of each recent workspace.
// Nested project files (a CLAUDE.md in a subfolder) are checked when an
// agent writes them, not by the watcher.
func (d *Daemon) memoryList() []memoryFile {
	roots := d.recentRoots()
	var out []memoryFile
	seen := map[string]bool{}
	for _, a := range d.cfg.Registry.All() {
		for _, m := range a.MemoryFiles {
			bases := []string{""}
			if m.Tier == contract.ConfigTierProject {
				bases = roots
			}
			for _, root := range bases {
				paths, err := a.Paths(m.Paths, d.cfg.Env, root)
				if err != nil {
					continue
				}
				for _, pattern := range paths {
					matches, _ := filepath.Glob(pattern)
					if len(matches) == 0 && !containsGlob(pattern) {
						matches = []string{pattern} // watch for it to appear
					}
					for _, p := range matches {
						if !seen[p] {
							seen[p] = true
							out = append(out, memoryFile{agent: a, path: p, tier: m.Tier, kind: m.Kind})
						}
					}
				}
			}
		}
	}
	return out
}

// CheckMemory hashes every watched memory file. A file seen for the first
// time is scanned; a changed one records a config_change event saying who
// changed it and is scanned again. Unchanged files are rescanned daily so new
// detector packs apply without waiting for an edit. It returns how many events
// it recorded.
func (d *Daemon) CheckMemory() (int, error) {
	d.memMu.Lock()
	defer d.memMu.Unlock()
	prev, err := d.store.ConfigHashes()
	if err != nil {
		return 0, err
	}
	n := 0
	seen := map[string]bool{}
	for _, m := range d.memoryList() {
		seen[m.path] = true
		k, err := d.checkMemoryFile(m, prev[m.path], prev[m.path].Path != "", "")
		if err != nil {
			return n, err
		}
		n += k
	}
	// Project roots leave the active watcher after rootTTL, and nested files
	// can be learned only through InstructionsLoaded. Keep rescanning their
	// persisted paths when unchanged; changed paths will be handled when that
	// workspace or file next becomes active.
	now := d.cfg.Now()
	for path, old := range prev {
		if seen[path] || old.Kind != "memory" || !scanDue(now, old.ObservedAt) {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil || digest(raw) != old.SHA256 {
			continue
		}
		a, ok := d.cfg.Registry.Get(contract.AgentProduct(old.Agent))
		if !ok {
			continue
		}
		if err := d.store.SetConfigHash(old, now); err != nil {
			return n, err
		}
		n += d.scanAtRest(memoryFile{agent: a, path: path, tier: contract.ConfigTier(old.Tier), kind: registry.AdapterMemoryFileKindInstructions}, raw)
	}
	return n, nil
}

func scanDue(now, observed time.Time) bool {
	return observed.IsZero() || !now.Before(observed.Add(memoryRescanInterval))
}

// checkMemoryFile compares one file with its last state. by forces the
// attribution, for a write an agent hook just reported.
func (d *Daemon) checkMemoryFile(m memoryFile, old timeline.ConfigHash, known bool, by events.ConfigChangedBy) (int, error) {
	now := d.cfg.Now()
	raw, err := os.ReadFile(m.path)
	sum := ""
	if err == nil {
		sum = digest(raw)
	}
	unchanged := known && old.SHA256 == sum
	rescanDue := unchanged && scanDue(now, old.ObservedAt)
	if unchanged && !rescanDue {
		return 0, nil
	}
	n := 0
	h := timeline.ConfigHash{Path: m.path, Tier: string(m.tier), Agent: string(m.agent.Agent), SHA256: sum,
		Kind: "memory", ChangedBy: old.ChangedBy}
	snapshotAs := ""
	if known && !unchanged {
		if by == "" {
			by = d.attribute(m.path)
		}
		h.ChangedBy = string(by)
		if err := d.recordMemoryChange(m, old.SHA256, sum, by); err != nil {
			return n, err
		}
		n++
		snapshotAs = string(by)
	} else if !known && sum != "" {
		snapshotAs = changedFirst
	}
	if err := d.store.SetConfigHash(h, now); err != nil {
		return n, err
	}
	findings := 0
	if sum != "" {
		findings = d.scanAtRest(m, raw)
		n += findings
	}
	if snapshotAs != "" {
		if sum == "" {
			raw = nil
		}
		d.snapshot(m, raw, sum, snapshotAs, findings, 0)
	}
	return n, nil
}

// attribute says whether a change was the agent's: an agent wrote the file
// through a hooked tool shortly before.
func (d *Daemon) attribute(path string) events.ConfigChangedBy {
	d.mu.Lock()
	at, ok := d.agentWrites[path]
	d.mu.Unlock()
	if ok && d.cfg.Now().Sub(at) < agentWriteWindow {
		return events.ConfigChangedByAgent
	}
	return events.ConfigChangedByPerson
}

var memoryHolds = map[registry.AdapterMemoryFileKind]events.ConfigHold{
	registry.AdapterMemoryFileKindInstructions: events.ConfigHoldInstructions,
	registry.AdapterMemoryFileKindRules:        events.ConfigHoldRules,
	registry.AdapterMemoryFileKindMemory:       events.ConfigHoldMemory,
}

func (d *Daemon) recordMemoryChange(m memoryFile, before, after string, by events.ConfigChangedBy) error {
	w := watched{agent: m.agent, path: m.path, tier: m.tier, holds: []events.ConfigHold{memoryHolds[m.kind]}}
	return d.recordConfigChangeBy(w, before, after, by)
}

// scanAtRest scans a memory file's content and records each finding.
func (d *Daemon) scanAtRest(m memoryFile, raw []byte) int {
	text := string(raw)
	if len(text) > maxMemoryScan {
		text = text[:maxMemoryScan]
	}
	fs := d.content.Scan(content.SourceMemoryFile, text)
	repo := ""
	if m.tier == contract.ConfigTierProject {
		repo = platform.GitRoot(filepath.Dir(m.path))
	}
	fs, _ = d.allowlistFor(repo).Filter(fs, text, platform.DisplayPath(m.path, d.cfg.Env.Home, repo), d.cfg.Now())
	class, _ := (intent.Context{Home: d.cfg.Env.Home}).Classify(m.path)
	n := 0
	for i, f := range fs {
		if i == maxFindingEvents {
			break
		}
		line := int64(f.Line)
		cf := &events.ContentFinding{DetectorID: f.DetectorID, PackVersion: f.PackVersion, Category: events.ContentFindingCategory(f.Category),
			Severity: events.ContentFindingSeverity(f.Severity), Confidence: events.ContentFindingConfidence(f.Confidence),
			Source: events.ContentFindingSourceMemoryFile, ActionTaken: events.ContentFindingActionTakenNone,
			Location: &events.ContentFindingLocation{PathClass: contract.PathClass(class), PathHash: d.content.Hash(m.path), Line: &line,
				Tier: m.tier, AgentProduct: m.agent.Agent}}
		if f.Category == content.CategoryCredential {
			cf.SecretType, cf.Fingerprint = f.SecretType, f.Fingerprint
		}
		ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeContentFinding,
			OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, ContentFinding: cf,
			Redaction: map[string]contract.PrivacyLevel{"user.local_user": contract.PrivacyLevelClear},
			Ext:       findingExt(f)}
		if err := d.appendEvent(ev, fmt.Sprintf("%s:%d  %s", m.path, f.Line, f.Excerpt)); err != nil {
			d.cfg.Logger.Warn("could not record content finding", "err", err)
			continue
		}
		n++
	}
	return n
}

// memoryWritten handles an agent's finished write to a memory file: the
// change is the agent's, and the new content is scanned now rather than at
// the next watcher pass. Files the watcher does not list (nested ones) are
// covered here.
func (d *Daemon) memoryWritten(c call, path string) {
	m := memoryFile{agent: c.adapter, path: path, tier: contract.ConfigTierProject, kind: registry.AdapterMemoryFileKindInstructions}
	for _, x := range d.memoryList() {
		if x.path == path {
			m = x
			break
		}
	}
	d.background(func() {
		d.memMu.Lock()
		defer d.memMu.Unlock()
		prev, err := d.store.ConfigHashes()
		if err != nil {
			return
		}
		old, known := prev[path]
		if _, err := d.checkMemoryFile(m, old, known, events.ConfigChangedByAgent); err != nil {
			d.cfg.Logger.Warn("memory check failed", "path", path, "err", err)
		}
	})
}

// memoryTargets returns the memory files a finished write touched.
func (d *Daemon) memoryTargets(actions []intent.Action, sess *sessionInfo) []string {
	ctx := intent.Context{Cwd: sess.Cwd, Home: d.cfg.Env.Home, RepoRoot: sess.Root, TempDirs: []string{os.TempDir()}}
	var out []string
	for _, a := range actions {
		if a.Kind != "file_write" && a.Kind != "file_delete" {
			continue
		}
		for _, r := range intent.Extract(a, ctx) {
			if r.Facts.TargetClass == "memory_file" && r.Facts.TargetPath != "" {
				out = append(out, r.Facts.TargetPath)
			}
		}
	}
	return out
}

// instructionsLoaded handles Claude Code's observe-only InstructionsLoaded
// hook. It hashes and scans the exact instruction file before Claude proceeds,
// including nested CLAUDE.md and rule files that the periodic watcher cannot
// discover from the workspace root alone.
func (d *Daemon) instructionsLoaded(c call) error {
	sess, err := d.session(c)
	if err != nil {
		return err
	}
	p := strings.TrimSpace(c.str("file_path"))
	if p == "" {
		return nil
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(sess.Cwd, p)
	}
	p = filepath.Clean(p)

	tier := contract.ConfigTierProject
	switch strings.ToLower(c.str("memory_type")) {
	case "user":
		tier = contract.ConfigTierUser
	case "managed", "policy":
		tier = contract.ConfigTierManaged
	case "local", "project":
		tier = contract.ConfigTierProject
	}
	kind := registry.AdapterMemoryFileKindInstructions
	if strings.Contains(filepath.ToSlash(p), "/.claude/rules/") {
		kind = registry.AdapterMemoryFileKindRules
	}
	m := memoryFile{agent: c.adapter, path: p, tier: tier, kind: kind}
	d.memMu.Lock()
	defer d.memMu.Unlock()
	prev, err := d.store.ConfigHashes()
	if err != nil {
		return err
	}
	old, known := prev[p]
	_, err = d.checkMemoryFile(m, old, known, "")
	return err
}
