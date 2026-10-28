// Package guard installs and removes Privometry's hook in each coding agent's
// config, and reports whether it is in place. Changes are computed first, so
// callers can show them before writing.
package guard

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/platform"
)

// Options say where the hook lives and what is installed.
type Options struct {
	Env          platform.Env
	HookCommand  string // absolute path of privometry-hook
	AgentVersion string // detected agent version; "" if unknown
	Root         string // prefixes paths, for tests
	// File, when set, is the hooks file to edit instead of the agent's
	// user-level one: scripts/hook-recorder writes a throwaway project's.
	File string
	// Project, when set, is a project folder whose project-level settings
	// can also turn the agent's hooks off (Check).
	Project string
}

// Change is a computed edit to one agent's config file.
type Change struct {
	Agent      string
	Path       string // as configured, without Root
	real       string
	Before     []byte // nil when the file does not exist
	After      []byte
	FailClosed bool     // whether a fail-closed setting was added
	Events     []string // events registered

	// TrustInstructions is set when the agent runs new hooks only after the
	// user approves them (Codex).
	TrustInstructions string
	// Warnings explain settings that would keep the hook from running.
	Warnings []string
}

// Changed reports whether applying would modify the file.
func (c *Change) Changed() bool { return !bytes.Equal(c.Before, c.After) }

// Apply writes the change. The first time Privometry edits a file it keeps a copy
// at <file>.privometry-backup; the new content replaces the file atomically with
// the same permissions.
func (c *Change) Apply() error {
	if !c.Changed() {
		return nil
	}
	if c.After == nil {
		return os.Remove(c.real)
	}
	mode := fs.FileMode(0o600)
	if c.Before != nil {
		info, err := os.Stat(c.real)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
		backup := c.real + ".privometry-backup"
		if _, err := os.Stat(backup); errors.Is(err, fs.ErrNotExist) {
			if err := os.WriteFile(backup, c.Before, mode); err != nil {
				return fmt.Errorf("backup: %w", err)
			}
		}
	} else if err := os.MkdirAll(filepath.Dir(c.real), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.real), "."+filepath.Base(c.real)+".privometry-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(c.After); err != nil {
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
	return os.Rename(tmp.Name(), c.real)
}

// ErrUnsupported is returned for agents whose registration format guard does
// not write yet.
var ErrUnsupported = errors.New("guard: installing hooks for this agent is not supported yet")

func settingsPath(a registry.Adapter, opts Options) (string, string, error) {
	if opts.File != "" {
		return opts.File, filepath.Join(opts.Root, opts.File), nil
	}
	paths, err := a.Paths(a.Hooks.Install.Free.Paths, opts.Env, "")
	if err != nil {
		return "", "", err
	}
	if len(paths) == 0 {
		return "", "", fmt.Errorf("guard: %s has no install path on %s", a.Agent, opts.Env.OS())
	}
	return paths[0], filepath.Join(opts.Root, paths[0]), nil
}

func load(realPath string) ([]byte, *object, error) {
	raw, err := os.ReadFile(realPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, newObject(), nil
	}
	if err != nil {
		return nil, nil, err
	}
	o, err := parseOrdered(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("guard: %s is not valid JSON, so Privometry will not edit it: %w", realPath, err)
	}
	return raw, o, nil
}

// layout reads and writes one registration format.
type layout interface {
	// remove deletes Privometry's entries and returns how many it removed.
	remove(doc *object) int
	// add registers one command for an event.
	add(doc *object, ev registry.HookEvent, entry *object)
	// find returns Privometry's entry for an event, or nil.
	find(doc *object, event string) *object
	// empty reports whether the document holds nothing but what Privometry added.
	cleanup(doc *object)
}

func layoutFor(a registry.Adapter) (layout, error) {
	switch a.Hooks.Registration {
	case registry.HooksRegistrationClaudeSettings, registry.HooksRegistrationCodexHooks, registry.HooksRegistrationGeminiSettings:
		return groupedLayout{}, nil
	case registry.HooksRegistrationCursorHooks, registry.HooksRegistrationCopilotHooks:
		return flatLayout{}, nil
	case registry.HooksRegistrationAntigravityHooks:
		return namedLayout{}, nil
	}
	return nil, fmt.Errorf("%w (%s)", ErrUnsupported, a.Agent)
}

// Install computes the edit that registers privometry-hook for every hook event in
// the agent's definition, replacing any earlier Privometry entries.
func Install(a registry.Adapter, opts Options) (*Change, error) {
	lay, err := layoutFor(a)
	if err != nil {
		return nil, err
	}
	path, realPath, err := settingsPath(a, opts)
	if err != nil {
		return nil, err
	}
	before, doc, err := load(realPath)
	if err != nil {
		return nil, err
	}
	lay.remove(doc)

	c := &Change{Agent: string(a.Agent), Path: path, real: realPath, Before: before}
	fc := a.Hooks.FailClosedOption
	failClosed := fc != nil && (fc.MinVersion == "" || opts.AgentVersion != "" && atLeast(opts.AgentVersion, fc.MinVersion))
	for _, ev := range a.Hooks.Events {
		entry := hookEntry(a, opts, commandPath(opts)+" "+string(a.Agent)+" "+ev.Name)
		timeout := a.Hooks.TimeoutSeconds
		if ev.TimeoutSeconds != nil {
			timeout = ev.TimeoutSeconds
		}
		if timeout != nil {
			switch a.Hooks.Registration {
			case registry.HooksRegistrationGeminiSettings:
				entry.set("timeout", *timeout*1000) // milliseconds
			case registry.HooksRegistrationCopilotHooks:
				entry.set("timeoutSec", *timeout)
			default:
				entry.set("timeout", *timeout)
			}
		}
		if failClosed && decisionRole(ev.Role) {
			entry.set(fc.Key, fc.Value)
			c.FailClosed = true
		}
		lay.add(doc, ev, entry)
		c.Events = append(c.Events, ev.Name)
	}
	if t := a.Hooks.Trust; t != nil && t.Required {
		c.TrustInstructions = t.Instructions
	}
	c.Warnings = warnings(a, opts)
	c.After = encode(doc)
	return c, nil
}

// hookEntry is one registration of the hook command in the agent's format.
func hookEntry(a registry.Adapter, opts Options, cmd string) *object {
	entry := newObject()
	switch a.Hooks.Registration {
	case registry.HooksRegistrationCursorHooks:
		entry.set("command", cmd)
	case registry.HooksRegistrationCopilotHooks:
		// Copilot runs "bash" on macOS and Linux and "powershell" on Windows,
		// where a quoted program path needs the call operator.
		entry.set("type", "command")
		if opts.Env.GOOS == "windows" {
			entry.set("powershell", "& "+cmd)
		} else {
			entry.set("bash", cmd)
		}
	case registry.HooksRegistrationGeminiSettings:
		entry.set("name", "privometry")
		entry.set("type", "command")
		entry.set("command", cmd)
	default:
		entry.set("type", "command")
		entry.set("command", cmd)
	}
	return entry
}

// entryCommand is the command an entry runs, from whichever key the agent
// uses for it.
func entryCommand(entry *object) string {
	for _, key := range []string{"command", "bash", "powershell"} {
		if cmd, _ := entry.get(key).(string); cmd != "" {
			return strings.TrimPrefix(cmd, "& ")
		}
	}
	return ""
}

// Uninstall computes the edit that removes every Privometry hook entry.
func Uninstall(a registry.Adapter, opts Options) (*Change, error) {
	lay, err := layoutFor(a)
	if err != nil {
		return nil, err
	}
	path, realPath, err := settingsPath(a, opts)
	if err != nil {
		return nil, err
	}
	before, doc, err := load(realPath)
	if err != nil {
		return nil, err
	}
	c := &Change{Agent: string(a.Agent), Path: path, real: realPath, Before: before, After: before}
	if before == nil || lay.remove(doc) == 0 {
		return c, nil
	}
	lay.cleanup(doc)
	c.After = encode(doc)
	if a.Hooks.Registration == registry.HooksRegistrationCopilotHooks && len(doc.keys) == 0 {
		c.After = nil // Privometry's own hooks file: remove it rather than leave {}
	}
	return c, nil
}

// Status is whether Privometry's hook is in place for one agent.
type Status struct {
	Agent   string   `json:"agent"`
	Path    string   `json:"path"`
	State   string   `json:"state"` // installed, partial, stale, disabled, missing, unsupported
	Missing []string `json:"missing,omitempty"`
	// DisabledBy is the config file that turns the agent's hooks off, when
	// State is disabled because of a setting.
	DisabledBy    string `json:"disabled_by,omitempty"`
	FailClosed    bool   `json:"fail_closed"`
	TrustRequired bool   `json:"trust_required,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// Check reports the hook's state: installed when every event is registered
// with this privometry-hook, stale when entries point at another binary, and
// disabled when entries are there but a setting turns the agent's hooks off
// or Privometry's own entry is turned off.
func Check(a registry.Adapter, opts Options) Status {
	s := Status{Agent: string(a.Agent)}
	lay, err := layoutFor(a)
	if err != nil {
		s.State = "unsupported"
		return s
	}
	path, realPath, err := settingsPath(a, opts)
	s.Path = path
	if err != nil {
		s.State, s.Detail = "missing", err.Error()
		return s
	}
	_, doc, err := load(realPath)
	if err != nil {
		s.State, s.Detail = "missing", err.Error()
		return s
	}
	found, stale := 0, false
	for _, ev := range a.Hooks.Events {
		entry := lay.find(doc, ev.Name)
		if entry == nil {
			s.Missing = append(s.Missing, ev.Name)
			continue
		}
		found++
		cmd := entryCommand(entry)
		if opts.HookCommand != "" && !strings.HasPrefix(cmd, commandPath(opts)+" ") {
			stale = true
		}
		if fc := a.Hooks.FailClosedOption; fc != nil && decisionRole(ev.Role) && entry.get(fc.Key) != nil {
			s.FailClosed = true
		}
	}
	switch {
	case found == 0:
		s.State = "missing"
	case stale:
		s.State, s.Detail = "stale", "hook entries point at a different privometry-hook; run privometry guard install"
	case len(s.Missing) > 0:
		s.State = "partial"
	default:
		s.State = "installed"
	}
	if found > 0 {
		if ownEntryOff(a, doc) {
			s.State, s.Detail = "disabled", fmt.Sprintf(`Privometry's hook is turned off ("enabled": false) in %s; run privometry guard install`, path)
		} else if dis := Disabled(a, opts, opts.Project); dis != nil {
			s.State, s.DisabledBy = "disabled", dis.Path
			s.Detail = fmt.Sprintf("%s in %s turns off all of %s's hooks, Privometry's included; remove it", dis.Setting, dis.Path, a.DisplayName)
		}
	}
	if t := a.Hooks.Trust; t != nil && t.Required && found > 0 {
		s.TrustRequired = true
		if s.Detail == "" {
			s.Detail = t.Instructions
		}
	}
	return s
}

// Installed reports whether any Privometry hook is registered for the agent's
// decision events. The daemon uses it to skip calls another agent imports.
func Installed(a registry.Adapter, opts Options) bool {
	lay, err := layoutFor(a)
	if err != nil {
		return false
	}
	_, realPath, err := settingsPath(a, opts)
	if err != nil {
		return false
	}
	_, doc, err := load(realPath)
	if err != nil {
		return false
	}
	for _, ev := range a.Hooks.Events {
		if decisionRole(ev.Role) && lay.find(doc, ev.Name) != nil {
			return true
		}
	}
	return false
}

// groupedLayout is Claude Code's, Codex's and Gemini CLI's shape:
// {"hooks": {"<Event>": [{"matcher": "...", "hooks": [{"type": "command", ...}]}]}}.
type groupedLayout struct{}

func (groupedLayout) remove(doc *object) int {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return 0
	}
	return removePrivometry(hooks)
}

func (groupedLayout) add(doc *object, ev registry.HookEvent, entry *object) {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		hooks = newObject()
		doc.set("hooks", hooks)
	}
	group := newObject()
	if ev.Matcher != "" {
		group.set("matcher", ev.Matcher)
	}
	group.set("hooks", []any{entry})
	list, _ := hooks.get(ev.Name).([]any)
	hooks.set(ev.Name, append(list, group))
}

func (groupedLayout) find(doc *object, event string) *object {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return nil
	}
	groups, _ := hooks.get(event).([]any)
	for _, g := range groups {
		group, _ := g.(*object)
		if group == nil {
			continue
		}
		entries, _ := group.get("hooks").([]any)
		for _, e := range entries {
			if entry, _ := e.(*object); entry != nil {
				if isPrivometry(entryCommand(entry)) {
					return entry
				}
			}
		}
	}
	return nil
}

func (groupedLayout) cleanup(doc *object) {
	if hooks, ok := doc.get("hooks").(*object); ok && len(hooks.keys) == 0 {
		doc.del("hooks")
	}
}

// flatLayout is Cursor's and Copilot CLI's shape:
// {"version": 1, "hooks": {"<event>": [{"command": "...", "matcher": "..."}]}}
// (Copilot names the command "bash" or "powershell").
type flatLayout struct{}

func (flatLayout) remove(doc *object) int {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return 0
	}
	removed := 0
	for _, event := range append([]string{}, hooks.keys...) {
		entries, ok := hooks.get(event).([]any)
		if !ok {
			continue
		}
		var keep []any
		for _, e := range entries {
			if entry, _ := e.(*object); entry != nil {
				if isPrivometry(entryCommand(entry)) {
					removed++
					continue
				}
			}
			keep = append(keep, e)
		}
		if len(keep) == 0 {
			hooks.del(event)
		} else if len(keep) != len(entries) {
			hooks.set(event, keep)
		}
	}
	return removed
}

func (flatLayout) add(doc *object, ev registry.HookEvent, entry *object) {
	if doc.get("version") == nil {
		doc.keys = append([]string{"version"}, doc.keys...)
		doc.vals["version"] = 1
	}
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		hooks = newObject()
		doc.set("hooks", hooks)
	}
	if ev.Matcher != "" {
		entry.set("matcher", ev.Matcher)
	}
	list, _ := hooks.get(ev.Name).([]any)
	hooks.set(ev.Name, append(list, entry))
}

func (flatLayout) find(doc *object, event string) *object {
	hooks, _ := doc.get("hooks").(*object)
	if hooks == nil {
		return nil
	}
	entries, _ := hooks.get(event).([]any)
	for _, e := range entries {
		if entry, _ := e.(*object); entry != nil {
			if isPrivometry(entryCommand(entry)) {
				return entry
			}
		}
	}
	return nil
}

func (flatLayout) cleanup(doc *object) {
	if hooks, ok := doc.get("hooks").(*object); ok && len(hooks.keys) == 0 {
		doc.del("hooks")
		if len(doc.keys) == 1 && doc.get("version") != nil {
			doc.del("version") // the file held only what Privometry added
		}
	}
}

// namedLayout is Antigravity's shape: each top-level key names a hook and holds
// its events; Privometry's hook is named privometry, and other hooks are left
// alone. PreToolUse and PostToolUse take matcher groups, other events a list.
// {"privometry": {"PreToolUse": [{"matcher": "*", "hooks": [{...}]}], "SessionStart": [{...}]}}.
type namedLayout struct{}

const hookName = "privometry"

func namedGrouped(event string) bool { return event == "PreToolUse" || event == "PostToolUse" }

func (namedLayout) remove(doc *object) int {
	ours, _ := doc.get(hookName).(*object)
	if ours == nil {
		return 0
	}
	doc.del(hookName)
	return max(1, len(ours.keys))
}

func (namedLayout) add(doc *object, ev registry.HookEvent, entry *object) {
	ours, _ := doc.get(hookName).(*object)
	if ours == nil {
		ours = newObject()
		doc.set(hookName, ours)
	}
	list, _ := ours.get(ev.Name).([]any)
	if !namedGrouped(ev.Name) {
		ours.set(ev.Name, append(list, entry))
		return
	}
	group := newObject()
	if ev.Matcher != "" {
		group.set("matcher", ev.Matcher)
	}
	group.set("hooks", []any{entry})
	ours.set(ev.Name, append(list, group))
}

func (namedLayout) find(doc *object, event string) *object {
	ours, _ := doc.get(hookName).(*object)
	if ours == nil {
		return nil
	}
	items, _ := ours.get(event).([]any)
	for _, it := range items {
		o, _ := it.(*object)
		if o == nil {
			continue
		}
		entries := []any{o}
		if namedGrouped(event) {
			entries, _ = o.get("hooks").([]any)
		}
		for _, e := range entries {
			if entry, _ := e.(*object); entry != nil && isPrivometry(entryCommand(entry)) {
				return entry
			}
		}
	}
	return nil
}

func (namedLayout) cleanup(*object) {}

// warnings explains settings that would stop the hook from running.
func warnings(a registry.Adapter, opts Options) []string {
	if dis := Disabled(a, opts, ""); dis != nil {
		return []string{fmt.Sprintf("hooks are turned off in %s (%s); %s will not run Privometry until you remove that setting",
			dis.Path, dis.Setting, a.DisplayName)}
	}
	return nil
}

func decisionRole(r registry.HookEventRole) bool {
	switch r {
	case registry.HookEventRolePreTool, registry.HookEventRolePreShell, registry.HookEventRolePreMCP, registry.HookEventRolePreFileRead:
		return true
	}
	return false
}

// isPrivometry reports whether a hook command runs privometry-hook.
func isPrivometry(cmd string) bool {
	first := strings.Trim(strings.Fields(cmd + " ")[0], `"'`)
	if strings.HasPrefix(cmd, "'") || strings.HasPrefix(cmd, `"`) {
		q := cmd[0]
		if end := strings.IndexByte(cmd[1:], q); end >= 0 {
			first = cmd[1 : end+1]
		}
	}
	base := first[strings.LastIndexAny(first, `/\`)+1:] // either separator, whatever OS wrote it
	return base == "privometry-hook" || base == "privometry-hook.exe"
}

// removePrivometry deletes Privometry's entries from a Claude-style hooks map and
// prunes groups and events left empty. It returns how many it removed.
func removePrivometry(hooks *object) int {
	removed := 0
	for _, event := range append([]string{}, hooks.keys...) {
		groups, ok := hooks.get(event).([]any)
		if !ok {
			continue
		}
		var keepGroups []any
		for _, g := range groups {
			group, ok := g.(*object)
			if !ok {
				keepGroups = append(keepGroups, g)
				continue
			}
			entries, _ := group.get("hooks").([]any)
			var keep []any
			for _, e := range entries {
				if entry, ok := e.(*object); ok && isPrivometry(entryCommand(entry)) {
					removed++
					continue
				}
				keep = append(keep, e)
			}
			if len(keep) == 0 && len(entries) > 0 {
				continue
			}
			if len(keep) != len(entries) {
				group.set("hooks", keep)
			}
			keepGroups = append(keepGroups, group)
		}
		if len(keepGroups) == 0 {
			hooks.del(event)
		} else {
			hooks.set(event, keepGroups)
		}
	}
	return removed
}

// commandPath is the hook path as it starts a hook command. On Windows it
// is always in double quotes: agents run hooks through cmd.exe or Git Bash,
// both take a double-quoted path, and Bash would eat unquoted backslashes.
func commandPath(opts Options) string {
	if opts.Env.GOOS == "windows" {
		return `"` + opts.HookCommand + `"`
	}
	return shellQuote(opts.HookCommand)
}

// shellQuote quotes a path for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"$`\\;&|<>()*?[]{}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func atLeast(version, minimum string) bool {
	if minimum == "" {
		return true
	}
	a, b := registry.ParseVersion(version), registry.ParseVersion(minimum)
	if a == "" || b == "" {
		return false
	}
	return (&registry.Adapter{Versions: ">=" + b}).Supports(a)
}
