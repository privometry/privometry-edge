// Package discover finds coding agents on a machine or in a repo: whether each
// is installed and at which version, which config files exist at each tier,
// and the MCP servers, hooks and skills those files define. It reads files and
// runs each agent's version command; it never writes anything.
package discover

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/redact"
	"github.com/privometry/privometry-edge/internal/scanner/parsers"
)

// Options control one discovery run.
type Options struct {
	Env      platform.Env
	Machine  bool   // scan user and managed tiers and detect installed agents
	RepoRoot string // scan this repo's project tier; empty skips it

	// Root prefixes every absolute path read, so tests can point discovery at
	// a fixture tree. Reported paths never include it.
	Root string
	// LookPath finds an agent binary; nil means exec.LookPath.
	LookPath func(string) (string, error)
	// RunVersion runs a version command; nil runs it with a 3-second timeout.
	RunVersion func(argv []string) (string, error)
	// ListProcesses returns executable names for running processes. It is best
	// effort: discovery continues when the operating system refuses the query.
	ListProcesses func() ([]string, error)
}

// Agent is everything found for one coding agent.
type Agent struct {
	Product     contract.AgentProduct `json:"product"`
	Name        string                `json:"name"`
	Installed   bool                  `json:"installed"`
	Version     string                `json:"version,omitempty"`
	Supported   *bool                 `json:"supported,omitempty"`
	Evidence    []string              `json:"evidence"`
	Configs     []ConfigFile          `json:"configs"`
	MCPServers  []MCPServer           `json:"mcp_servers"`
	Hooks       []Hook                `json:"hooks"`
	Skills      []Skill               `json:"skills"`
	Plugins     []Plugin              `json:"plugins"`
	MemoryFiles []MemoryFile          `json:"memory_files"`
	VersionNote string                `json:"version_note,omitempty"`
}

// MemoryFile is one memory or instruction file that exists, such as
// CLAUDE.md or AGENTS.md. Its content is scanned, never reported.
type MemoryFile struct {
	Tier   contract.ConfigTier `json:"tier"`
	Kind   string              `json:"kind"` // instructions, rules or memory
	Path   string              `json:"path"`
	SHA256 string              `json:"sha256"`
	// RealPath is where the file was read.
	RealPath string `json:"-"`
}

// ConfigFile is one config file that exists. Doc holds its parsed content for
// posture checks and is never serialized.
type ConfigFile struct {
	Tier   contract.ConfigTier `json:"tier"`
	Path   string              `json:"path"`
	Format string              `json:"format"`
	Holds  []string            `json:"holds"`
	SHA256 string              `json:"sha256"`
	Error  string              `json:"error,omitempty"`
	Doc    any                 `json:"-"`
	// RealPath is where the file was read, for locating findings by line.
	RealPath string `json:"-"`
}

// MCPServer is one configured MCP server. Command and URL are redacted; env
// and header values are never kept, only their names.
type MCPServer struct {
	Name      string              `json:"name"`
	Tier      contract.ConfigTier `json:"tier"`
	Path      string              `json:"path"`
	Pointer   string              `json:"pointer"`
	Transport string              `json:"transport"`
	Command   string              `json:"command,omitempty"`
	URL       string              `json:"url,omitempty"`
	EnvNames  []string            `json:"env_names,omitempty"`
	Pinned    *bool               `json:"pinned,omitempty"`
	Package   string              `json:"package,omitempty"`
	// RawPointer addresses the server in the parsed document. Pointer is safe
	// to report and may abbreviate a home or repository path used as a map key.
	RawPointer string `json:"-"`
}

// Hook is one registered hook command, redacted.
type Hook struct {
	Tier       contract.ConfigTier `json:"tier"`
	Path       string              `json:"path"`
	Event      string              `json:"event"`
	Matcher    string              `json:"matcher,omitempty"`
	Command    string              `json:"command"`
	Privometry bool                `json:"privometry"`
}

// Skill is one skill file with its frontmatter name.
type Skill struct {
	Tier        contract.ConfigTier `json:"tier"`
	Path        string              `json:"path"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
}

// Plugin is one installed agent plugin. Installation paths and registry
// metadata are deliberately omitted from reports.
type Plugin struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Marketplace string              `json:"marketplace,omitempty"`
	Version     string              `json:"version,omitempty"`
	Scope       string              `json:"scope,omitempty"`
	Tier        contract.ConfigTier `json:"tier"`
	Path        string              `json:"path"`
}

// Run discovers every agent in reg.
func Run(reg *registry.Registry, opts Options) ([]Agent, error) {
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.RunVersion == nil {
		opts.RunVersion = runVersion
	}
	if opts.ListProcesses == nil {
		opts.ListProcesses = listProcesses
	}
	d := &discoverer{opts: opts, parsed: map[string]*ConfigFile{}, processes: map[string]bool{}}
	if opts.Machine {
		if names, err := opts.ListProcesses(); err == nil {
			for _, name := range names {
				if key := processKey(name); key != "" {
					d.processes[key] = true
					d.procPaths = append(d.procPaths, strings.ReplaceAll(strings.TrimSpace(name), `\`, "/"))
				}
			}
		}
	}
	var agents []Agent
	for _, a := range reg.All() {
		agent, err := d.agent(a)
		if err != nil {
			return nil, fmt.Errorf("discover %s: %w", a.Agent, err)
		}
		if agent.Installed || len(agent.Configs) > 0 || len(agent.MemoryFiles) > 0 {
			agents = append(agents, agent)
		}
	}
	return agents, nil
}

type discoverer struct {
	opts      Options
	parsed    map[string]*ConfigFile // by real path, so a file shared by tiers is parsed once
	dirs      []string               // the repo's folders, for nested memory files; walked once
	processes map[string]bool        // normalized executable names, read once per scan
	procPaths []string               // the same executables as listed, with / separators, for process_patterns
}

func (d *discoverer) wantTier(t contract.ConfigTier) bool {
	if t == contract.ConfigTierProject {
		return d.opts.RepoRoot != ""
	}
	return d.opts.Machine
}

func (d *discoverer) agent(a registry.Adapter) (Agent, error) {
	agent := Agent{Product: a.Agent, Name: a.DisplayName, Evidence: []string{}, Configs: []ConfigFile{},
		MCPServers: []MCPServer{}, Hooks: []Hook{}, Skills: []Skill{}, Plugins: []Plugin{}, MemoryFiles: []MemoryFile{}}
	if d.opts.Machine {
		d.detect(a, &agent)
	}

	for _, tier := range a.ConfigTiers {
		if !d.wantTier(tier.Tier) {
			continue
		}
		holds := make([]string, len(tier.Holds))
		for i, h := range tier.Holds {
			holds[i] = string(h)
		}
		files, err := d.files(a, tier.Paths)
		if err != nil {
			return agent, err
		}
		for _, f := range files {
			cf := d.read(f, string(tier.Format), tier.Tier, holds)
			agent.Configs = append(agent.Configs, *cf)
			if slices.Contains(holds, "hooks") && cf.Doc != nil {
				agent.Hooks = append(agent.Hooks, d.hooks(a.Hooks.Registration, cf)...)
			}
			if slices.Contains(holds, "skills") && cf.Doc != nil {
				fm := parsers.Map(cf.Doc)
				agent.Skills = append(agent.Skills, Skill{Tier: cf.Tier, Path: cf.Path,
					Name: parsers.String(fm["name"]), Description: parsers.String(fm["description"])})
			}
			if slices.Contains(holds, "plugins") && cf.Doc != nil {
				agent.Plugins = append(agent.Plugins, d.plugins(cf)...)
			}
		}
	}

	for _, src := range a.MCPSources {
		if !d.wantTier(src.Tier) {
			continue
		}
		files, err := d.files(a, src.Paths)
		if err != nil {
			return agent, err
		}
		for _, f := range files {
			cf := d.read(f, string(src.Format), src.Tier, []string{"mcp_servers"})
			if !slices.ContainsFunc(agent.Configs, func(c ConfigFile) bool { return c.Path == cf.Path }) {
				agent.Configs = append(agent.Configs, *cf)
			}
			agent.MCPServers = append(agent.MCPServers, d.mcpServers(cf, src.Pointer)...)
		}
	}

	for _, m := range a.MemoryFiles {
		if !d.wantTier(m.Tier) {
			continue
		}
		files, err := d.files(a, m.Paths)
		if err != nil {
			return agent, err
		}
		if m.Nested != nil && *m.Nested {
			files = append(files, d.nested(m.Paths)...)
		}
		sort.Strings(files)
		for _, f := range slices.Compact(files) {
			mf := MemoryFile{Tier: m.Tier, Kind: string(m.Kind), Path: d.display(f), RealPath: d.real(f)}
			if raw, err := readLimited(mf.RealPath); err == nil {
				sum := sha256.Sum256(raw)
				mf.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
			}
			agent.MemoryFiles = append(agent.MemoryFiles, mf)
		}
	}

	if d.opts.Machine && !agent.Installed {
		for _, c := range agent.Configs {
			if c.Tier != contract.ConfigTierProject {
				agent.Installed = true
				agent.Evidence = append(agent.Evidence, "config "+c.Path)
				break
			}
		}
	}
	sortAgent(&agent)
	return agent, nil
}

// runningAs returns the process name or, for an agent running under another
// name (the native installer's versioned binary), the process pattern that
// matched a running executable; "" when none did.
func (d *discoverer) runningAs(a registry.Adapter) string {
	for _, name := range a.Detect.Processes {
		if d.processes[processKey(name)] {
			return name
		}
	}
	for _, pattern := range a.Detect.ProcessPatterns {
		for _, p := range d.procPaths {
			if strings.Contains(p, pattern) {
				return pattern
			}
		}
	}
	return ""
}

// detect looks for a running process, the agent's binary, its desktop app and
// the binary inside that app, and reads the version from the first binary that
// answers. Process evidence contains only the adapter's public process name or
// pattern, never a PID, a path or a command line.
func (d *discoverer) detect(a registry.Adapter, agent *Agent) {
	var candidates []string // binaries to ask for the version, in order
	if name := d.runningAs(a); name != "" {
		agent.Installed = true
		agent.Evidence = append(agent.Evidence, "process "+name)
	}
	for _, b := range a.Detect.Binaries {
		if p, err := d.opts.LookPath(b); err == nil {
			candidates = append(candidates, p)
			agent.Installed = true
			agent.Evidence = append(agent.Evidence, "binary "+d.display(p))
			break
		}
	}
	if a.Detect.AppBundles != nil {
		paths, _ := a.Paths(a.Detect.AppBundles, d.opts.Env, "")
		for _, p := range paths {
			if _, err := os.Stat(d.real(p)); err == nil {
				agent.Installed = true
				agent.Evidence = append(agent.Evidence, "app "+d.display(p))
				break
			}
		}
	}
	if a.Detect.AppBinaries != nil {
		paths, _ := a.Paths(a.Detect.AppBinaries, d.opts.Env, "")
		for _, p := range paths {
			if info, err := os.Stat(d.real(p)); err == nil && info.Mode().IsRegular() {
				agent.Installed = true
				agent.Evidence = append(agent.Evidence, "app "+d.display(appOf(p)))
				candidates = append(candidates, d.real(p))
				break
			}
		}
	}
	if len(candidates) == 0 || len(a.Detect.VersionCmd) == 0 {
		return
	}
	var failures []string
	for _, bin := range candidates {
		argv := append([]string{bin}, a.Detect.VersionCmd[1:]...)
		out, err := d.opts.RunVersion(argv)
		if v := registry.ParseVersion(out); err == nil && v != "" {
			agent.Version = v
			ok := a.Supports(v)
			agent.Supported = &ok
			if len(failures) > 0 {
				agent.VersionNote = "version read from " + d.display(appOf(bin)) + "; " + strings.Join(failures, "; ")
			}
			return
		}
		msg := d.display(strings.TrimPrefix(bin, d.opts.Root)) + " --version failed"
		if err != nil {
			msg += ": " + firstLine(err.Error())
		}
		failures = append(failures, msg)
	}
	agent.VersionNote = strings.Join(failures, "; ")
}

// appOf returns the .app bundle that holds a path, or the path itself.
func appOf(p string) string {
	if i := strings.Index(p, ".app/"); i >= 0 {
		return p[:i+len(".app")]
	}
	return p
}

// Folders a nested memory file search skips, and its limits.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
	".venv": true, "venv": true, "__pycache__": true, ".next": true, ".cache": true}

const (
	maxNestedDepth = 8
	maxNestedDirs  = 5000
)

// nested finds a project-relative memory file pattern in every folder below
// the repo root, as agents load a CLAUDE.md or AGENTS.md from subfolders.
func (d *discoverer) nested(osPaths map[string][]string) []string {
	if d.opts.RepoRoot == "" {
		return nil
	}
	if d.dirs == nil {
		root := d.real(d.opts.RepoRoot)
		d.dirs = []string{}
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if p != root && (skipDirs[e.Name()] || strings.Count(rel, string(filepath.Separator)) >= maxNestedDepth) {
				return filepath.SkipDir
			}
			if p != root {
				d.dirs = append(d.dirs, p)
			}
			if len(d.dirs) >= maxNestedDirs {
				return filepath.SkipAll
			}
			return nil
		})
	}
	var out []string
	for _, pattern := range osPaths["any"] {
		if filepath.IsAbs(pattern) || strings.HasPrefix(pattern, "~") {
			continue
		}
		for _, dir := range d.dirs {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			for _, m := range matches {
				if info, err := os.Stat(m); err == nil && info.Mode().IsRegular() {
					out = append(out, strings.TrimPrefix(m, d.opts.Root))
				}
			}
		}
	}
	return out
}

// files expands path patterns and returns the existing files, sorted.
func (d *discoverer) files(a registry.Adapter, osPaths map[string][]string) ([]string, error) {
	patterns, err := a.Paths(osPaths, d.opts.Env, d.opts.RepoRoot)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range patterns {
		matches, err := filepath.Glob(d.real(p))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.Mode().IsRegular() {
				out = append(out, strings.TrimPrefix(m, d.opts.Root))
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}

func (d *discoverer) read(p, format string, tier contract.ConfigTier, holds []string) *ConfigFile {
	realPath := d.real(p)
	if cf, ok := d.parsed[realPath]; ok {
		c := *cf
		c.Tier, c.Holds = tier, holds
		return &c
	}
	cf := &ConfigFile{Tier: tier, Path: d.display(p), Format: format, Holds: holds, RealPath: realPath}
	raw, err := readLimited(realPath)
	if err == nil {
		sum := sha256.Sum256(raw)
		cf.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		cf.Doc, err = parsers.Parse(format, raw)
	}
	if err != nil {
		cf.Error = firstLine(err.Error())
	}
	d.parsed[realPath] = cf
	return cf
}

func readLimited(p string) ([]byte, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > parsers.MaxSize {
		return nil, parsers.ErrTooLarge
	}
	return os.ReadFile(p)
}

// hooks lists the hook commands in one config file.
func (d *discoverer) hooks(reg registry.HooksRegistration, cf *ConfigFile) []Hook {
	if reg == registry.HooksRegistrationAntigravityHooks {
		return d.namedHooks(cf)
	}
	var out []Hook
	byEvent := parsers.Map(parsers.Lookup(cf.Doc, "/hooks"))
	events := make([]string, 0, len(byEvent))
	for e := range byEvent {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, entry := range parsers.List(byEvent[event]) {
			m := parsers.Map(entry)
			matcher := parsers.String(m["matcher"])
			var commands []string
			switch reg {
			case registry.HooksRegistrationCursorHooks:
				commands = append(commands, parsers.String(m["command"]))
			case registry.HooksRegistrationCopilotHooks:
				for _, key := range []string{"bash", "powershell", "command"} {
					if c := parsers.String(m[key]); c != "" {
						commands = append(commands, strings.TrimPrefix(c, "& "))
						break
					}
				}
			default:
				for _, h := range parsers.List(m["hooks"]) {
					commands = append(commands, parsers.String(parsers.Map(h)["command"]))
				}
			}
			for _, c := range commands {
				if c == "" {
					continue
				}
				out = append(out, Hook{Tier: cf.Tier, Path: cf.Path, Event: event, Matcher: matcher,
					Command: d.redact(c), Privometry: isPrivometryHook(c)})
			}
		}
	}
	return out
}

// namedHooks reads Antigravity's hooks file, where each top-level key names a
// hook that holds events; PreToolUse and PostToolUse hold matcher groups.
// Hooks with "enabled": false are skipped.
func (d *discoverer) namedHooks(cf *ConfigFile) []Hook {
	var out []Hook
	byName := parsers.Map(cf.Doc)
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		def := parsers.Map(byName[name])
		if on, ok := def["enabled"].(bool); ok && !on {
			continue
		}
		events := make([]string, 0, len(def))
		for e := range def {
			if e != "enabled" {
				events = append(events, e)
			}
		}
		sort.Strings(events)
		for _, event := range events {
			for _, item := range parsers.List(def[event]) {
				m := parsers.Map(item)
				handlers := []any{item}
				if event == "PreToolUse" || event == "PostToolUse" {
					handlers = parsers.List(m["hooks"])
				}
				for _, h := range handlers {
					c := parsers.String(parsers.Map(h)["command"])
					if c == "" {
						continue
					}
					out = append(out, Hook{Tier: cf.Tier, Path: cf.Path, Event: event, Matcher: parsers.String(m["matcher"]),
						Command: d.redact(c), Privometry: isPrivometryHook(c)})
				}
			}
		}
	}
	return out
}

func escapePointer(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }

func isPrivometryHook(command string) bool {
	command = strings.TrimSpace(command)
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	first := strings.Trim(fields[0], `"'`)
	if q := command[0]; q == '"' || q == '\'' { // a quoted path may hold spaces
		if end := strings.IndexByte(command[1:], q); end >= 0 {
			first = command[1 : end+1]
		}
	}
	return strings.HasPrefix(first[strings.LastIndexAny(first, `/\`)+1:], "privometry-hook")
}

// mcpServers reads the server map at pointer.
func (d *discoverer) mcpServers(cf *ConfigFile, pointer string) []MCPServer {
	var out []MCPServer
	for _, found := range d.pointerMaps(cf.Doc, pointer) {
		names := make([]string, 0, len(found.value))
		for name := range found.value {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			m := parsers.Map(found.value[name])
			rawPointer := found.rawPointer + "/" + escapePointer(name)
			s := MCPServer{Name: name, Tier: cf.Tier, Path: cf.Path,
				Pointer: found.pointer + "/" + escapePointer(name), RawPointer: rawPointer, Transport: "stdio"}
			url := parsers.String(m["url"])
			for _, key := range []string{"httpUrl", "serverUrl"} { // Gemini CLI, Antigravity
				if url == "" {
					url = parsers.String(m[key])
				}
			}
			if url != "" {
				s.Transport = "http"
				s.URL = d.redact(url)
			}
			if cmd := parsers.String(m["command"]); cmd != "" {
				argv := []string{cmd}
				for _, a := range parsers.List(m["args"]) {
					argv = append(argv, fmt.Sprint(a))
				}
				s.Command = d.redact(strings.Join(argv, " "))
				s.Package, s.Pinned = packageOf(argv)
			}
			for _, key := range []string{"env", "headers", "http_headers"} {
				for k := range parsers.Map(m[key]) {
					s.EnvNames = append(s.EnvNames, k)
				}
			}
			sort.Strings(s.EnvNames)
			out = append(out, s)
		}
	}
	return out
}

// plugins reads Claude Code's version 2 installed-plugin registry. Unknown
// fields are ignored, and installPath is never retained or reported.
func (d *discoverer) plugins(cf *ConfigFile) []Plugin {
	registry := parsers.Map(parsers.Map(cf.Doc)["plugins"])
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Plugin
	for _, id := range ids {
		name, marketplace := id, ""
		if at := strings.LastIndex(id, "@"); at > 0 {
			name, marketplace = id[:at], id[at+1:]
		}
		for _, raw := range parsers.List(registry[id]) {
			entry := parsers.Map(raw)
			out = append(out, Plugin{ID: id, Name: name, Marketplace: marketplace,
				Version: parsers.String(entry["version"]), Scope: parsers.String(entry["scope"]),
				Tier: cf.Tier, Path: cf.Path})
		}
	}
	return out
}

type pointerMap struct {
	pointer    string
	rawPointer string
	value      map[string]any
}

// pointerMaps follows an RFC 6901 pointer with optional whole-segment `*`
// wildcards. Wildcard keys are sorted for deterministic reports. A path used
// as a map key is shortened in the report pointer but retained privately for
// reading the selected server configuration.
func (d *discoverer) pointerMaps(doc any, pointer string) []pointerMap {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if pointer == "" {
		parts = nil
	}
	var walk func(any, int, string, string) []pointerMap
	walk = func(cur any, at int, shown, raw string) []pointerMap {
		if at == len(parts) {
			if m, ok := cur.(map[string]any); ok {
				return []pointerMap{{pointer: shown, rawPointer: raw, value: m}}
			}
			return nil
		}
		part := strings.NewReplacer("~1", "/", "~0", "~").Replace(parts[at])
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if part != "*" {
			next, ok := m[part]
			if !ok {
				return nil
			}
			encoded := "/" + escapePointer(part)
			return walk(next, at+1, shown+encoded, raw+encoded)
		}
		keys := make([]string, 0, len(m))
		for key := range m {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var out []pointerMap
		for _, key := range keys {
			shownKey := key
			if filepath.IsAbs(key) {
				shownKey = d.display(key)
			}
			out = append(out, walk(m[key], at+1, shown+"/"+escapePointer(shownKey), raw+"/"+escapePointer(key))...)
		}
		return out
	}
	return walk(doc, 0, "", "")
}

var pinnedRE = regexp.MustCompile(`^(@[^/]+/)?[^@]+@[0-9][^\s]*$`)

// packageOf finds the package a package-runner command launches (npx, uvx,
// bunx, pnpm dlx, pipx run, docker run) and whether its version is pinned.
func packageOf(argv []string) (string, *bool) {
	runner := filepath.Base(argv[0])
	args := argv[1:]
	switch {
	case runner == "npx" || runner == "bunx" || runner == "uvx":
	case (runner == "pnpm" || runner == "yarn") && len(args) > 0 && args[0] == "dlx",
		runner == "pipx" && len(args) > 0 && args[0] == "run":
		args = args[1:]
	case runner == "docker" && len(args) > 0 && args[0] == "run":
		image := dockerImage(args[1:])
		if image == "" {
			return "", nil
		}
		pinned := strings.Contains(image, "@sha256:") ||
			strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") && !strings.HasSuffix(image, ":latest")
		return image, &pinned
	default:
		return "", nil
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		pinned := pinnedRE.MatchString(a) || strings.Contains(a, "==")
		return a, &pinned
	}
	return "", nil
}

// dockerValueFlags take a separate value, which is not the image name.
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true, "--name": true,
	"--network": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--env-file": true,
	"--entrypoint": true, "--mount": true, "-l": true, "--label": true, "--platform": true,
}

// dockerImage returns the first argument of "docker run" that is not a flag
// or a flag's value.
func dockerImage(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if dockerValueFlags[a] {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func (d *discoverer) redact(s string) string {
	return redact.Redact(s, redact.Context{Home: d.opts.Env.Home, RepoRoot: d.opts.RepoRoot})
}

// real maps a logical path to the file system, applying Root.
func (d *discoverer) real(p string) string {
	if d.opts.Root == "" {
		return p
	}
	return filepath.Join(d.opts.Root, p)
}

// display shortens a path for reports: inside the repo it becomes relative,
// under home it starts with ~.
func (d *discoverer) display(p string) string { return Display(p, d.opts.Env.Home, d.opts.RepoRoot) }

// Display is the path form used in every report.
func Display(p, home, repoRoot string) string { return platform.DisplayPath(p, home, repoRoot) }

func sortAgent(a *Agent) {
	sort.SliceStable(a.Configs, func(i, j int) bool {
		if a.Configs[i].Tier != a.Configs[j].Tier {
			return tierOrder(a.Configs[i].Tier) < tierOrder(a.Configs[j].Tier)
		}
		return a.Configs[i].Path < a.Configs[j].Path
	})
	sort.SliceStable(a.Plugins, func(i, j int) bool {
		if a.Plugins[i].ID != a.Plugins[j].ID {
			return a.Plugins[i].ID < a.Plugins[j].ID
		}
		return a.Plugins[i].Scope < a.Plugins[j].Scope
	})
}

func tierOrder(t contract.ConfigTier) int {
	return map[contract.ConfigTier]int{contract.ConfigTierManaged: 0, contract.ConfigTierUser: 1, contract.ConfigTierProject: 2}[t]
}

func runVersion(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // runs a discovered agent binary with --version
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", errors.New("timed out")
	}
	return string(out), err
}

func processKey(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	return name
}

// listProcesses returns executable names without arguments so scan reports do
// not risk capturing credentials from command lines. Windows is included even
// though broader Windows scanner verification remains a P2 item.
func listProcesses() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	} else {
		cmd = exec.CommandContext(ctx, "ps", "-axo", "comm=")
	}
	out, err := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, errors.New("timed out")
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		return strings.Split(string(out), "\n"), nil
	}
	rows, err := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) > 0 {
			names = append(names, row[0])
		}
	}
	return names, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
