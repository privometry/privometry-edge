// Package scanner runs a full scan: discovery, posture checks, content scans
// of memory files, skills and configs, and the result that reports render.
// See internal/scanner/report for output formats.
package scanner

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privometry/privometry-edge/detectorpacks"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/scanner/parsers"
	"github.com/privometry/privometry-edge/internal/scanner/posture"
)

// ResultSchema identifies the JSON report. It is v0 until the scan report has
// its own spec (before the GitHub Action in M6); fields may still change.
const ResultSchema = "privometry.scan/v0"

// Result is one scan.
type Result struct {
	Schema        string            `json:"schema"`
	ScannedAt     contract.Time     `json:"scanned_at"`
	SensorVersion string            `json:"sensor_version"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Machine       bool              `json:"machine"`
	Repo          string            `json:"repo,omitempty"`
	Agents        []discover.Agent  `json:"agents"`
	Findings      []posture.Finding `json:"findings"`
	// ContentFindings are content detector hits in memory and instruction
	// files, skills and agent configs (PRD SCAN-05 to SCAN-07).
	ContentFindings []ContentFinding `json:"content_findings"`
	// Allowlisted counts content findings dropped by policy allowlists.
	Allowlisted int            `json:"allowlisted"`
	Summary     map[string]int `json:"summary"`
}

// Options control a scan.
type Options struct {
	discover.Options
	// Detectors are the detector packs to run; nil means the packs built
	// into this binary.
	Detectors []*content.Pack
	// Allowlist drops content findings people accepted in a policy file.
	Allowlist *content.Allowlist
	// Changed lists the repo files a merge or pull request changes. Agent
	// config, memory and policy files among them become agent_file_changed
	// findings, and every changed text file is scanned with the detectors
	// that apply to repositories (PRD EDGE-30, SCAN-08).
	Changed []Change
}

// Change is one changed file, relative to the repo root with / separators.
type Change struct {
	Path    string
	Deleted bool
}

// ContentFinding is one detector hit in a file at rest. The excerpt masks
// credentials; it is shown to the developer and never uploaded.
type ContentFinding struct {
	Detector   string                `json:"detector"`
	Title      string                `json:"title"`
	Category   string                `json:"category"`
	Severity   contract.Risk         `json:"severity"`
	Confidence string                `json:"confidence"`
	Agent      contract.AgentProduct `json:"agent"`
	Tier       contract.ConfigTier   `json:"tier"`
	Source     string                `json:"source"`
	Path       string                `json:"path"`
	Line       int                   `json:"line"`
	SecretType string                `json:"secret_type,omitempty"`
	Excerpt    string                `json:"excerpt"`
}

var (
	engineOnce sync.Once
	engine     *content.Engine
	engineErr  error
)

// detectors returns an engine for packs, or for the shipped packs, loaded
// once, when packs is nil.
func detectors(packs []*content.Pack) (*content.Engine, error) {
	if packs != nil {
		return content.New(packs, content.Options{}), nil
	}
	engineOnce.Do(func() {
		packs, err := content.Load(detectorpacks.FS)
		if err != nil {
			engineErr = err
			return
		}
		engine = content.New(packs, content.Options{})
	})
	return engine, engineErr
}

// maxScanFile bounds how much of one file the content scan reads.
const maxScanFile = 1 << 20

// scanContent runs the detectors over each agent's memory files, skills and
// config files, once per file, then over the changed repo files not already
// scanned. Credentials in config files are left to the secret_in_config
// posture check, which names the setting. It returns the findings and how
// many the allowlist dropped.
func scanContent(agents []discover.Agent, opts Options) ([]ContentFinding, int, error) {
	eng, err := detectors(opts.Detectors)
	if err != nil {
		return nil, 0, err
	}
	out := []ContentFinding{}
	seen := map[string]bool{}
	allowlisted := 0
	now := time.Now()
	add := func(a discover.Agent, tier contract.ConfigTier, display, text string, src content.Source, lines bool) {
		fs, dropped := opts.Allowlist.Filter(eng.Scan(src, text), text, display, now)
		allowlisted += dropped
		for _, f := range fs {
			if src == content.SourceAgentConfig && f.Category == content.CategoryCredential {
				continue
			}
			line := f.Line
			if !lines {
				line = 0
			}
			out = append(out, ContentFinding{Detector: f.DetectorID, Title: f.Title, Category: string(f.Category),
				Severity: contract.Risk(f.Severity), Confidence: string(f.Confidence), Agent: a.Product, Tier: tier,
				Source: string(src), Path: display, Line: line, SecretType: f.SecretType, Excerpt: f.Excerpt})
		}
	}
	scan := func(a discover.Agent, tier contract.ConfigTier, display, realPath string, src content.Source) {
		if seen[realPath] {
			return
		}
		seen[realPath] = true
		raw, err := os.ReadFile(realPath)
		if err != nil {
			return
		}
		if len(raw) > maxScanFile {
			raw = raw[:maxScanFile]
		}
		add(a, tier, display, string(raw), src, true)
	}
	for _, a := range agents {
		for _, m := range a.MemoryFiles {
			scan(a, m.Tier, m.Path, m.RealPath, content.SourceMemoryFile)
		}
		for _, c := range a.Configs {
			if slices.Equal(c.Holds, []string{"mcp_servers"}) {
				// A file Privometry reads only for its MCP servers (~/.claude.json
				// is mostly the agent's own state): scan just the servers.
				if seen[c.RealPath] {
					continue
				}
				seen[c.RealPath] = true
				var b strings.Builder
				for _, srv := range a.MCPServers {
					if srv.Path == c.Path {
						pointer := srv.RawPointer
						if pointer == "" {
							pointer = srv.Pointer
						}
						b.WriteString(content.Flatten(parsers.Lookup(c.Doc, pointer)))
					}
				}
				add(a, c.Tier, c.Path, b.String(), content.SourceAgentConfig, false)
				continue
			}
			src := content.SourceAgentConfig
			if slices.Contains(c.Holds, "skills") {
				src = content.SourceSkill
			}
			scan(a, c.Tier, c.Path, c.RealPath, src)
		}
	}
	for _, c := range opts.Changed {
		if c.Deleted || opts.RepoRoot == "" {
			continue
		}
		realPath := opts.Root + path.Join(opts.RepoRoot, c.Path)
		if seen[realPath] {
			continue
		}
		seen[realPath] = true
		info, err := os.Lstat(realPath)
		if err != nil || !info.Mode().IsRegular() {
			continue // gone, a folder, or a symlink that may point outside the repo
		}
		raw, err := os.ReadFile(realPath)
		if err != nil || isBinary(raw) {
			continue
		}
		if len(raw) > maxScanFile {
			raw = raw[:maxScanFile]
		}
		add(discover.Agent{}, contract.ConfigTierProject, c.Path, string(raw), content.SourceRepo, true)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := posture.Rank(out[i].Severity), posture.Rank(out[j].Severity); r1 != r2 {
			return r1 > r2
		}
		return out[i].Path < out[j].Path
	})
	return out, allowlisted, nil
}

// isBinary reports whether a file looks binary: a NUL byte near its start.
func isBinary(b []byte) bool {
	return bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0
}

// Scan discovers agents, checks their posture and scans their files.
func Scan(reg *registry.Registry, opts Options) (*Result, error) {
	agents, err := discover.Run(reg, opts.Options)
	if err != nil {
		return nil, err
	}
	findings := posture.Run(reg, agents, opts.Env, opts.Root)
	if findings == nil {
		findings = []posture.Finding{}
	}
	locate(agents, findings)
	findings = append(findings, changedFiles(reg, opts)...)
	cfs, allowlisted, err := scanContent(agents, opts)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Schema:          ResultSchema,
		ScannedAt:       contract.At(time.Now()),
		SensorVersion:   buildinfo.Version,
		OS:              opts.Env.OS(),
		Arch:            runtime.GOARCH,
		Machine:         opts.Machine,
		Agents:          agents,
		Findings:        findings,
		ContentFindings: cfs,
		Allowlisted:     allowlisted,
		Summary:         map[string]int{},
	}
	if res.Agents == nil {
		res.Agents = []discover.Agent{}
	}
	if opts.RepoRoot != "" {
		res.Repo = discover.Display(opts.RepoRoot, opts.Env.Home, "")
	}
	for _, f := range findings {
		res.Summary[string(f.Severity)]++
	}
	for _, f := range cfs {
		res.Summary[string(f.Severity)]++
	}
	return res, nil
}

// locate sets each finding's line from its JSON pointer: the first line that
// holds the pointer's last key. Good enough for annotations; 0 when unknown.
func locate(agents []discover.Agent, findings []posture.Finding) {
	realPath := map[string]string{}
	for _, a := range agents {
		for _, c := range a.Configs {
			realPath[c.Path] = c.RealPath
		}
	}
	for i := range findings {
		f := &findings[i]
		p, ok := realPath[f.Path]
		if !ok || f.Pointer == "" {
			continue
		}
		key := f.Pointer[strings.LastIndex(f.Pointer, "/")+1:]
		key = strings.NewReplacer("~1", "/", "~0", "~").Replace(key)
		if isIndex(key) { // an array element: look for its parent key instead
			parent := strings.TrimSuffix(f.Pointer, "/"+key)
			key = parent[strings.LastIndex(parent, "/")+1:]
		}
		f.Line = lineOf(p, key)
	}
}

func isIndex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func lineOf(path, key string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.Contains(line, `"`+key+`"`) || strings.HasPrefix(strings.TrimSpace(line), key+" ") ||
			strings.HasPrefix(strings.TrimSpace(line), key+"=") || strings.Contains(line, "."+key+"]") || strings.Contains(line, "["+key+"]") {
			return n
		}
	}
	return 0
}
