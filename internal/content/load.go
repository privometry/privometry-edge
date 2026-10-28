// Package content runs Privometry's content detectors (privometry.detectorpack/v1) on
// the text agents read, write and send, and on memory and instruction files
// at rest. It produces findings for the timeline and the content facts the
// policy decides on (secret_detected, injection_detected, hidden_content).
//
// Detection runs on the device. A finding carries the detector, location and,
// for credentials, a salted fingerprint; the matched value never leaves the
// engine except as a masked excerpt for the local timeline.
package content

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/privometry/privometry-oss/specs"
)

// Pack is a loaded, compiled detector pack.
type Pack struct {
	Manifest  Manifest
	Detectors []*Compiled
}

// Compiled is one detector ready to run.
type Compiled struct {
	Detector
	QID       string // <pack>:<id>
	Pack      string
	Version   string
	re        *regexp.Regexp
	secretIdx int // submatch index of the secret group, or 0 for the whole match
	keywords  []string
	allow     map[string]bool
	sources   map[Source]bool
	unicode   map[DetectorUnicode]bool
	minLength int
}

// unsplit removes the {{}} markers that keep sample credentials from being
// contiguous in the repository.
func unsplit(s string) string { return strings.ReplaceAll(s, "{{}}", "") }

// Load reads every <dir>/pack.yaml in fsys with its detectors/*.yaml,
// validating each file against its schema and compiling every detector.
func Load(fsys fs.FS) ([]*Pack, error) {
	manifests, err := fs.Glob(fsys, "*/pack.yaml")
	if err != nil {
		return nil, err
	}
	var packs []*Pack
	for _, mpath := range manifests {
		p, err := loadPack(fsys, mpath)
		if err != nil {
			return nil, err
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Manifest.ID < packs[j].Manifest.ID })
	return packs, nil
}

func loadPack(fsys fs.FS, mpath string) (*Pack, error) {
	var m Manifest
	raw, err := fs.ReadFile(fsys, mpath)
	if err != nil {
		return nil, err
	}
	if err := specs.DecodeInto("detectorpack/v1/pack.schema.json", mpath, raw, &m); err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}
	files, _ := fs.Glob(fsys, path.Join(path.Dir(mpath), "detectors", "*.yaml"))
	sort.Strings(files)
	var docs []DetectorsFile
	for _, f := range files {
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var doc DetectorsFile
		if err := specs.DecodeInto("detectorpack/v1/detectors.schema.json", f, raw, &doc); err != nil {
			return nil, fmt.Errorf("content: %w", err)
		}
		docs = append(docs, doc)
	}
	return NewPack(m, docs)
}

// NewPack compiles a validated manifest and its detector files, such as one
// pack of a signed detector pack set. Detector IDs must be unique and their
// categories listed in the manifest.
func NewPack(m Manifest, docs []DetectorsFile) (*Pack, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("content: %s has no detectors/*.yaml", m.ID)
	}
	p := &Pack{Manifest: m}
	seen := map[string]bool{}
	for _, doc := range docs {
		for _, d := range doc.Detectors {
			if seen[d.ID] {
				return nil, fmt.Errorf("content: %s: detector %s is defined twice", p.Manifest.ID, d.ID)
			}
			seen[d.ID] = true
			if !slices.Contains(p.Manifest.Categories, d.Category) {
				return nil, fmt.Errorf("content: %s:%s: category %s is not listed in pack.yaml", p.Manifest.ID, d.ID, d.Category)
			}
			c, err := compile(p.Manifest, d)
			if err != nil {
				return nil, fmt.Errorf("content: %s:%s: %w", p.Manifest.ID, d.ID, err)
			}
			p.Detectors = append(p.Detectors, c)
		}
	}
	return p, nil
}

// Default shortest spans for structure detectors without min_length.
var defaultMinLength = map[DetectorStructure]int{
	DetectorStructureBase64Blob:    64,
	DetectorStructureHexBlob:       64,
	DetectorStructureWhitespaceRun: 120,
}

func compile(m Manifest, d Detector) (*Compiled, error) {
	c := &Compiled{Detector: d, QID: m.ID + ":" + d.ID, Pack: m.ID, Version: m.Version,
		allow: map[string]bool{}, sources: map[Source]bool{}, unicode: map[DetectorUnicode]bool{}}
	if d.Pattern != "" {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern: %w", err)
		}
		c.re = re
		c.secretIdx = re.SubexpIndex("secret")
		if c.secretIdx < 0 {
			c.secretIdx = 0
		}
	}
	for _, k := range d.Keywords {
		c.keywords = append(c.keywords, strings.ToLower(k))
	}
	for _, a := range d.Allow {
		c.allow[unsplit(a)] = true
	}
	for _, s := range d.AppliesTo {
		c.sources[s] = true
	}
	for _, u := range d.Unicode {
		c.unicode[u] = true
	}
	if d.MinLength != nil {
		c.minLength = int(*d.MinLength)
	} else {
		c.minLength = defaultMinLength[d.Structure]
	}
	for i := range c.Samples.Match {
		c.Samples.Match[i] = unsplit(c.Samples.Match[i])
	}
	for i := range c.Samples.NoMatch {
		c.Samples.NoMatch[i] = unsplit(c.Samples.NoMatch[i])
	}
	return c, nil
}

// RunsOn reports whether the detector runs on a source.
func (c *Compiled) RunsOn(s Source) bool { return c.sources[s] }
