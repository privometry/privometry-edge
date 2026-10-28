// release-metadata creates deterministic release SBOM and dependency-license
// inventory files without requiring a third-party binary in the release job.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

type pkg struct {
	Module *module
}

type moduleLicense struct {
	Path         string   `json:"path"`
	Version      string   `json:"version,omitempty"`
	License      string   `json:"license"`
	LicenseFiles []string `json:"license_files"`
	Allowed      bool     `json:"allowed"`
}

type licenseReport struct {
	Schema  string          `json:"schema"`
	Modules []moduleLicense `json:"modules"`
	Allowed bool            `json:"allowed"`
}

type bom struct {
	Format      string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    bomMetadata    `json:"metadata"`
	Components  []bomComponent `json:"components"`
}

type bomMetadata struct {
	Component bomComponent `json:"component"`
}

type bomComponent struct {
	Type     string       `json:"type"`
	Name     string       `json:"name"`
	Version  string       `json:"version,omitempty"`
	PURL     string       `json:"purl,omitempty"`
	Licenses []bomLicense `json:"licenses,omitempty"`
}

type bomLicense struct {
	Expression string `json:"expression"`
}

func main() {
	var sbomPath, licensesPath, version string
	flag.StringVar(&sbomPath, "sbom", "privometry.cdx.json", "CycloneDX SBOM output path")
	flag.StringVar(&licensesPath, "licenses", "dependency-licenses.json", "dependency license report output path")
	flag.StringVar(&version, "version", "dev", "Privometry version recorded in the SBOM")
	flag.Parse()

	mods, err := listModules()
	if err != nil {
		fatal(err)
	}
	report, problems := scanLicenses(mods)
	if err := writeJSON(licensesPath, report); err != nil {
		fatal(err)
	}
	if err := writeJSON(sbomPath, makeBOM(mods, report, version)); err != nil {
		fatal(err)
	}
	if len(problems) > 0 {
		fatal(fmt.Errorf("dependency license policy failed:\n  %s", strings.Join(problems, "\n  ")))
	}
	fmt.Printf("wrote %s and %s for %d modules\n", sbomPath, licensesPath, len(mods))
}

func listModules() ([]module, error) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/...")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	seen := map[string]module{}
	dec := json.NewDecoder(out)
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if p.Module == nil {
			continue
		}
		m := *p.Module
		if m.Replace != nil {
			m.Dir = m.Replace.Dir
		}
		seen[m.Path+"@"+m.Version] = m
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	mods := make([]module, 0, len(seen))
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

func scanLicenses(mods []module) (licenseReport, []string) {
	report := licenseReport{Schema: "privometry.licenses/v1", Allowed: true}
	var problems []string
	for _, m := range mods {
		entry := moduleLicense{Path: m.Path, Version: m.Version}
		ids, files, err := licensesIn(m.Dir)
		entry.LicenseFiles = files
		switch {
		case err != nil:
			entry.License = "UNKNOWN"
			problems = append(problems, m.Path+": "+err.Error())
		case len(ids) == 0:
			entry.License = "UNKNOWN"
			problems = append(problems, m.Path+": no recognized license")
		default:
			entry.License = strings.Join(ids, " OR ")
			entry.Allowed = true
		}
		if !entry.Allowed {
			report.Allowed = false
		}
		report.Modules = append(report.Modules, entry)
	}
	if len(problems) > 0 {
		report.Allowed = false
	}
	return report, problems
}

func licensesIn(dir string) ([]string, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	var files, unknown []string
	for _, entry := range entries {
		name := entry.Name()
		upper := strings.ToUpper(name)
		if entry.IsDir() || !(upper == "LICENSE" || upper == "COPYING" || strings.HasPrefix(upper, "LICENSE.") || strings.HasPrefix(upper, "COPYING.")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, files, err
		}
		files = append(files, name)
		id := classifyLicense(string(raw))
		if id == "" {
			unknown = append(unknown, name)
			continue
		}
		seen[id] = true
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil, errors.New("no LICENSE or COPYING file")
	}
	if len(unknown) > 0 {
		return nil, files, fmt.Errorf("unrecognized license text in %s", strings.Join(unknown, ", "))
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, files, nil
}

func classifyLicense(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(lower, "mozilla public license version 2.0"):
		return "MPL-2.0"
	case strings.Contains(lower, "permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(lower, "redistribution and use in source and binary forms") && strings.Contains(lower, "neither the name"):
		return "BSD-3-Clause"
	case strings.Contains(lower, "redistribution and use in source and binary forms"):
		return "BSD-2-Clause"
	case strings.Contains(lower, "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"):
		return "ISC"
	case strings.Contains(lower, "this software is provided 'as-is', without any express or implied warranty") && strings.Contains(lower, "altered source versions must be plainly marked"):
		return "Zlib"
	default:
		return ""
	}
}

func makeBOM(mods []module, report licenseReport, version string) bom {
	licenses := make(map[string]string, len(report.Modules))
	for _, m := range report.Modules {
		licenses[m.Path+"@"+m.Version] = m.License
	}
	b := bom{Format: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: bomMetadata{Component: bomComponent{Type: "application", Name: "privometry", Version: version}}}
	for _, m := range mods {
		if m.Main {
			continue
		}
		component := bomComponent{Type: "library", Name: m.Path, Version: m.Version, PURL: goPURL(m.Path, m.Version)}
		if license := licenses[m.Path+"@"+m.Version]; license != "" && license != "UNKNOWN" {
			component.Licenses = []bomLicense{{Expression: license}}
		}
		b.Components = append(b.Components, component)
	}
	return b
}

func goPURL(path, version string) string {
	path = strings.ReplaceAll(path, "%", "%25")
	path = strings.ReplaceAll(path, "@", "%40")
	return "pkg:golang/" + path + "@" + version
}

func writeJSON(path string, value any) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "release-metadata:", err)
	os.Exit(1)
}
