// Package report renders a scan as a table for people, JSON for tools, or
// SARIF 2.1.0 for code-scanning services.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/scanner"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
	"github.com/privometry/privometry-oss/internal/scanner/posture"
)

// Write renders res in format: table, json or sarif.
func Write(w io.Writer, format string, res *scanner.Result) error {
	switch format {
	case "table", "":
		return Table(w, res)
	case "json":
		return JSON(w, res)
	case "sarif":
		return SARIF(w, res)
	}
	return fmt.Errorf("report: unknown format %q (want table, json or sarif)", format)
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, res *scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}

var osNames = map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"}

// Table writes a human-readable report.
func Table(w io.Writer, res *scanner.Result) error {
	scope := []string{}
	if res.Machine {
		scope = append(scope, "this machine")
	}
	if res.Repo != "" {
		scope = append(scope, "repo "+res.Repo)
	}
	fmt.Fprintf(w, "Privometry scan of %s (%s %s)\n\n", strings.Join(scope, " and "), osNames[res.OS], res.Arch)

	if len(res.Agents) == 0 {
		fmt.Fprintln(w, "No coding agents found.")
		if len(res.Findings) == 0 && len(res.ContentFindings) == 0 {
			return nil
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(res.Agents) > 0 {
		fmt.Fprintln(tw, "AGENT\tVERSION\tSUPPORTED\tPRIVOMETRY HOOK\tCONFIG FILES\tMCP SERVERS\tSKILLS\tPLUGINS\tMEMORY FILES")
	}
	for _, a := range res.Agents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", a.Name, orDash(a.Version), supported(a), hooked(a),
			configCount(a), len(a.MCPServers), len(a.Skills), len(a.Plugins), len(a.MemoryFiles))
	}
	tw.Flush()
	for _, a := range res.Agents {
		if a.VersionNote != "" {
			fmt.Fprintf(w, "  %s: %s\n", a.Name, a.VersionNote)
		}
	}

	var servers [][]string
	for _, a := range res.Agents {
		for _, s := range a.MCPServers {
			target := s.Command
			if s.Transport == "http" {
				target = s.URL
			}
			servers = append(servers, []string{a.Name, s.Name, string(s.Tier), s.Transport, pinned(s), truncate(target, 70)})
		}
	}
	if len(servers) > 0 {
		fmt.Fprintf(w, "\nMCP SERVERS\n")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tNAME\tTIER\tTRANSPORT\tPINNED\tCOMMAND OR URL")
		for _, s := range servers {
			fmt.Fprintln(tw, strings.Join(s, "\t"))
		}
		tw.Flush()
	}

	var hooks [][]string
	for _, a := range res.Agents {
		for _, h := range a.Hooks {
			hooks = append(hooks, []string{a.Name, h.Event, string(h.Tier), truncate(h.Command, 70)})
		}
	}
	if len(hooks) > 0 {
		fmt.Fprintf(w, "\nHOOKS\n")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tEVENT\tTIER\tCOMMAND")
		for _, h := range hooks {
			fmt.Fprintln(tw, strings.Join(h, "\t"))
		}
		tw.Flush()
	}

	var unreadable []string
	for _, a := range res.Agents {
		for _, c := range a.Configs {
			if c.Error != "" {
				unreadable = append(unreadable, fmt.Sprintf("  %s (%s): %s", c.Path, a.Name, c.Error))
			}
		}
	}
	if len(unreadable) > 0 {
		fmt.Fprintf(w, "\nCOULD NOT READ (%d)\n%s\n", len(unreadable), strings.Join(unreadable, "\n"))
	}

	names := map[contract.AgentProduct]string{}
	for _, a := range res.Agents {
		names[a.Product] = a.Name
	}
	name := func(p contract.AgentProduct) string {
		switch {
		case names[p] != "":
			return names[p]
		case p == "":
			return "Repository"
		}
		return string(p) // an agent file deleted in a change: the agent is no longer found
	}
	if len(res.ContentFindings) > 0 {
		fmt.Fprintf(w, "\nIN MEMORY FILES, SKILLS, CONFIGS AND CHANGED FILES (%d)\n", len(res.ContentFindings))
		for _, f := range res.ContentFindings {
			fmt.Fprintf(w, "  %-8s %s: %s\n", strings.ToUpper(string(f.Severity)), name(f.Agent), f.Title)
			fmt.Fprintf(w, "           in %s:%d (%s)\n", f.Path, f.Line, f.Detector)
			fmt.Fprintf(w, "           %s\n", truncate(f.Excerpt, 120))
		}
	}
	if res.Allowlisted > 0 {
		fmt.Fprintf(w, "\n%d content finding(s) skipped by allowlists in Privometry policy files.\n", res.Allowlisted)
	}
	if len(res.Findings) == 0 {
		if len(res.ContentFindings) == 0 {
			fmt.Fprintf(w, "\nNothing worth fixing.\n")
		}
		return nil
	}
	fmt.Fprintf(w, "\nWORTH FIXING (%d)\n", len(res.Findings))
	for _, f := range res.Findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(w, "  %-8s %s: %s\n", strings.ToUpper(string(f.Severity)), name(f.Agent), f.Message)
		if loc != "" {
			fmt.Fprintf(w, "           in %s\n", loc)
		}
		fmt.Fprintf(w, "           Fix: %s\n", f.Fix)
	}
	return nil
}

// configCount counts config files other than skills, which have their own column.
func configCount(a discover.Agent) int {
	n := 0
	for _, c := range a.Configs {
		if !slices.Equal(c.Holds, []string{"skills"}) {
			n++
		}
	}
	return n
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func supported(a discover.Agent) string {
	switch {
	case a.Supported == nil:
		return "-"
	case *a.Supported:
		return "yes"
	}
	return "no"
}

func hooked(a discover.Agent) string {
	if slices.ContainsFunc(a.Hooks, func(h discover.Hook) bool { return h.Privometry }) {
		return "installed"
	}
	return "not installed"
}

func pinned(s discover.MCPServer) string {
	switch {
	case s.Pinned == nil:
		return "-"
	case *s.Pinned:
		return "yes"
	}
	return "no"
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// ---- SARIF 2.1.0 ----

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	DefaultConfiguration map[string]string `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation map[string]string `json:"artifactLocation"`
	Region           *sarifRegion      `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// ruleName turns a check ID such as auto_approve_mode into AutoApproveMode.
func ruleName(id string) string {
	var b strings.Builder
	for _, w := range strings.Split(id, "_") {
		if w != "" {
			b.WriteString(strings.ToUpper(w[:1]) + w[1:])
		}
	}
	return b.String()
}

// sarifLevel maps a severity to a SARIF level, and securitySeverity to the
// 0-10 score GitHub code scanning uses to rank alerts.
func sarifLevel(r contract.Risk) string {
	switch r {
	case contract.RiskCritical, contract.RiskHigh:
		return "error"
	case contract.RiskMedium:
		return "warning"
	}
	return "note"
}

var securitySeverity = map[contract.Risk]string{
	contract.RiskCritical: "9.5", contract.RiskHigh: "8.0", contract.RiskMedium: "5.5", contract.RiskLow: "3.0", contract.RiskNone: "0.0",
}

// SARIF writes the findings as SARIF 2.1.0. Repo files use paths relative to
// the repo root (uriBaseId %SRCROOT%), so code scanning can annotate them.
func SARIF(w io.Writer, res *scanner.Result) error {
	var rules []sarifRule
	index := map[string]int{}
	for _, c := range posture.Checks {
		index[c.ID] = len(rules)
		rules = append(rules, sarifRule{
			ID:                   "privometry/" + c.ID,
			Name:                 ruleName(c.ID),
			ShortDescription:     sarifText{c.Title},
			FullDescription:      sarifText{c.Help},
			DefaultConfiguration: map[string]string{"level": sarifLevel(c.Severity)},
			Properties:           map[string]any{"security-severity": securitySeverity[c.Severity], "tags": []string{"security", "ai-agents"}},
		})
	}
	for _, f := range res.ContentFindings {
		if _, ok := index[f.Detector]; ok {
			continue
		}
		index[f.Detector] = len(rules)
		rules = append(rules, sarifRule{
			ID:                   f.Detector,
			Name:                 ruleName(strings.ReplaceAll(f.Detector[strings.LastIndex(f.Detector, ":")+1:], "-", "_")),
			ShortDescription:     sarifText{f.Title},
			FullDescription:      sarifText{f.Title + " (content detector, category " + f.Category + ")."},
			DefaultConfiguration: map[string]string{"level": sarifLevel(f.Severity)},
			Properties:           map[string]any{"security-severity": securitySeverity[f.Severity], "tags": []string{"security", "ai-agents", f.Category}},
		})
	}
	results := []sarifResult{}
	for _, f := range res.ContentFindings {
		loc := map[string]string{"uri": f.Path}
		if f.Tier == contract.ConfigTierProject {
			loc["uriBaseId"] = "%SRCROOT%"
		}
		phys := sarifPhysical{ArtifactLocation: loc}
		if f.Line > 0 {
			phys.Region = &sarifRegion{StartLine: f.Line}
		}
		results = append(results, sarifResult{RuleID: f.Detector, RuleIndex: index[f.Detector], Level: sarifLevel(f.Severity),
			Message: sarifText{f.Title + ": " + f.Excerpt}, Locations: []sarifLocation{{PhysicalLocation: phys}}})
	}
	for _, f := range res.Findings {
		r := sarifResult{RuleID: "privometry/" + f.Check, RuleIndex: index[f.Check], Level: sarifLevel(f.Severity),
			Message: sarifText{f.Message + " Fix: " + f.Fix}}
		if f.Path != "" {
			loc := map[string]string{"uri": f.Path}
			if f.Tier == contract.ConfigTierProject {
				loc["uriBaseId"] = "%SRCROOT%"
			}
			phys := sarifPhysical{ArtifactLocation: loc}
			if f.Line > 0 {
				phys.Region = &sarifRegion{StartLine: f.Line}
			}
			r.Locations = []sarifLocation{{PhysicalLocation: phys}}
		}
		results = append(results, r)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "Privometry", Version: res.SensorVersion, InformationURI: "https://github.com/privometry/privometry-oss", Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
