package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/scanner/parsers"
)

// Disabling is a config file that turns the agent's hooks off.
type Disabling struct {
	Path    string // as configured, without Root
	Tier    string
	Setting string // the setting as it reads in the file, for example disableAllHooks = true
}

// Disabled returns the first config file that turns all of the agent's hooks
// off with one of its definition's hooks.disable_settings, or nil. It reads
// the user and managed tiers, and the project tiers of projectDir when it is
// set (.claude/settings.local.json for Claude Code). Files that do not parse
// are skipped: the agent cannot read them either.
func Disabled(a registry.Adapter, opts Options, projectDir string) *Disabling {
	if len(a.Hooks.DisableSettings) == 0 {
		return nil
	}
	for _, p := range SettingsFiles(a, opts, projectDir) {
		if setting := DisablesIn(a, filepath.Join(opts.Root, p.Path), p.Format); setting != "" {
			return &Disabling{Path: p.Path, Tier: p.Tier, Setting: setting}
		}
	}
	return nil
}

// DisablesIn returns the hook-disabling setting the file at path holds, as it
// reads in the file, or "" when it holds none, is missing or does not parse.
func DisablesIn(a registry.Adapter, path, format string) string {
	if len(a.Hooks.DisableSettings) == 0 {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	doc, err := parsers.Parse(format, raw)
	if err != nil {
		return ""
	}
	for _, s := range a.Hooks.DisableSettings {
		if v := parsers.Lookup(doc, s.Pointer); v != nil && sameValue(v, s.Value) {
			return settingText(format, s)
		}
	}
	return ""
}

// SettingsFile is one config file that may hold a hook-disabling setting.
type SettingsFile struct {
	Path   string
	Tier   string
	Format string
}

// SettingsFiles lists the files Disabled reads, existing or not, with globs
// expanded; project tiers only when projectDir is set.
func SettingsFiles(a registry.Adapter, opts Options, projectDir string) []SettingsFile {
	var out []SettingsFile
	seen := map[string]bool{}
	for _, t := range a.ConfigTiers {
		switch t.Format {
		case registry.FileFormatJSON, registry.FileFormatJsonc, registry.FileFormatToml:
		default:
			continue
		}
		if !slices.Contains(t.Holds, "settings") && !slices.Contains(t.Holds, "hooks") {
			continue
		}
		root := ""
		if t.Tier == "project" {
			if projectDir == "" {
				continue
			}
			root = projectDir
		}
		paths, err := a.Paths(t.Paths, opts.Env, root)
		if err != nil {
			continue
		}
		for _, pattern := range paths {
			matches := []string{pattern}
			if strings.ContainsAny(pattern, "*?[") {
				matches = nil
				found, _ := filepath.Glob(filepath.Join(opts.Root, pattern))
				for _, m := range found {
					matches = append(matches, strings.TrimPrefix(m, opts.Root))
				}
			}
			for _, m := range matches {
				if !seen[m] {
					seen[m] = true
					out = append(out, SettingsFile{Path: m, Tier: string(t.Tier), Format: string(t.Format)})
				}
			}
		}
	}
	return out
}

// sameValue compares a parsed setting with the definition's value as JSON,
// so a TOML integer matches a YAML one.
func sameValue(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func settingText(format string, s registry.HooksDisableSetting) string {
	val, _ := json.Marshal(s.Value)
	keys := strings.Split(strings.TrimPrefix(s.Pointer, "/"), "/")
	if format == string(registry.FileFormatToml) && len(keys) > 1 {
		return fmt.Sprintf("[%s] %s = %s", strings.Join(keys[:len(keys)-1], "."), keys[len(keys)-1], val)
	}
	if format == string(registry.FileFormatToml) {
		return fmt.Sprintf("%s = %s", keys[0], val)
	}
	return fmt.Sprintf("%q: %s", strings.Join(keys, "."), val)
}

// ownEntryOff reports whether Privometry's own entry is there but turned off
// (Antigravity's "enabled": false on the privometry hook).
func ownEntryOff(a registry.Adapter, doc *object) bool {
	if a.Hooks.Registration != registry.HooksRegistrationAntigravityHooks {
		return false
	}
	ours, _ := doc.get(hookName).(*object)
	if ours == nil {
		return false
	}
	on, ok := ours.get("enabled").(bool)
	return ok && !on
}
