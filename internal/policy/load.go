package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-oss/internal/cloud/bundles"
	"github.com/privometry/privometry-oss/internal/content"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/policy/compiler"
	"github.com/privometry/privometry-oss/internal/policy/merge"
	"github.com/privometry/privometry-oss/internal/policy/rulepack"
	"github.com/privometry/privometry-oss/rulepacks"
	"github.com/privometry/privometry-oss/specs"
)

// BuiltinPacks returns the rule packs shipped in the sensor.
func BuiltinPacks() ([]rulepack.Pack, error) { return rulepack.Load(rulepacks.FS) }

// LoadFile reads a policy file, validates it and tags it with its layer.
func LoadFile(path, layer string) (merge.Source, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return merge.Source{}, err
	}
	if err := specs.Validate("policy/v1/policy.schema.json", path, raw); err != nil {
		return merge.Source{}, err
	}
	var p compiler.Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return merge.Source{}, fmt.Errorf("%s: %w", path, err)
	}
	return merge.Source{Layer: layer, Policy: p}, nil
}

// BundleSources returns the organization layer of a verified bundle: the
// policy files it carries, each loaded as a policy file would be. A source
// that fails to load is reported in errs and skipped.
func BundleSources(b *bundles.Bundle) (sources []merge.Source, errs []error) {
	for _, s := range b.Sources {
		if s.Layer != bundles.BundleSourceLayerOrg {
			errs = append(errs, fmt.Errorf("bundle %d: source %s has layer %s; only organization policies come from bundles", b.Version, s.Name, s.Layer))
			continue
		}
		name := fmt.Sprintf("bundle %d %s.yaml", b.Version, s.Name) // .yaml: validated as YAML
		if err := specs.Validate("policy/v1/policy.schema.json", name, []byte(s.Content)); err != nil {
			errs = append(errs, err)
			continue
		}
		var p compiler.Policy
		if err := yaml.Unmarshal([]byte(s.Content), &p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		sources = append(sources, merge.Source{Layer: merge.Org, Version: s.Version, Policy: p})
	}
	return sources, errs
}

// Sources loads every policy layer the daemon merges: the user policy, the
// repo policy and, on an enrolled device, the organization policies of the
// bundle it holds (enforced even after the bundle expires). Files that fail
// to load are reported in errs and skipped.
func Sources(env platform.Env, repoRoot string, now time.Time) (sources []merge.Source, errs []error) {
	sources, errs = LocalSources(env.Home, repoRoot)
	held, err := bundles.Load(env, now)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("organization bundle ignored: %w", err))
	case held != nil:
		if held.Expired {
			errs = append(errs, fmt.Errorf("organization bundle %d expired on %s; still enforced until a new one arrives",
				held.Bundle.Version, held.Bundle.ExpiresAt.Format(time.RFC3339)))
		}
		org, orgErrs := BundleSources(held.Bundle)
		sources, errs = append(sources, org...), append(errs, orgErrs...)
	}
	return sources, errs
}

// Local paths of the user and repo policy files.
const (
	UserPolicyPath = ".privometry/policy.yaml" // under the home folder
	RepoPolicyPath = ".privometry/policy.yaml" // under the repo root
)

// LocalSources loads the user policy (~/.privometry/policy.yaml) and the repo
// policy (<repo>/.privometry/policy.yaml) when they exist. A file that fails to
// load is reported in errs and skipped, so a broken repo file cannot turn
// protection off.
func LocalSources(home, repoRoot string) (sources []merge.Source, errs []error) {
	try := func(path, layer string) {
		src, err := LoadFile(path, layer)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			errs = append(errs, fmt.Errorf("%s policy ignored: %w", layer, err))
		default:
			sources = append(sources, src)
		}
	}
	if home != "" {
		try(filepath.Join(home, UserPolicyPath), merge.User)
	}
	if repoRoot != "" {
		try(filepath.Join(repoRoot, RepoPolicyPath), merge.Repo)
	}
	return sources, errs
}

// Allowlist collects the content allowlist entries of the given policies
// (PRD SCAN-09), whatever their layer. Repo and user entries apply to the
// files and actions their policy covers; an organization's arrive with
// policy bundles.
func Allowlist(sources []merge.Source) *content.Allowlist {
	var entries []content.AllowEntry
	for _, s := range sources {
		for _, e := range s.Policy.Allowlist {
			ce := content.AllowEntry{Detectors: e.Detectors, Paths: e.Paths, Values: e.Values, Reason: e.Reason,
				Source: s.Layer + " policy " + s.Policy.Name}
			if e.ExpiresAt != "" {
				t, err := time.Parse(time.RFC3339, e.ExpiresAt)
				if err != nil {
					continue // the schema rejects this; never widen on a bad date
				}
				ce.Expires = t
			}
			entries = append(entries, ce)
		}
	}
	return content.NewAllowlist(entries)
}
