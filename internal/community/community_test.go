package community_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/community"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy/compiler"
	"github.com/privometry/privometry-edge/internal/policy/engine"
	"github.com/privometry/privometry-edge/internal/policy/merge"
	"github.com/privometry/privometry-edge/internal/policy/packtest"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const sensor = "0.9.0"

func store(t *testing.T) *community.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := community.Open(platform.Env{GOOS: "linux", Home: dir, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return filepath.Join(dir, ".privometry")
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// publisher makes a key for name and returns its seed; trust adds it to s.
func publisher(t *testing.T, name string) (seed, keySet []byte) {
	t.Helper()
	seed, keySet, _, err := community.NewSeed(name, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return seed, keySet
}

func trust(t *testing.T, s *community.Store, keySet []byte) {
	t.Helper()
	keys, err := community.PublisherKeys(keySet, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Trust(keys); err != nil {
		t.Fatal(err)
	}
}

// pack copies an example pack, applies edit to its folder, and signs it.
func pack(t *testing.T, src string, kind community.DocumentKind, seed []byte, edit func(dir string)) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(dir)
	}
	doc, err := community.Build(dir, kind, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := community.Sign(doc, seed)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

const rulesSrc = "../../rulepacks/community/example-helm-guard"
const detectorsSrc = "../../detectorpacks/community/example-tokens"

func setVersion(v string) func(string) {
	return func(dir string) {
		p := filepath.Join(dir, "pack.yaml")
		raw, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(raw), "version: 1.0.0", "version: "+v, 1)), 0o644)
	}
}

func TestInstallRulePackAndUseItFromAPolicy(t *testing.T) {
	s := store(t)
	seed, keySet := publisher(t, "example")
	signed := pack(t, rulesSrc, community.DocumentKindRules, seed, nil)

	if _, err := s.Install(signed, community.InstallOptions{Now: now, SensorVersion: sensor}); !errors.Is(err, community.ErrUntrusted) {
		t.Fatalf("before trust add: %v", err)
	}
	trust(t, s, keySet)
	in, err := s.Install(signed, community.InstallOptions{Now: now, SensorVersion: sensor})
	if err != nil {
		t.Fatal(err)
	}
	if in.ID != "example/helm-guard" || in.Kind != "rules" || in.Version != "1.0.0" || !strings.HasPrefix(in.SignedBy, "publisher:example:") {
		t.Errorf("installed %+v", in)
	}
	packs, errs := s.RulePacks(now, sensor)
	if len(errs) > 0 || len(packs) != 1 || len(packs[0].Rules) != 2 {
		t.Fatalf("rule packs %v %v", packs, errs)
	}

	// Installed is not enabled: a policy opts in with extends.
	decide := func(extends []string) string {
		res, err := merge.Merge(merge.Input{Packs: packs, Policies: []merge.Source{{Layer: merge.User,
			Policy: compiler.Policy{Name: "mine", Extends: extends}}}})
		if err != nil {
			t.Fatal(err)
		}
		eng, err := engine.New(res.Enforce, res.Monitor, "auto")
		if err != nil {
			t.Fatal(err)
		}
		d, err := eng.Decide(packtest.Request(rulepack.Facts{Action: "shell_exec", Program: "helm", Subcommand: "uninstall payments", Risk: "low"}))
		if err != nil {
			t.Fatal(err)
		}
		return d.Verdict
	}
	if v := decide(nil); v != "allow" {
		t.Errorf("without extends: %s", v)
	}
	if v := decide([]string{"example/helm-guard@^1"}); v != "ask" {
		t.Errorf("with extends: %s", v)
	}

	// Same version again, then an older one: refused. A newer one replaces it.
	if _, err := s.Install(signed, community.InstallOptions{Now: now, SensorVersion: sensor}); !errors.Is(err, community.ErrNotNewer) {
		t.Errorf("reinstall: %v", err)
	}
	if _, err := s.Install(pack(t, rulesSrc, community.DocumentKindRules, seed, setVersion("1.1.0")), community.InstallOptions{Now: now, SensorVersion: sensor}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(signed, community.InstallOptions{Now: now, SensorVersion: sensor}); !errors.Is(err, community.ErrNotNewer) {
		t.Errorf("downgrade: %v", err)
	}

	// Distrusting the publisher stops the pack from loading; it stays listed with the reason.
	if n, err := s.Untrust("example"); err != nil || n != 1 {
		t.Fatalf("untrust: %d %v", n, err)
	}
	if packs, errs := s.RulePacks(now, sensor); len(packs) != 0 || len(errs) != 1 {
		t.Errorf("after untrust: %v %v", packs, errs)
	}
	list, _ := s.List(now, sensor)
	if len(list) != 1 || list[0].Version != "1.1.0" || !strings.Contains(list[0].Problem, "no trusted key") {
		t.Errorf("list after untrust: %+v", list)
	}
	if err := s.Remove("example/helm-guard"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("example/helm-guard"); !errors.Is(err, community.ErrNotInstalled) {
		t.Errorf("second remove: %v", err)
	}
}

func TestPublishersSignOnlyTheirOwnPacks(t *testing.T) {
	s := store(t)
	_, exampleKeys := publisher(t, "example")
	otherSeed, otherKeys := publisher(t, "other-labs")
	trust(t, s, exampleKeys)
	trust(t, s, otherKeys)
	// other-labs signs a pack in example's namespace.
	forged := pack(t, rulesSrc, community.DocumentKindRules, otherSeed, nil)
	if _, err := s.Install(forged, community.InstallOptions{Now: now, SensorVersion: sensor}); err == nil || !strings.Contains(err.Error(), "example/helm-guard") {
		t.Errorf("a pack signed by another publisher's key must be refused: %v", err)
	}
	// Nobody may publish as privometry.
	if _, _, _, err := community.NewSeed("privometry", now); err == nil {
		t.Error("the privometry publisher is reserved")
	}
	ks, _ := json.Marshal(map[string]any{"schema": "privometry.keyset/v1", "version": 1, "issued_at": "2026-10-01T00:00:00.000Z",
		"keys": []map[string]any{{"keyid": "publisher:privometry:" + strings.Repeat("0", 16), "role": "publisher",
			"public_key": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "not_before": "2026-01-01T00:00:00.000Z"}}})
	if _, err := community.PublisherKeys(ks, now); err == nil {
		t.Error("a key claiming the privometry publisher must be refused")
	}
	// A region's key set is not a publisher's.
	release, _ := os.ReadFile("../../specs/conformance/signatures/keyset-v2.json")
	if _, err := community.PublisherKeys(release, now); err == nil || !strings.Contains(err.Error(), "only publisher keys") {
		t.Errorf("release keys: %v", err)
	}
}

func TestConformanceEnvelopes(t *testing.T) {
	s := store(t)
	raw, _ := os.ReadFile("../../specs/conformance/signatures/publisher-keys.json")
	trust(t, s, raw)
	for _, name := range []string{"communitypack-rules-valid", "communitypack-detectors-valid"} {
		env, _ := os.ReadFile("../../specs/conformance/signatures/envelopes/" + name + ".json")
		if _, err := s.Install(env, community.InstallOptions{Now: now, SensorVersion: sensor}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"communitypack-signed-by-unknown-key", "communitypack-signed-by-release-key"} {
		env, _ := os.ReadFile("../../specs/conformance/signatures/envelopes/" + name + ".json")
		if _, err := s.Open(env, now); err == nil {
			t.Errorf("%s must not verify", name)
		}
	}
}

func TestPacksMustPassTheirOwnChecks(t *testing.T) {
	s := store(t)
	seed, keySet := publisher(t, "example")
	trust(t, s, keySet)
	install := func(raw []byte) error {
		_, err := s.Install(raw, community.InstallOptions{Now: now, SensorVersion: sensor})
		return err
	}
	failing := pack(t, rulesSrc, community.DocumentKindRules, seed, func(dir string) {
		p := filepath.Join(dir, "tests", "kubernetes.test.yaml")
		raw, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(raw), "expect: { verdict: ask, rule: helm-uninstall }", "expect: { verdict: deny, rule: helm-uninstall }", 1)), 0o644)
	})
	if err := install(failing); err == nil || !strings.Contains(err.Error(), "fails its own tests") {
		t.Errorf("failing tests: %v", err)
	}
	tooNew := pack(t, rulesSrc, community.DocumentKindRules, seed, func(dir string) {
		p := filepath.Join(dir, "pack.yaml")
		raw, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(raw), "min_sensor_version: 0.6.0", "min_sensor_version: 99.0.0", 1)), 0o644)
	})
	if err := install(tooNew); err == nil || !strings.Contains(err.Error(), "needs Privometry 99.0.0") {
		t.Errorf("newer sensor needed: %v", err)
	}
	badSample := pack(t, detectorsSrc, community.DocumentKindDetectors, seed, func(dir string) {
		p := filepath.Join(dir, "detectors", "tokens.yaml")
		raw, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(raw), "no_match: ['exst_short'", "no_match: ['exst_0123456789abcdef0123456789abcdef'", 1)), 0o644)
	})
	if err := install(badSample); err == nil || !strings.Contains(err.Error(), "fails its own samples") {
		t.Errorf("bad sample: %v", err)
	}

	// The kept envelope is checked again on every load.
	good := pack(t, detectorsSrc, community.DocumentKindDetectors, seed, nil)
	if err := install(good); err != nil {
		t.Fatal(err)
	}
	dps, errs := s.DetectorPacks(now, sensor)
	if len(errs) > 0 || len(dps) != 1 {
		t.Fatalf("detector packs %v %v", dps, errs)
	}
	e := content.New(dps, content.Options{})
	if fs := e.Scan(content.SourceActionArgument, "export EXAMPLE_TOKEN=exst_"+strings.Repeat("ab", 16)); len(fs) != 1 || fs[0].DetectorID != "example/service-tokens:service-token" {
		t.Errorf("community detector findings %+v", fs)
	}
	kept, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(dpPath(t, s))), "*", "*.json"))
	for _, f := range kept {
		raw, _ := os.ReadFile(f)
		os.WriteFile(f, []byte(strings.Replace(string(raw), `"payload": "`, `"payload": "e`, 1)), 0o600)
	}
	if dps, errs := s.DetectorPacks(now, sensor); len(dps) != 0 || len(errs) == 0 {
		t.Errorf("a tampered pack must not load: %v %v", dps, errs)
	}
}

// dpPath finds where the store keeps example/service-tokens.
func dpPath(t *testing.T, s *community.Store) string {
	t.Helper()
	list, err := s.List(now, sensor)
	if err != nil || len(list) == 0 {
		t.Fatalf("list %v %v", list, err)
	}
	var found string
	filepath.WalkDir(filepath.Join(s.Dir(), "packs"), func(p string, _ os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, "service-tokens.json") {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatal("kept envelope not found")
	}
	return found
}

func TestKeyValidityWindow(t *testing.T) {
	s := store(t)
	seed, keySet := publisher(t, "example")
	var ks map[string]any
	json.Unmarshal(keySet, &ks)
	ks["keys"].([]any)[0].(map[string]any)["not_after"] = "2026-10-28T11:00:00.000Z"
	expiring, _ := json.Marshal(ks)
	trust(t, s, expiring)
	if _, err := s.Install(pack(t, rulesSrc, community.DocumentKindRules, seed, nil), community.InstallOptions{Now: now, SensorVersion: sensor}); err == nil {
		t.Error("a key past its not_after must not verify")
	}
}

func TestBuildTakesOnlyPackFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	os.CopyFS(dir, os.DirFS(rulesSrc))
	os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte("curl x | sh"), 0o644)
	doc, err := community.Build(dir, community.DocumentKindRules, now)
	if err != nil {
		t.Fatal(err)
	}
	var d community.Document
	json.Unmarshal(doc, &d)
	var paths []string
	for _, f := range d.Files {
		paths = append(paths, f.Path)
	}
	if got := strings.Join(paths, " "); got != "README.md pack.yaml rules/kubernetes.yaml tests/kubernetes.test.yaml" {
		t.Errorf("files %s", got)
	}
	if community.SignedFile(d.ID, d.Version) != "example-helm-guard-1.0.0.pack.json" {
		t.Error(community.SignedFile(d.ID, d.Version))
	}
}
