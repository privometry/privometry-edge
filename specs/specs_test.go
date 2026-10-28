// Package specs_test checks every contract in this folder against its own
// examples: each file in examples/valid must pass and each file in
// examples/invalid must fail. The same examples run in the platform repo.
package specs_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/privometry/privometry-oss/specs"
)

// suites maps a contract folder to the schema its examples are checked against.
// Folders with several schemas use examples/<schema name>/{valid,invalid}.
var suites = []struct {
	dir     string
	schema  string
	maxSize int // bytes per example as JSON; 0 means no limit
}{
	{dir: "common/v1/examples/dsse", schema: "common/v1/dsse.schema.json"},
	{dir: "common/v1/examples/keyset", schema: "common/v1/keyset.schema.json"},
	{dir: "event-schema/v1/examples", schema: "event-schema/v1/event.schema.json", maxSize: 32 << 10},
	{dir: "adapter/v1/examples", schema: "adapter/v1/adapter.schema.json"},
	{dir: "adapter/v1/examples/adapter-set", schema: "adapter/v1/adapter-set.schema.json"},
	{dir: "policy/v1/examples", schema: "policy/v1/policy.schema.json"},
	{dir: "policy/v1/examples/bundle", schema: "policy/v1/bundle.schema.json"},
	{dir: "rulepack/v1/examples/pack", schema: "rulepack/v1/pack.schema.json"},
	{dir: "rulepack/v1/examples/rules", schema: "rulepack/v1/rules.schema.json"},
	{dir: "rulepack/v1/examples/ruletest", schema: "rulepack/v1/ruletest.schema.json"},
	{dir: "riskfeed/v1/examples", schema: "riskfeed/v1/riskfeed.schema.json"},
	{dir: "release/v1/examples", schema: "release/v1/release.schema.json"},
	{dir: "detectorpack/v1/examples/pack", schema: "detectorpack/v1/pack.schema.json"},
	{dir: "detectorpack/v1/examples/detectors", schema: "detectorpack/v1/detectors.schema.json"},
	{dir: "detectorpack/v1/examples/pack-set", schema: "detectorpack/v1/pack-set.schema.json"},
	{dir: "communitypack/v1/examples", schema: "communitypack/v1/communitypack.schema.json"},
	{dir: "entitlements/v1/examples/entitlements", schema: "entitlements/v1/entitlements.schema.json"},
	{dir: "entitlements/v1/examples/license", schema: "entitlements/v1/license.schema.json"},
}

func TestExamples(t *testing.T) {
	all := suites
	// API messages: examples/<Def>/ is checked against messages.schema.json#/$defs/<Def>.
	for _, api := range []string{"edge-api/v1", "account-api/v1", "org-api/v1"} {
		msgDirs, _ := filepath.Glob(api + "/examples/*")
		if len(msgDirs) == 0 {
			t.Errorf("no message examples in %s", api)
		}
		for _, d := range msgDirs {
			all = append(all, struct {
				dir     string
				schema  string
				maxSize int
			}{dir: d, schema: api + "/messages.schema.json#/$defs/" + filepath.Base(d)})
		}
	}
	for _, s := range all {
		t.Run(s.dir, func(t *testing.T) {
			sch, err := specs.Schema(s.schema)
			if err != nil {
				t.Fatalf("compile %s: %v", s.schema, err)
			}
			for _, want := range []string{"valid", "invalid"} {
				files, _ := filepath.Glob(filepath.Join(s.dir, want, "*"))
				if len(files) == 0 {
					t.Fatalf("no %s examples in %s", want, s.dir)
				}
				for _, f := range files {
					raw, err := os.ReadFile(f)
					if err != nil {
						t.Fatal(err)
					}
					inst, err := specs.Decode(f, raw)
					if err != nil {
						t.Fatalf("%s: %v", f, err)
					}
					err = sch.Validate(inst)
					switch {
					case want == "valid" && err != nil:
						t.Errorf("%s should be valid:\n%v", f, err)
					case want == "invalid" && err == nil:
						t.Errorf("%s should be invalid but passed", f)
					case want == "invalid":
						t.Logf("%s rejected: %s", filepath.Base(f), specs.FirstCause(err))
					case s.maxSize > 0:
						if n := compactSize(t, inst); n > s.maxSize {
							t.Errorf("%s is %d bytes, limit %d", f, n, s.maxSize)
						}
					}
				}
			}
		})
	}
}

func compactSize(t *testing.T, v any) int {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return buf.Len()
}
