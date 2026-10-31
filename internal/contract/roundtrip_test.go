package contract_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/internal/riskfeed"
	"github.com/privometry/privometry-edge/internal/update"
	"github.com/privometry/privometry-edge/specs"
)

const root = "../.."

type target struct {
	glob   string     // files under the repo root
	schema string     // schema path under specs/
	new    func() any // returns a pointer to the generated type
}

var targets = []target{
	{"specs/common/v1/examples/dsse/valid/*", "common/v1/dsse.schema.json", func() any { return new(contract.Envelope) }},
	{"specs/common/v1/examples/keyset/valid/*", "common/v1/keyset.schema.json", func() any { return new(contract.KeySet) }},
	{"specs/conformance/signatures/*.json", "common/v1/keyset.schema.json", func() any { return new(contract.KeySet) }},
	{"specs/event-schema/v1/examples/valid/*", "event-schema/v1/event.schema.json", func() any { return new(events.Event) }},
	{"specs/adapter/v1/examples/valid/*", "adapter/v1/adapter.schema.json", func() any { return new(registry.Adapter) }},
	{"specs/adapter/v1/examples/adapter-set/valid/*", "adapter/v1/adapter-set.schema.json", func() any { return new(registry.AdapterSet) }},
	{"specs/policy/v1/examples/bundle/valid/*", "policy/v1/bundle.schema.json", func() any { return new(bundle.Bundle) }},
	{"specs/riskfeed/v1/examples/valid/*", "riskfeed/v1/riskfeed.schema.json", func() any { return new(riskfeed.Document) }},
	{"specs/release/v1/examples/valid/*", "release/v1/release.schema.json", func() any { return new(update.Release) }},
	{"specs/detectorpack/v1/examples/pack/valid/*", "detectorpack/v1/pack.schema.json", func() any { return new(content.Manifest) }},
	{"specs/detectorpack/v1/examples/detectors/valid/*", "detectorpack/v1/detectors.schema.json", func() any { return new(content.DetectorsFile) }},
	{"specs/detectorpack/v1/examples/pack-set/valid/*", "detectorpack/v1/pack-set.schema.json", func() any { return new(content.PackSet) }},
	{"specs/rulepack/v1/examples/pack/valid/*", "rulepack/v1/pack.schema.json", func() any { return new(rulepack.Manifest) }},
	{"specs/rulepack/v1/examples/ruletest/valid/*", "rulepack/v1/ruletest.schema.json", func() any { return new(rulepack.TestFile) }},
	{"rulepacks/*/pack.yaml", "rulepack/v1/pack.schema.json", func() any { return new(rulepack.Manifest) }},
	{"rulepacks/*/tests/*.test.yaml", "rulepack/v1/ruletest.schema.json", func() any { return new(rulepack.TestFile) }},
}

// TestRoundTrip decodes every valid example strictly into its generated type,
// encodes it again, and requires the same document, still valid.
func TestRoundTrip(t *testing.T) {
	for _, tg := range targets {
		files, _ := filepath.Glob(filepath.Join(root, tg.glob))
		if len(files) == 0 {
			t.Errorf("no files for %s", tg.glob)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "vectors.json") {
				continue
			}
			t.Run(strings.TrimPrefix(f, root+"/"), func(t *testing.T) { roundTrip(t, f, tg) })
		}
	}
}

func roundTrip(t *testing.T, file string, tg target) {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := specs.Decode(file, raw) // YAML becomes JSON-compatible values
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(inst)
	if err != nil {
		t.Fatal(err)
	}
	v := tg.new()
	dec := json.NewDecoder(bytes.NewReader(original))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode into %T: %v", v, err)
	}
	again, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := specs.Validate(tg.schema, "roundtrip.json", again); err != nil {
		t.Errorf("re-encoded document is invalid: %v", err)
	}
	if a, b := normalize(t, original), normalize(t, again); !reflect.DeepEqual(a, b) {
		t.Errorf("round trip changed the document\n before %s\n after  %s", original, again)
	}
}

// normalize decodes JSON and drops null members and empty arrays: for an
// optional field, absent, null and [] mean the same thing in every contract.
// Required fields are covered by re-validating the encoded document.
func normalize(t *testing.T, raw []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return dropNulls(v)
}

func dropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if a, ok := e.([]any); e == nil || ok && len(a) == 0 {
				delete(x, k)
				continue
			}
			x[k] = dropNulls(e)
		}
	case []any:
		for i, e := range x {
			x[i] = dropNulls(e)
		}
	}
	return v
}
