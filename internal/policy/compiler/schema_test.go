package compiler_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/privometry/privometry-oss/internal/policy/compiler"
)

// TestTypesCoverSchema keeps the hand-written policy types in step with
// policy.schema.json. They are not generated because conditions accept a
// string or a list, which reads better as compiler.List than as generated code.
// A new schema property fails this test until it is handled or listed below.
func TestTypesCoverSchema(t *testing.T) {
	raw, err := os.ReadFile(specsDir + "/policy/v1/policy.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
		Defs       map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		typ       any
		props     map[string]any
		notLoaded []string // schema properties deliberately not decoded yet
	}{
		{"Policy", compiler.Policy{}, schema.Properties, []string{"ext"}},
		{"Defaults", compiler.Defaults{}, schema.Defs["defaults"].Properties, nil},
		{"Rule", compiler.Rule{}, schema.Defs["rule"].Properties, nil},
		{"Conditions", compiler.Conditions{}, schema.Defs["facts"].Properties, nil},
		{"Exception", compiler.Exception{}, schema.Defs["exception"].Properties, nil},
		{"AllowEntry", compiler.AllowEntry{}, schema.Defs["allow_entry"].Properties, nil},
	}
	for _, c := range cases {
		var fields []string
		rt := reflect.TypeOf(c.typ)
		for i := range rt.NumField() {
			tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ",")
			if tag != "" && tag != "-" {
				fields = append(fields, tag)
			}
		}
		var want []string
		for p := range c.props {
			if !slices.Contains(c.notLoaded, p) {
				want = append(want, p)
			}
		}
		sort.Strings(fields)
		sort.Strings(want)
		if !slices.Equal(fields, want) {
			t.Errorf("%s fields %v\n  schema properties %v", c.name, fields, want)
		}
	}
}
