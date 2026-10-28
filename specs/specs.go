// Package specs embeds Privometry's contract schemas so every Go component validates
// files against the exact spec version it was built with.
package specs

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// IDBase prefixes every schema's $id; the rest of the $id is its path here.
const IDBase = "https://privometry.dev/specs/"

//go:embed */v1/*.schema.json
var schemaFS embed.FS

// CedarSchema is policy/v1/privometry.cedarschema.
//
//go:embed policy/v1/privometry.cedarschema
var CedarSchema []byte

var (
	compileOnce sync.Once
	compiler    *jsonschema.Compiler
	compileErr  error
)

// Schema returns the compiled schema at path, for example "policy/v1/policy.schema.json".
func Schema(path string) (*jsonschema.Schema, error) {
	compileOnce.Do(func() { compiler, compileErr = newCompiler() })
	if compileErr != nil {
		return nil, compileErr
	}
	return compiler.Compile(IDBase + path)
}

// newCompiler registers every embedded schema under its $id, so relative $refs
// between contracts resolve without network access, and checks that each $id
// matches its file path.
func newCompiler() (*jsonschema.Compiler, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.AssertContent()
	err := fs.WalkDir(schemaFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := schemaFS.ReadFile(p)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		id, _ := doc.(map[string]any)["$id"].(string)
		if want := IDBase + p; id != want {
			return fmt.Errorf("%s: $id is %q, want %q", p, id, want)
		}
		return c.AddResource(id, doc)
	})
	return c, err
}

// Decode turns a JSON or YAML document (chosen by the file name's extension)
// into the value form the validator expects.
func Decode(name string, raw []byte) (any, error) {
	if ext := path.Ext(name); ext == ".yaml" || ext == ".yml" {
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if doc.Kind == 0 {
			return nil, errors.New("empty YAML document")
		}
		v, err := fromYAML(&doc)
		if err != nil {
			return nil, err
		}
		if raw, err = json.Marshal(v); err != nil {
			return nil, err
		}
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(raw))
}

// Validate decodes raw and checks it against the schema at schemaPath.
func Validate(schemaPath, name string, raw []byte) error {
	sch, err := Schema(schemaPath)
	if err != nil {
		return err
	}
	inst, err := Decode(name, raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%s: %s", name, FirstCause(err))
	}
	return nil
}

// DecodeInto validates raw against the schema at schemaPath, then decodes it
// into v (a pointer to a generated type) rejecting fields v does not know.
// YAML is converted to JSON first, so generated types need only json tags.
func DecodeInto(schemaPath, name string, raw []byte, v any) error {
	sch, err := Schema(schemaPath)
	if err != nil {
		return err
	}
	inst, err := Decode(name, raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%s: %s", name, FirstCause(err))
	}
	js, err := json.Marshal(inst)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(js))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// FirstCause returns the deepest validation cause as "at <pointer>: <reason>",
// which names the failing keyword more usefully than the full error tree.
func FirstCause(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err.Error()
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	msg := ve.ErrorKind.LocalizedString(message.NewPrinter(language.English))
	return fmt.Sprintf("at %q: %s", "/"+strings.Join(ve.InstanceLocation, "/"), msg)
}

// fromYAML converts a YAML document to JSON-compatible values. Timestamps
// keep their literal text, so a policy's expires_at is validated as written
// rather than after YAML has reinterpreted it.
func fromYAML(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		return fromYAML(n.Content[0])
	case yaml.AliasNode:
		return fromYAML(n.Alias)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := fromYAML(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" {
				merged, err := fromYAML(val)
				if err != nil {
					return nil, err
				}
				m, _ := merged.(map[string]any)
				for mk, mv := range m {
					if _, set := out[mk]; !set {
						out[mk] = mv
					}
				}
				continue
			}
			v, err := fromYAML(val)
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.ScalarNode:
		if n.Tag == "!!timestamp" {
			return n.Value, nil
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}
