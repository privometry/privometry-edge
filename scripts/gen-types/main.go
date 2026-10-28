// Command gen-types generates Go types from the JSON Schemas in specs/.
//
//	go run ./scripts/gen-types          # write the *.gen.go files
//	go run ./scripts/gen-types -check   # exit 1 if any generated file is stale
//
// It handles the subset of JSON Schema 2020-12 the Privometry contracts use:
// objects, arrays, maps (additionalProperties), string enums, consts,
// $ref across files, and oneOf with null for nullable values. Conditional
// keywords (if/then, allOf constraints, not) only validate and are ignored.
//
// Naming: a document root gets the name configured below, a $defs entry its
// CamelCase key, and an inline object or enum its parent's name plus the
// property name (singular for array items).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"unicode"
)

const module = "github.com/privometry/privometry-oss"

type source struct {
	schema string // path under specs/
	root   string // Go name for the document root; empty when the root is only a $defs container
}

type output struct {
	pkg     string
	dir     string
	file    string
	sources []source
}

var outputs = []output{
	{"contract", "internal/contract", "common.gen.go", []source{
		{"common/v1/common.schema.json", ""},
		{"common/v1/dsse.schema.json", "Envelope"},
		{"common/v1/keyset.schema.json", "KeySet"},
	}},
	{"events", "internal/events", "event.gen.go", []source{{"event-schema/v1/event.schema.json", "Event"}}},
	{"registry", "internal/adapters/registry", "adapter.gen.go", []source{
		{"adapter/v1/adapter.schema.json", "Adapter"},
		{"adapter/v1/adapter-set.schema.json", "AdapterSet"},
	}},
	{"bundles", "internal/cloud/bundles", "bundle.gen.go", []source{{"policy/v1/bundle.schema.json", "Bundle"}}},
	{"entitlements", "internal/cloud/entitlements", "entitlements.gen.go", []source{
		{"entitlements/v1/entitlements.schema.json", "Entitlements"},
		{"entitlements/v1/license.schema.json", "License"},
		{"entitlements/v1/feature-registry.schema.json", "FeatureRegistry"},
	}},
	{"riskfeed", "internal/riskfeed", "riskfeed.gen.go", []source{{"riskfeed/v1/riskfeed.schema.json", "Document"}}},
	{"rulepack", "internal/policy/rulepack", "rulepack.gen.go", []source{
		{"rulepack/v1/pack.schema.json", "Manifest"},
		{"rulepack/v1/ruletest.schema.json", "TestFile"},
	}},
	{"cloud", "internal/cloud", "messages.gen.go", []source{{"edge-api/v1/messages.schema.json", ""}}},
	{"account", "internal/cloud/account", "messages.gen.go", []source{{"account-api/v1/messages.schema.json", ""}}},
	{"orgapi", "internal/cloud/orgapi", "messages.gen.go", []source{{"org-api/v1/messages.schema.json", ""}}},
	{"update", "internal/update", "release.gen.go", []source{{"release/v1/release.schema.json", "Release"}}},
	{"community", "internal/community", "communitypack.gen.go", []source{{"communitypack/v1/communitypack.schema.json", "Document"}}},
	{"content", "internal/content", "detectorpack.gen.go", []source{
		{"detectorpack/v1/pack.schema.json", "Manifest"},
		{"detectorpack/v1/detectors.schema.json", "DetectorsFile"},
		{"detectorpack/v1/pack-set.schema.json", "PackSet"},
	}},
}

// handwritten maps schema locations to types written by hand.
var handwritten = map[string]typeRef{
	"common/v1/common.schema.json#/$defs/timestamp": {pkg: "contract", dir: "internal/contract", name: "Time"},
}

// ---- ordered JSON ----

type obj struct {
	keys []string
	vals map[string]any
}

func (o *obj) get(k string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[k]
	return v, ok
}

func (o *obj) str(k string) string {
	v, _ := o.get(k)
	s, _ := v.(string)
	return s
}

func (o *obj) child(k string) *obj {
	v, _ := o.get(k)
	c, _ := v.(*obj)
	return c
}

func parse(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &obj{vals: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				o.keys = append(o.keys, k)
				o.vals[k] = v
			}
			_, err := dec.Token()
			return o, err
		case '[':
			var a []any
			for dec.More() {
				v, err := parse(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
	}
	return tok, nil
}

// ---- schema loading and lookup ----

var docs = map[string]*obj{}

func load(file string) *obj {
	if d, ok := docs[file]; ok {
		return d
	}
	raw, err := os.ReadFile(path.Join("specs", file))
	if err != nil {
		log.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parse(dec)
	if err != nil {
		log.Fatalf("%s: %v", file, err)
	}
	docs[file] = v.(*obj)
	return docs[file]
}

type loc struct{ file, ptr string }

func (l loc) String() string { return l.file + "#" + l.ptr }

func (l loc) node() *obj {
	cur := any(load(l.file))
	if l.ptr == "" {
		return cur.(*obj)
	}
	for _, part := range strings.Split(strings.TrimPrefix(l.ptr, "/"), "/") {
		switch c := cur.(type) {
		case *obj:
			v, ok := c.get(part)
			if !ok {
				log.Fatalf("%s: no %q", l, part)
			}
			cur = v
		case []any:
			var i int
			_, _ = fmt.Sscan(part, &i)
			cur = c[i]
		}
	}
	n, ok := cur.(*obj)
	if !ok {
		log.Fatalf("%s: not a schema object", l)
	}
	return n
}

func (l loc) at(parts ...string) loc { return loc{l.file, l.ptr + "/" + strings.Join(parts, "/")} }

func resolveRef(from loc, ref string) loc {
	file, frag, _ := strings.Cut(ref, "#")
	if file == "" {
		file = from.file
	} else {
		file = path.Clean(path.Join(path.Dir(from.file), file))
	}
	return loc{file, frag}
}

// ---- naming ----

type typeRef struct{ pkg, dir, name string }

type named struct {
	typeRef
	at   loc
	kind string // struct or enum
}

var (
	registry = map[string]*named{} // loc string -> type
	fileOut  = map[string]*output{}
	byPkg    = map[string][]*named{}
)

func register(o *output, at loc, name, kind string) {
	key := at.String()
	if _, ok := registry[key]; ok {
		return
	}
	for _, n := range byPkg[o.pkg] {
		if n.name == name {
			log.Fatalf("name %s.%s used for both %s and %s", o.pkg, name, n.at, at)
		}
	}
	n := &named{typeRef: typeRef{o.pkg, o.dir, name}, at: at, kind: kind}
	registry[key] = n
	byPkg[o.pkg] = append(byPkg[o.pkg], n)
	if kind == "struct" {
		nameChildren(o, at, name)
	}
}

func isStruct(n *obj) bool { return n.child("properties") != nil }
func isEnum(n *obj) bool   { _, ok := n.get("enum"); return ok }

// nameChildren names the inline objects and enums under a struct.
func nameChildren(o *output, at loc, parent string) {
	props := at.node().child("properties")
	for _, p := range props.keys {
		pl := at.at("properties", escape(p))
		nameInline(o, pl, parent+goName(p), parent+singular(goName(p)))
	}
}

func nameInline(o *output, at loc, name, itemName string) {
	n := at.node()
	if _, ok := n.get("$ref"); ok {
		return
	}
	switch {
	case isStruct(n):
		register(o, at, name, "struct")
	case isEnum(n):
		register(o, at, name, "enum")
	case n.str("type") == "array" && n.child("items") != nil:
		nameInline(o, at.at("items"), itemName, itemName)
	case n.child("additionalProperties") != nil:
		nameInline(o, at.at("additionalProperties"), itemName, itemName)
	}
	if alts, ok := n.get("oneOf"); ok {
		for i, a := range alts.([]any) {
			if a.(*obj).str("type") != "null" {
				nameInline(o, at.at("oneOf", fmt.Sprint(i)), name, itemName)
			}
		}
	}
}

func escape(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }

var initialisms = map[string]string{
	"id": "ID", "ids": "IDs", "cli": "CLI", "html": "HTML", "url": "URL", "uri": "URI", "api": "API", "mcp": "MCP", "os": "OS", "csr": "CSR",
	"sha256": "SHA256", "http": "HTTP", "https": "HTTPS", "json": "JSON", "ide": "IDE", "cvss": "CVSS",
	"oci": "OCI", "uid": "UID", "sql": "SQL", "ssh": "SSH", "tls": "TLS", "ip": "IP", "jwt": "JWT",
	"pem": "PEM", "dsse": "DSSE", "keyid": "KeyID", "vsx": "VSX", "aks": "AKS",
}

func goName(s string) string {
	var words []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0]
		}
	}
	for i, r := range s {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ' ' || r == '+' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && len(cur) > 0 && unicode.IsLower(cur[len(cur)-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	var b strings.Builder
	for _, w := range words {
		if up, ok := initialisms[strings.ToLower(w)]; ok {
			b.WriteString(up)
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

func singular(s string) string {
	switch {
	case strings.HasSuffix(s, "ies"):
		return strings.TrimSuffix(s, "ies") + "y"
	case strings.HasSuffix(s, "ss"), strings.HasSuffix(s, "us"):
		return s
	case strings.HasSuffix(s, "s"):
		return strings.TrimSuffix(s, "s")
	}
	return s
}

// ---- type expressions ----

type fileCtx struct {
	out     *output
	imports map[string]bool
	kinds   map[string]string // type expression -> struct or enum, for named types
}

func (c *fileCtx) qualify(t typeRef, kind string) string {
	name := t.name
	if t.pkg != c.out.pkg {
		c.imports[module+"/"+t.dir] = true
		name = t.pkg + "." + t.name
	}
	c.kinds[name] = kind
	return name
}

func (c *fileCtx) goType(at loc) string {
	key := at.String()
	if h, ok := handwritten[key]; ok {
		return c.qualify(h, "struct")
	}
	if n, ok := registry[key]; ok {
		return c.qualify(n.typeRef, n.kind)
	}
	n := at.node()
	if ref := n.str("$ref"); ref != "" {
		return c.goType(resolveRef(at, ref))
	}
	if alts, ok := n.get("oneOf"); ok {
		var types []string
		nullable := false
		for i, a := range alts.([]any) {
			if a.(*obj).str("type") == "null" {
				nullable = true
				continue
			}
			types = append(types, c.goType(at.at("oneOf", fmt.Sprint(i))))
		}
		t := "any"
		if len(slices.Compact(slices.Clone(types))) == 1 {
			t = types[0]
		}
		if nullable && t != "any" && !strings.HasPrefix(t, "*") {
			return "*" + t
		}
		return t
	}
	if all, ok := n.get("allOf"); ok && n.str("type") == "" {
		for i, a := range all.([]any) {
			if a.(*obj).str("$ref") != "" {
				return c.goType(at.at("allOf", fmt.Sprint(i)))
			}
		}
	}
	if types, ok := n.get("type"); ok {
		if list, ok := types.([]any); ok && slices.Contains(list, any("object")) {
			if slices.Contains(list, any("null")) {
				return "*map[string]any" // so an empty object survives encoding, apart from null
			}
			return "map[string]any"
		}
	}
	if cv, ok := n.get("const"); ok {
		if _, isStr := cv.(string); isStr {
			return "string"
		}
	}
	switch n.str("type") {
	case "string":
		return "string"
	case "integer":
		return "int64"
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		return "[]" + c.goType(at.at("items"))
	case "object", "":
		if isStruct(n) {
			log.Fatalf("%s: inline object has no name", at)
		}
		if ap := n.child("additionalProperties"); ap != nil {
			return "map[string]" + c.goType(at.at("additionalProperties"))
		}
		if n.str("type") == "object" {
			return "map[string]any"
		}
	}
	if isEnum(n) {
		return "string"
	}
	return "any"
}

// ---- emission ----

func comment(b *strings.Builder, indent, text string) {
	for _, para := range strings.Split(strings.TrimSpace(text), "\n") {
		line := indent + "//"
		for _, w := range strings.Fields(para) {
			if len(line)+1+len(w) > 80 && line != indent+"//" {
				b.WriteString(line + "\n")
				line = indent + "//"
			}
			line += " " + w
		}
		b.WriteString(line + "\n")
	}
}

func description(at loc) string {
	n := at.node()
	if d := n.str("description"); d != "" {
		return d
	}
	if ref := n.str("$ref"); ref != "" {
		return description(resolveRef(at, ref))
	}
	return ""
}

func emitEnum(_ *fileCtx, b *strings.Builder, t *named) {
	fmt.Fprintf(b, "// %s is generated from %s.\n", t.name, t.at)
	if d := description(t.at); d != "" {
		b.WriteString("//\n")
		comment(b, "", d)
	}
	fmt.Fprintf(b, "type %s string\n\n", t.name)
	values, _ := t.at.node().get("enum")
	fmt.Fprintf(b, "// Values of %s.\nconst (\n", t.name)
	for _, v := range values.([]any) {
		s := v.(string)
		fmt.Fprintf(b, "\t%s %s = %q\n", t.name+goName(s), t.name, s)
	}
	b.WriteString(")\n\n")
}

func emitStruct(c *fileCtx, b *strings.Builder, t *named) {
	n := t.at.node()
	fmt.Fprintf(b, "// %s is generated from %s.\n", t.name, t.at)
	if d := n.str("description"); d != "" {
		b.WriteString("//\n")
		comment(b, "", d)
	}
	fmt.Fprintf(b, "type %s struct {\n", t.name)
	var required []string
	if r, ok := n.get("required"); ok {
		for _, x := range r.([]any) {
			required = append(required, x.(string))
		}
	}
	props := n.child("properties")
	for i, p := range props.keys {
		pl := t.at.at("properties", escape(p))
		typ := c.goType(pl)
		req := slices.Contains(required, p)
		omit := ",omitempty"
		if req {
			omit = ""
		} else if c.needsPointer(typ) {
			typ = "*" + typ
		}
		if d := description(pl); d != "" {
			if i > 0 {
				b.WriteString("\n")
			}
			comment(b, "\t", d)
		}
		fmt.Fprintf(b, "\t%s %s `json:\"%s%s\"`\n", goName(p), typ, p, omit)
	}
	b.WriteString("}\n\n")
}

// needsPointer reports whether an optional field needs a pointer to tell
// "absent" from the zero value: numbers, booleans and structs.
func (c *fileCtx) needsPointer(typ string) bool {
	switch typ {
	case "int64", "float64", "bool":
		return true
	}
	return c.kinds[typ] == "struct"
}

func schemaConsts(_ *fileCtx, b *strings.Builder, o *output) {
	var lines []string
	for _, s := range o.sources {
		if s.root == "" {
			continue
		}
		if sc := load(s.schema).child("properties").child("schema"); sc != nil {
			if v, ok := sc.get("const"); ok {
				lines = append(lines, fmt.Sprintf("\t%sSchema = %q", s.root, v))
			}
		}
	}
	if len(lines) > 0 {
		b.WriteString("// Schema identifiers for the documents in this file.\nconst (\n" + strings.Join(lines, "\n") + "\n)\n\n")
	}
}

func generate(o *output) []byte {
	c := &fileCtx{out: o, imports: map[string]bool{}, kinds: map[string]string{}}
	var body strings.Builder
	schemaConsts(c, &body, o)
	for _, t := range byPkg[o.pkg] {
		if t.kind == "enum" {
			emitEnum(c, &body, t)
		} else {
			emitStruct(c, &body, t)
		}
	}
	var b strings.Builder
	var srcs []string
	for _, s := range o.sources {
		srcs = append(srcs, "specs/"+s.schema)
	}
	fmt.Fprintf(&b, "// Code generated by scripts/gen-types from %s; DO NOT EDIT.\n\n", strings.Join(srcs, ", "))
	fmt.Fprintf(&b, "package %s\n\n", o.pkg)
	if len(c.imports) > 0 {
		var imps []string
		for i := range c.imports {
			imps = append(imps, fmt.Sprintf("\t%q", i))
		}
		sort.Strings(imps)
		b.WriteString("import (\n" + strings.Join(imps, "\n") + "\n)\n\n")
	}
	b.WriteString(body.String())
	src, err := format.Source([]byte(b.String()))
	if err != nil {
		log.Fatalf("%s: %v\n%s", o.file, err, b.String())
	}
	return src
}

func main() {
	check := flag.Bool("check", false, "report stale generated files instead of writing them")
	flag.Parse()
	log.SetFlags(0)

	// Pass 1: name every root, $defs entry and inline object or enum.
	for i := range outputs {
		o := &outputs[i]
		for _, s := range o.sources {
			fileOut[s.schema] = o
			root := loc{s.schema, ""}
			if s.root != "" {
				register(o, root, s.root, "struct")
			}
			defs := root.node().child("$defs")
			if defs == nil {
				continue
			}
			for _, k := range defs.keys {
				at := root.at("$defs", escape(k))
				if _, ok := handwritten[at.String()]; ok {
					continue
				}
				n := at.node()
				switch {
				case isStruct(n):
					register(o, at, goName(k), "struct")
				case isEnum(n):
					register(o, at, goName(k), "enum")
				}
			}
		}
	}

	// Pass 2: emit.
	stale := false
	for i := range outputs {
		o := &outputs[i]
		src := generate(o)
		target := path.Join(o.dir, o.file)
		if *check {
			old, _ := os.ReadFile(target)
			if !bytes.Equal(old, src) {
				fmt.Fprintf(os.Stderr, "stale: %s\n", target)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(o.dir, 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(target, src, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %s (%d types)\n", target, len(byPkg[o.pkg]))
	}
	if stale {
		fmt.Fprintln(os.Stderr, "run: go run ./scripts/gen-types")
		os.Exit(1)
	}
}
