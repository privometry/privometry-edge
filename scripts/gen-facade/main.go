// Command gen-facade writes pkg/edge's subpackages from pkg/edge/facade.txt:
// for each internal package listed, a facade package of aliases (types),
// constants, variables and wrapper functions for exactly the names listed,
// so a connected build outside this module can use them.
//
//	go run ./scripts/gen-facade          # write pkg/edge/*/facade.gen.go
//	go run ./scripts/gen-facade -check   # exit 1 if any facade is stale
//
// A function's signature may only use builtin types, standard library types
// and types the facade exposes; anything else is an error, which names the
// type to add to facade.txt.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/doc"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	module   = "github.com/privometry/privometry-edge"
	listFile = "pkg/edge/facade.txt"
	outName  = "facade.gen.go"
)

type name struct{ orig, as string }

type source struct {
	pkg   string // import path under the module, such as internal/contract
	names []name
}

type facade struct {
	dir     string // under pkg/edge
	sources []source
}

func main() {
	check := flag.Bool("check", false, "exit 1 if a generated facade is stale")
	flag.Parse()
	facades, err := readList(listFile)
	if err != nil {
		log.Fatal(err)
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil).(types.ImporterFrom)
	// Where each exposed type lives in the facade, for function signatures.
	exposed := map[string]string{} // "<pkg path>.<Name>" -> "<facade import path>.<As>"
	for _, f := range facades {
		for _, s := range f.sources {
			for _, n := range s.names {
				exposed[module+"/"+s.pkg+"."+n.orig] = module + "/pkg/edge/" + f.dir + "." + n.as
			}
		}
	}
	stale := false
	for _, f := range facades {
		src, err := generate(fset, imp, f, exposed)
		if err != nil {
			log.Fatal(err)
		}
		out := filepath.Join("pkg/edge", f.dir, outName)
		if *check {
			cur, _ := os.ReadFile(out)
			if !bytes.Equal(cur, src) {
				fmt.Println("stale:", out)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(out, src, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", out)
	}
	if stale {
		fmt.Println("run: go run ./scripts/gen-facade")
		os.Exit(1)
	}
}

func readList(file string) ([]*facade, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byDir := map[string]*facade{}
	var order []*facade
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("%s:%d: want a package, a facade and names", file, line)
		}
		fc := byDir[fields[1]]
		if fc == nil {
			fc = &facade{dir: fields[1]}
			byDir[fields[1]] = fc
			order = append(order, fc)
		}
		s := source{pkg: fields[0]}
		for _, n := range fields[2:] {
			orig, as, ok := strings.Cut(n, ":")
			if !ok {
				as = orig
			}
			s.names = append(s.names, name{orig, as})
		}
		fc.sources = append(fc.sources, s)
	}
	return order, sc.Err()
}

func generate(fset *token.FileSet, imp types.ImporterFrom, f *facade, exposed map[string]string) ([]byte, error) {
	self := module + "/pkg/edge/" + f.dir
	imports := map[string]string{} // path -> name used in this file
	used := map[string]bool{}
	var body bytes.Buffer
	qual := func(p *types.Package) string {
		used[p.Path()] = true
		if imports[p.Path()] == "" {
			imports[p.Path()] = p.Name()
		}
		return imports[p.Path()]
	}
	// Signatures name exposed types by their facade name.
	sigQual := func() types.Qualifier {
		return func(p *types.Package) string {
			if !strings.HasPrefix(p.Path(), module+"/") {
				return qual(p) // standard library
			}
			return "\x00" + p.Path() + "\x01" // resolved below
		}
	}
	for _, s := range f.sources {
		pkg, err := imp.ImportFrom(module+"/"+s.pkg, ".", 0)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.pkg, err)
		}
		docs, err := docsOf(fset, s.pkg)
		if err != nil {
			return nil, err
		}
		local := qual(pkg)
		for _, n := range s.names {
			obj := pkg.Scope().Lookup(n.orig)
			if obj == nil || !obj.Exported() {
				return nil, fmt.Errorf("%s: no exported %s", s.pkg, n.orig)
			}
			comment := firstSentence(docs[n.orig])
			if comment == "" {
				comment = "is " + path.Base(s.pkg) + "." + n.orig + "."
			} else if n.as != n.orig {
				comment = strings.Replace(comment, n.orig, n.as, 1)
			}
			if !strings.HasPrefix(comment, n.as+" ") {
				comment = n.as + " " + strings.TrimPrefix(comment, n.orig+" ")
			}
			fmt.Fprintf(&body, "\n// %s\n", comment)
			ref := local + "." + n.orig
			switch o := obj.(type) {
			case *types.TypeName:
				if tp, ok := o.Type().(*types.Named); ok && tp.TypeParams().Len() > 0 {
					return nil, fmt.Errorf("%s.%s: generic types are not supported", s.pkg, n.orig)
				}
				fmt.Fprintf(&body, "type %s = %s\n", n.as, ref)
			case *types.Const:
				fmt.Fprintf(&body, "const %s = %s\n", n.as, ref)
			case *types.Var:
				fmt.Fprintf(&body, "var %s = %s\n", n.as, ref)
			case *types.Func:
				sig := o.Type().(*types.Signature)
				params, results := tupleString(sig.Params(), sig.Variadic(), sigQual()), tupleString(sig.Results(), false, sigQual())
				params, err1 := resolve(params, exposed, self, qual)
				results, err2 := resolve(results, exposed, self, qual)
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("%s.%s: %v", s.pkg, n.orig, errors(err1, err2))
				}
				args := argNames(sig)
				call := ref + "(" + strings.Join(args, ", ") + ")"
				if sig.Variadic() {
					call = ref + "(" + strings.Join(args, ", ") + "...)"
				}
				ret := "return "
				if sig.Results().Len() == 0 {
					ret = ""
				}
				if results != "" && (sig.Results().Len() > 1 || sig.Results().At(0).Name() != "") {
					results = "(" + results + ")"
				}
				fmt.Fprintf(&body, "func %s(%s) %s { %s%s }\n", n.as, params, results, ret, call)
			default:
				return nil, fmt.Errorf("%s.%s: unsupported %T", s.pkg, n.orig, obj)
			}
		}
	}
	var out bytes.Buffer
	pkgName := path.Base(f.dir)
	fmt.Fprintf(&out, "// Code generated by scripts/gen-facade from pkg/edge/facade.txt; DO NOT EDIT.\n\n")
	var from []string
	for _, s := range f.sources {
		from = append(from, s.pkg)
	}
	fmt.Fprintf(&out, "// Package %s re-exports, for connected builds, the names that\n// privometry-connect uses from:\n//\n", pkgName)
	for _, f := range from {
		fmt.Fprintf(&out, "//   - %s\n", f)
	}
	fmt.Fprintf(&out, "package %s\n\nimport (\n", pkgName)
	var std, mod []string
	for p := range used {
		if strings.HasPrefix(p, module+"/") {
			mod = append(mod, p)
		} else {
			std = append(std, p)
		}
	}
	sort.Strings(std)
	sort.Strings(mod)
	for i, group := range [][]string{std, mod} {
		if i > 0 && len(std) > 0 && len(mod) > 0 {
			out.WriteString("\n")
		}
		for _, p := range group {
			if path.Base(p) == imports[p] {
				fmt.Fprintf(&out, "\t%q\n", p)
			} else {
				fmt.Fprintf(&out, "\t%s %q\n", imports[p], p)
			}
		}
	}
	out.WriteString(")\n")
	out.Write(body.Bytes())
	src, err := format.Source(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: %w\n%s", f.dir, err, out.Bytes())
	}
	return src, nil
}

// resolve replaces the module's package markers in a signature with the
// facade's names for the types, importing other facades as needed.
func resolve(s string, exposed map[string]string, self string, qual func(*types.Package) string) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, 0)
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		b.WriteString(s[:i])
		s = s[i+1:]
		j := strings.IndexByte(s, 1)
		pkgPath := s[:j]
		s = s[j+2:] // the marker's end and the dot
		k := 0
		for k < len(s) && (s[k] == '_' || 'a' <= s[k]|0x20 && s[k]|0x20 <= 'z' || '0' <= s[k] && s[k] <= '9') {
			k++
		}
		typ := s[:k]
		s = s[k:]
		to, ok := exposed[pkgPath+"."+typ]
		if !ok {
			return "", fmt.Errorf("uses %s.%s, which the facade does not expose", strings.TrimPrefix(pkgPath, module+"/"), typ)
		}
		fpkg, fname := to[:strings.LastIndexByte(to, '.')], to[strings.LastIndexByte(to, '.')+1:]
		if fpkg == self {
			b.WriteString(fname)
			continue
		}
		b.WriteString(qual(types.NewPackage(fpkg, path.Base(fpkg))) + "." + fname)
	}
}

func tupleString(t *types.Tuple, variadic bool, q types.Qualifier) string {
	var parts []string
	for i := 0; i < t.Len(); i++ {
		v := t.At(i)
		typ := types.TypeString(v.Type(), q)
		if variadic && i == t.Len()-1 {
			typ = "..." + types.TypeString(v.Type().(*types.Slice).Elem(), q)
		}
		if v.Name() != "" && v.Name() != "_" {
			parts = append(parts, v.Name()+" "+typ)
		} else if t.Len() > 0 && t.At(0).Name() != "" {
			parts = append(parts, fmt.Sprintf("p%d %s", i, typ))
		} else {
			parts = append(parts, typ)
		}
	}
	return strings.Join(parts, ", ")
}

// argNames are the names a wrapper passes on: the parameters' own, or p0, p1…
func argNames(sig *types.Signature) []string {
	var out []string
	named := sig.Params().Len() > 0 && sig.Params().At(0).Name() != ""
	for i := 0; i < sig.Params().Len(); i++ {
		if named && sig.Params().At(i).Name() != "_" {
			out = append(out, sig.Params().At(i).Name())
		} else {
			out = append(out, fmt.Sprintf("p%d", i))
		}
	}
	return out
}

func errors(errs ...error) string {
	var s []string
	for _, e := range errs {
		if e != nil {
			s = append(s, e.Error())
		}
	}
	return strings.Join(s, "; ")
}

// docsOf reads the doc comments of a package's top-level declarations.
func docsOf(fset *token.FileSet, dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	out := map[string]string{}
	{
		for _, file := range files {
			for _, d := range file.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil && d.Doc != nil {
						out[d.Name.Name] = d.Doc.Text()
					}
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						text := ""
						switch sp := sp.(type) {
						case *ast.TypeSpec:
							if sp.Doc != nil {
								text = sp.Doc.Text()
							} else if d.Doc != nil && len(d.Specs) == 1 {
								text = d.Doc.Text()
							}
							out[sp.Name.Name] = text
						case *ast.ValueSpec:
							if sp.Doc != nil {
								text = sp.Doc.Text()
							} else if sp.Comment != nil {
								text = sp.Comment.Text()
							} else if d.Doc != nil && len(d.Specs) == 1 {
								text = d.Doc.Text()
							}
							for _, n := range sp.Names {
								out[n.Name] = text
							}
						}
					}
				}
			}
		}
	}
	return out, nil
}

// firstSentence is a doc comment's first sentence on one line.
func firstSentence(s string) string {
	var p doc.Package
	s = strings.Join(strings.Fields(p.Synopsis(s)), " ")
	if slices.Contains([]string{"", "."}, s) {
		return ""
	}
	return s
}
