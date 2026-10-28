package compiler

import (
	"fmt"
	"slices"
	"strings"
)

// Options say where compiled rules come from.
type Options struct {
	// Qualifier prefixes rule IDs: a pack ID (privometry/core-catastrophic) or a policy name.
	Qualifier string
	// Layer is builtin, repo, user or org.
	Layer string
	// DefaultMode applies to rules without a mode; empty means enforce.
	DefaultMode string
}

// Output holds Cedar text for the two policy sets.
type Output struct {
	Enforce string
	Monitor string // recorded as would_verdict only
}

var riskLevels = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Entry is one rule ready to compile, with its final ID, layer and mode, and
// any exceptions that lift it.
type Entry struct {
	ID         string // qualified, for example privometry/core-catastrophic:git-force-push
	Layer      string // builtin, repo, user or org
	Mode       string // enforce or monitor
	Rule       Rule
	Exceptions []*Conditions
}

// Compile translates rules from one source into Cedar. Each rule becomes one
// policy annotated with @id, @verdict, @layer and @category; deny rules become
// forbid, ask and allow rules become permit.
func Compile(rules []Rule, opts Options) (Output, error) {
	entries := make([]Entry, 0, len(rules))
	for _, r := range rules {
		id := r.ID
		if opts.Qualifier != "" {
			id = opts.Qualifier + ":" + r.ID
		}
		mode := r.Mode
		if mode == "" {
			mode = opts.DefaultMode
		}
		entries = append(entries, Entry{ID: id, Layer: opts.Layer, Mode: mode, Rule: r})
	}
	return CompileEntries(entries)
}

// CompileEntries compiles rules that may come from different layers into one
// enforce set and one monitor set. IDs must be unique.
func CompileEntries(entries []Entry) (Output, error) {
	var enforce, monitor strings.Builder
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.ID] {
			return Output{}, fmt.Errorf("rule %q: duplicate id", e.ID)
		}
		seen[e.ID] = true
		text, err := compileRule(e)
		if err != nil {
			return Output{}, fmt.Errorf("rule %q: %w", e.ID, err)
		}
		if e.Mode == "monitor" {
			monitor.WriteString(text)
		} else {
			enforce.WriteString(text)
		}
	}
	return Output{Enforce: enforce.String(), Monitor: monitor.String()}, nil
}

func compileRule(e Entry) (string, error) {
	r := e.Rule
	if r.When == nil {
		return "", fmt.Errorf("missing when")
	}
	effect := "permit"
	switch r.Verdict {
	case "deny":
		effect = "forbid"
	case "allow", "ask":
	default:
		return "", fmt.Errorf("unknown verdict %q", r.Verdict)
	}
	category := r.Category
	if category == "" {
		category = "other"
	}
	id := e.ID

	when, err := conditions(r.When, false)
	if err != nil {
		return "", fmt.Errorf("when: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "@id(%s)\n@verdict(%s)\n@layer(%s)\n@category(%s)\n", quote(id), quote(r.Verdict), quote(e.Layer), quote(category))
	fmt.Fprintf(&b, "%s (principal, %s, resource)", effect, actionScope(r.When.Action))
	if len(when) > 0 {
		fmt.Fprintf(&b, "\nwhen { %s }", strings.Join(when, " && "))
	}
	if r.Unless != nil {
		unless, err := conditions(r.Unless, true)
		if err != nil {
			return "", fmt.Errorf("unless: %w", err)
		}
		if len(unless) > 0 {
			fmt.Fprintf(&b, "\nunless { %s }", strings.Join(unless, " && "))
		}
	}
	// Each exception is its own unless clause: any one that holds lifts the rule.
	for _, x := range e.Exceptions {
		cond, err := conditions(x, true)
		if err != nil {
			return "", fmt.Errorf("exception: %w", err)
		}
		if len(cond) > 0 {
			fmt.Fprintf(&b, "\nunless { %s }", strings.Join(cond, " && "))
		}
	}
	b.WriteString(";\n\n")
	return b.String(), nil
}

func actionUID(a string) string { return "Privometry::Action::" + quote(a) }

// actionScope puts when.action in the policy scope, where Cedar indexes it.
func actionScope(actions List) string {
	switch len(actions) {
	case 0:
		return "action"
	case 1:
		return "action == " + actionUID(actions[0])
	}
	uids := make([]string, len(actions))
	for i, a := range actions {
		uids[i] = actionUID(a)
	}
	return "action in [" + strings.Join(uids, ", ") + "]"
}

// conditions returns one expression per set fact. In a when clause the action
// lives in the scope; in an unless clause it becomes an expression.
func conditions(c *Conditions, includeAction bool) ([]string, error) {
	var out []string
	add := func(e string) {
		if e != "" {
			out = append(out, e)
		}
	}
	if includeAction && len(c.Action) > 0 {
		parts := make([]string, len(c.Action))
		for i, a := range c.Action {
			parts[i] = "action == " + actionUID(a)
		}
		add(or(parts))
	}
	add(setContains("context.intent", c.Intent))
	add(setContains("context.category", c.Category))
	if c.RiskAtLeast != "" {
		n, ok := riskLevels[c.RiskAtLeast]
		if !ok {
			return nil, fmt.Errorf("unknown risk %q", c.RiskAtLeast)
		}
		add(fmt.Sprintf("context.risk >= %d", n))
	}
	add(match("context.program", c.Program))
	add(subcommand(c.Subcommand))
	add(setContains("context.flags", c.Flags))
	add(match("context.path_class", c.PathClass))
	add(match("context.target_path", c.TargetPath))
	add(match("context.host", c.Host))
	add(match("context.mcp_server", c.MCPServer))
	add(match("context.mcp_tool", c.MCPTool))
	add(match("context.catalog_status", c.CatalogStatus))
	add(boolean("context.untrusted_input_seen", c.UntrustedInputSeen))
	if slices.Contains(c.SecretDetected, "any") {
		add("!context.secret_detected.isEmpty()")
	} else {
		add(setContains("context.secret_detected", c.SecretDetected))
	}
	add(match("context.injection_detected", c.InjectionDetected))
	add(boolean("context.injection_seen", c.InjectionSeen))
	add(boolean("context.hidden_content", c.HiddenContent))
	add(match("context.target_class", c.TargetClass))
	add(match("principal.product", c.Agent))
	if len(c.Repo) > 0 {
		add("(resource is Privometry::Repo && " + match("resource.remote", c.Repo) + ")")
	}
	return out, nil
}

// match compares a string attribute with literals and * globs: literals use ==
// (or one set lookup when there are several), globs use like.
func match(attr string, values []string) string {
	var exact, parts []string
	for _, v := range values {
		if strings.Contains(v, "*") {
			parts = append(parts, attr+" like "+quote(v))
		} else {
			exact = append(exact, v)
		}
	}
	switch len(exact) {
	case 0:
	case 1:
		parts = slices.Insert(parts, 0, attr+" == "+quote(exact[0]))
	default:
		parts = slices.Insert(parts, 0, list(exact)+".contains("+attr+")")
	}
	return or(parts)
}

// subcommand matches leading words: "destroy" matches "destroy" and
// "destroy module.db" but not "destroyer".
func subcommand(values []string) string {
	var parts []string
	for _, v := range values {
		op := " == "
		if strings.Contains(v, "*") {
			op = " like "
		}
		parts = append(parts, "context.subcommand"+op+quote(v), "context.subcommand like "+quote(v+" *"))
	}
	return or(parts)
}

func boolean(attr string, v *bool) string {
	switch {
	case v == nil:
		return ""
	case *v:
		return attr
	}
	return "!" + attr
}

func setContains(attr string, values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return attr + ".contains(" + quote(values[0]) + ")"
	}
	return attr + ".containsAny(" + list(values) + ")"
}

func or(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

func list(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = quote(v)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// quote makes a Cedar string literal. Policy globs forbid backslashes, so the
// only escapes needed are for quotes and control characters from messages.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
