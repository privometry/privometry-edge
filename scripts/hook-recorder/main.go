// Command hook-recorder records the raw payloads a coding agent sends its
// hooks, for adapter fixtures (test/fixtures/README.md). It only ever writes
// hooks into a throwaway project, never into an agent's user-level config.
//
//	go run ./scripts/hook-recorder setup -agent gemini_cli -project ~/scratch/rec-gemini
//	(start the agent in that project and use it; every hook event is saved)
//	go run ./scripts/hook-recorder sanitize -agent gemini_cli -version 0.12.0 \
//	    -in /tmp/privometry-recording-123/recordings -project ~/scratch/rec-gemini
//
// As a hook it runs as "hook-recorder AGENT EVENT" (what setup registers) or
// "hook-recorder -agent AGENT -event EVENT -out DIR". It saves stdin and exits
// 0 without a decision, so the agent goes on as if no hook were installed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/redact"
	"github.com/privometry/privometry-edge/internal/scanner/parsers"
)

// replies are written on stdout for agents that expect a JSON reply even
// when the hook has no opinion.
var replies = map[string]map[string]string{
	// agy 1.4.10 rejects a tool call whose PreToolUse reply has no decision,
	// and Stop needs one too. ask keeps the developer's own prompt.
	"antigravity": {"*": "{}", "PreToolUse": `{"decision":"ask"}`, "Stop": `{"decision":"stop"}`},
	// Cursor 3.27 blocks a fail-closed hook that prints nothing. Shell and MCP
	// calls ask, so the developer still approves or rejects them; preToolUse
	// and file reads cannot ask.
	"cursor": {
		"beforeShellExecution": `{"permission":"ask"}`, "beforeMCPExecution": `{"permission":"ask"}`,
		"beforeReadFile": `{"permission":"allow"}`, "preToolUse": `{"permission":"allow"}`,
	},
}

// reply is what the recorder prints for an agent's event, so the agent goes on
// as if no hook were installed.
func reply(agent, event string) string {
	if r, ok := replies[agent][event]; ok {
		return r
	}
	return replies[agent]["*"]
}

// starts says how to start each agent in the project.
var starts = map[contract.AgentProduct]string{
	contract.AgentProductClaudeCode:  "claude",
	contract.AgentProductCodexCLI:    "codex",
	contract.AgentProductCursor:      "cursor-agent, or open the folder in Cursor",
	contract.AgentProductGeminiCLI:   "gemini",
	contract.AgentProductCopilotCLI:  "copilot",
	contract.AgentProductAntigravity: "agy",
}

func main() {
	args := os.Args[1:]
	var err error
	switch {
	case len(args) > 0 && args[0] == "setup":
		var env platform.Env
		if env, err = platform.CurrentEnv(); err == nil {
			err = setup(args[1:], env, os.Stdout)
		}
	case len(args) > 0 && args[0] == "sanitize":
		var env platform.Env
		if env, err = platform.CurrentEnv(); err == nil {
			err = sanitize(args[1:], env, os.Stdout)
		}
	default:
		hook(args, os.Stdin, os.Stdout, os.Stderr)
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hook-recorder:", err)
		os.Exit(1)
	}
}

// hook saves one payload. It never interferes with the agent: every failure
// is reported on stderr only, and the exit status is always 0.
func hook(args []string, stdin io.Reader, stdout, stderr io.Writer) {
	fs := flag.NewFlagSet("hook-recorder", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "unknown", "agent product, e.g. claude_code")
	event := fs.String("event", "unknown", "hook event name as configured")
	out := fs.String("out", os.Getenv("PRIVOMETRY_RECORD_DIR"), "directory for recordings")
	if fs.Parse(args) != nil {
		return
	}
	if fs.NArg() == 2 {
		*agent, *event = fs.Arg(0), fs.Arg(1)
	}
	if *out == "" {
		// setup puts the recorder next to its recordings folder.
		if exe, err := os.Executable(); err == nil {
			*out = filepath.Join(filepath.Dir(exe), "recordings")
		}
	}
	if err := record(stdin, *agent, *event, *out); err != nil {
		fmt.Fprintln(stderr, "hook-recorder:", err)
	}
	_, _ = io.WriteString(stdout, reply(*agent, *event))
}

func record(stdin io.Reader, agent, event, out string) error {
	if out == "" {
		return fmt.Errorf("no output dir: pass -out or set PRIVOMETRY_RECORD_DIR")
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 4<<20))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") != nil {
		pretty.Reset()
		pretty.Write(raw) // keep non-JSON payloads verbatim
	}
	// Two hooks can fire within one clock tick (Windows), so a counter after
	// the time keeps names unique and in order, and nothing is overwritten.
	at := time.Now().UTC().Format("20060102T150405.000000000")
	for n := 0; n < 100; n++ {
		name := fmt.Sprintf("%s-%s-%s%02d.json", agent, event, at, n)
		f, err := os.OpenFile(filepath.Join(out, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := f.Write(pretty.Bytes()); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	return fmt.Errorf("hook-recorder: 100 recordings of %s %s at %s", agent, event, at)
}

func adapter(agent string) (registry.Adapter, error) {
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		return registry.Adapter{}, err
	}
	a, ok := reg.Get(contract.AgentProduct(agent))
	if !ok {
		var known []string
		for _, a := range reg.All() {
			known = append(known, string(a.Agent))
		}
		return registry.Adapter{}, fmt.Errorf("-agent must be one of %s", strings.Join(known, ", "))
	}
	return a, nil
}

// projectHooks is the agent's project-level hooks file in project, and
// whether the agent reads it only once the folder is trusted.
func projectHooks(a registry.Adapter, env platform.Env, project string) (string, bool, error) {
	for _, t := range a.ConfigTiers {
		if t.Tier != contract.ConfigTierProject || t.Format != registry.FileFormatJSON || !slices.Contains(t.Holds, registry.AdapterConfigTierHoldHooks) {
			continue
		}
		for _, key := range []string{"any", env.OS()} {
			for _, p := range t.Paths[key] {
				p = strings.ReplaceAll(p, "*", "privometry-recorder")
				return filepath.Join(project, filepath.FromSlash(p)), t.RequiresTrust != nil && *t.RequiresTrust, nil
			}
		}
	}
	return "", false, fmt.Errorf("%s has no project-level hooks file, so it cannot be recorded without editing its user-level config", a.DisplayName)
}

func setup(args []string, env platform.Env, stdout io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent product, e.g. gemini_cli")
	project := fs.String("project", "", "throwaway project folder to record in; created if missing")
	out := fs.String("out", "", "folder for the recorder and its recordings (default: a new temporary folder)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *project == "" || fs.NArg() != 0 {
		fs.Usage()
		return flag.ErrHelp
	}
	a, err := adapter(*agent)
	if err != nil {
		return err
	}
	proj, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	// In the home folder, or a folder above it, the project's hooks file
	// would be the agent's user-level one.
	if rel, err := filepath.Rel(proj, env.Home); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is or contains your home folder; use a throwaway project folder", proj)
	}
	file, trust, err := projectHooks(a, env, proj)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); err == nil {
		return fmt.Errorf("%s already exists; use a new, empty project folder", file)
	}

	dir := *out
	if dir == "" {
		if dir, err = os.MkdirTemp("", "privometry-recording-"); err != nil {
			return err
		}
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "recordings"), 0o700); err != nil {
		return err
	}
	exe := filepath.Join(dir, "hook-recorder")
	if env.GOOS == "windows" {
		exe += ".exe"
	}
	if err := copySelf(exe); err != nil {
		return err
	}
	c, err := guard.Install(a, guard.Options{Env: env, HookCommand: exe, File: file})
	if err != nil {
		return err
	}
	if err := c.Apply(); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Recording %s hook payloads.\n\n", a.DisplayName)
	fmt.Fprintf(stdout, "  Hooks:      %s (%s)\n", file, strings.Join(c.Events, ", "))
	fmt.Fprintf(stdout, "  Recorder:   %s\n", exe)
	fmt.Fprintf(stdout, "  Recordings: %s\n\n", filepath.Join(dir, "recordings"))
	fmt.Fprintf(stdout, "1. In %s, start %s.\n", proj, starts[a.Agent])
	if trust {
		fmt.Fprintf(stdout, "   Trust the folder when asked: %s ignores the project's hooks until you do.\n", a.DisplayName)
	}
	if t := c.TrustInstructions; t != "" {
		fmt.Fprintf(stdout, "   %s\n", t)
	}
	for _, w := range c.Warnings {
		fmt.Fprintf(stdout, "   Warning: %s\n", w)
	}
	fmt.Fprintln(stdout, `2. Ask for one of each, approving what it asks: list the folder, read a file, edit it,
   create a new file, fetch a URL, call a tool from a local MCP server if one is set up,
   and run "rm -rf build" (refuse it). Use made-up content only: no secrets, no private prompts.`)
	fmt.Fprintf(stdout, "3. Then turn the recordings into fixtures:\n   go run ./scripts/hook-recorder sanitize -agent %s -version <%s> -in %s -project %s\n",
		a.Agent, strings.Join(a.Detect.VersionCmd, " "), filepath.Join(dir, "recordings"), proj)
	return nil
}

// copySelf copies the running recorder, so the hook still works after go run
// deletes its temporary build.
func copySelf(to string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return os.WriteFile(to, raw, 0o755)
}

func sanitize(args []string, env platform.Env, stdout io.Writer) error {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent product, e.g. gemini_cli")
	version := fs.String("version", "", "agent version the recordings are from")
	in := fs.String("in", "", "recordings folder printed by setup")
	project := fs.String("project", "", "the project folder the agent ran in; becomes /home/dev/acme-api")
	fixtures := fs.String("fixtures", "test/fixtures", "fixtures folder")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *version == "" || *in == "" || fs.NArg() != 0 {
		fs.Usage()
		return flag.ErrHelp
	}
	if !regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`).MatchString(*version) {
		return fmt.Errorf("-version %q is not a version number", *version)
	}
	a, err := adapter(*agent)
	if err != nil {
		return err
	}
	dest := filepath.Join(*fixtures, *agent, *version, "hooks")
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists; fixtures for a version are recorded once", dest)
	}
	names, err := filepath.Glob(filepath.Join(*in, *agent+"-*.json"))
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no %s recordings in %s", *agent, *in)
	}
	sort.Strings(names) // oldest first: names end in the time recorded
	clean := cleaner(env, *project)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	seen := map[string]int{}
	for _, name := range names {
		rest := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(name), *agent+"-"), ".json")
		event := rest[:max(strings.LastIndex(rest, "-"), 0)]
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		text := scrubEmails(clean.Replace(string(raw)))
		base := strings.ToLower(event)
		if tool := toolName(a, event, text); tool != "" {
			base += "-" + tool
		}
		seen[base]++
		file := base + ".json"
		if seen[base] > 1 {
			file = fmt.Sprintf("%s-%d.json", base, seen[base])
		}
		if err := os.WriteFile(filepath.Join(dest, file), []byte(text), 0o644); err != nil {
			return err
		}
		note := ""
		if kinds := redact.SecretKinds(text); len(kinds) > 0 {
			note = "  <- looks like it holds " + strings.Join(kinds, ", ") + "; check by hand"
		}
		fmt.Fprintf(stdout, "%s%s\n", filepath.Join(dest, file), note)
	}
	fmt.Fprintf(stdout, `
Wrote %d fixtures. Before adding them, read each one: no private prompts, no real
MCP server URLs, nothing else about you or this machine. Rename files to say what
they show (pretooluse-bash-rm.json), add a row to test/fixtures/README.md, and set
verified in adapter-defs for version %s.
`, len(names), *version)
	return nil
}

// cleaner replaces what identifies the machine and person with the fixture
// placeholders: the project folder, the home folder, the user and host names.
// Paths are also matched as they appear inside JSON strings on Windows.
func cleaner(env platform.Env, project string) *strings.Replacer {
	var pairs []string
	add := func(from, to string) {
		if from == "" || from == to {
			return
		}
		pairs = append(pairs, from, to)
		if esc := strings.ReplaceAll(from, `\`, `\\`); esc != from {
			pairs = append(pairs, esc, to)
		}
	}
	paths := func(p, to string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			if realPath, err := filepath.EvalSymlinks(abs); err == nil {
				add(realPath, to) // /private/tmp/x on macOS for /tmp/x
			}
			add(abs, to)
			// Cursor names transcript folders after the path with / as -.
			add(dashed(abs), dashed(to))
		}
	}
	paths(project, "/home/dev/acme-api")
	paths(env.Home, "/home/dev")
	if u, err := user.Current(); err == nil && len(filepath.Base(u.Username)) >= 3 {
		add(filepath.Base(u.Username), "dev") // DOMAIN\name on Windows
	}
	if host, err := os.Hostname(); err == nil {
		add(host, "dev-laptop")
		if short, _, ok := strings.Cut(host, "."); ok {
			add(short, "dev-laptop")
		}
	}
	// Longest first, so a path is replaced before the names inside it.
	type pair struct{ from, to string }
	var ps []pair
	for i := 0; i < len(pairs); i += 2 {
		ps = append(ps, pair{pairs[i], pairs[i+1]})
	}
	sort.SliceStable(ps, func(i, j int) bool { return len(ps[i].from) > len(ps[j].from) })
	var sorted []string
	for _, p := range ps {
		sorted = append(sorted, p.from, p.to)
	}
	return strings.NewReplacer(sorted...)
}

func dashed(p string) string {
	return strings.Trim(strings.NewReplacer("/", "-", "\\", "-", ":", "").Replace(p), "-")
}

var unsafeName = regexp.MustCompile(`[^a-z0-9]+`)

var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// scrubEmails replaces email addresses, such as the user_email Cursor puts in
// every payload, with dev@example.com. git@host remote addresses are kept.
func scrubEmails(s string) string {
	return emailRE.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "git@") {
			return m
		}
		return "dev@example.com"
	})
}

// toolName is the tool a tool event is about, as a file name part.
func toolName(a registry.Adapter, event, payload string) string {
	for _, ev := range a.Hooks.Events {
		ptr := ev.Request["tool_name"]
		if ev.Name != event || ptr == "" {
			continue
		}
		doc, err := parsers.Parse("json", []byte(payload))
		if err != nil {
			return ""
		}
		name, _ := parsers.Lookup(doc, ptr).(string)
		name = strings.Trim(unsafeName.ReplaceAllString(strings.ToLower(name), "-"), "-")
		return name[:min(len(name), 40)]
	}
	return ""
}
