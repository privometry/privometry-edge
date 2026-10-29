package intent

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/privometry/privometry-edge/internal/policy/facts"
)

// Action is one agent tool call, already mapped to an action kind by the
// adapter (tool_kinds and tool_targets).
type Action struct {
	Kind      string // shell_exec, file_read, file_write, file_delete, network_fetch, mcp_call, web_search, subagent_spawn, other
	Command   string // shell_exec
	Path      string // file_*
	URL       string // network_fetch
	MCPServer string // mcp_call
	MCPTool   string
}

// Request is the facts for one Cedar request, plus why its risk was chosen.
type Request struct {
	Action string
	Facts  facts.Facts
	Reason string
}

var riskLevel = map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
var riskName = []string{"none", "low", "medium", "high", "critical"}

// riskAt keeps the higher of two risks and the reason for it.
type riskAt struct {
	level  int
	reason string
}

func (r *riskAt) raise(level, reason string) {
	if n := riskLevel[level]; n > r.level || r.reason == "" {
		if n >= r.level {
			r.level, r.reason = n, reason
		}
	}
}

// Extract turns an action into one request per command and target. An
// action always yields at least one request.
func Extract(a Action, ctx Context) []Request {
	switch a.Kind {
	case "shell_exec":
		return shell(a.Command, ctx)
	case "file_read", "file_write", "file_delete":
		return []Request{fileAction(a.Kind, a.Path, ctx)}
	case "network_fetch":
		return []Request{{Action: a.Kind, Facts: facts.Facts{Host: hostOf(a.URL), Risk: "low"}, Reason: "fetches a URL"}}
	case "web_search":
		return []Request{{Action: a.Kind, Facts: facts.Facts{Risk: "none"}, Reason: "web search"}}
	case "subagent_spawn":
		return []Request{{Action: a.Kind, Facts: facts.Facts{Risk: "none"}, Reason: "starts a subagent"}}
	case "mcp_call":
		risk, reason := "medium", "calls an MCP tool that may change something"
		if readOnlyToolRE.MatchString(a.MCPTool) {
			risk, reason = "low", "calls a read-only MCP tool"
		}
		return []Request{{Action: a.Kind, Facts: facts.Facts{MCPServer: a.MCPServer, MCPTool: a.MCPTool, Risk: risk}, Reason: reason}}
	}
	return []Request{{Action: "other", Facts: facts.Facts{Risk: "medium"}, Reason: "unknown tool"}}
}

var readOnlyToolRE = regexp.MustCompile(`(?i)^(get|list|search|read|fetch|query|describe|show|find|lookup|view|browse)([_-]|$)`)

func fileAction(kind, p string, ctx Context) Request {
	abs, ok := ctx.resolve(p)
	if !ok {
		return Request{Action: kind, Facts: facts.Facts{Risk: "high", TargetPath: p}, Reason: "path depends on a variable"}
	}
	class, secret := ctx.classify(abs)
	f := facts.Facts{TargetPath: abs, PathClass: class, TargetClass: targetClassOf(abs, class)}
	var r riskAt
	switch kind {
	case "file_read":
		r.raise(map[string]string{"repo": "none", "temp": "none"}[class], "reads a file in the repo")
		if class != "repo" && class != "temp" {
			r.raise("low", "reads a file outside the repo")
		}
		if secret {
			f.Intent = []string{"secret_read"}
			f.Category = []string{"secrets"}
			r.raise("high", "reads a credential file")
		}
	default:
		verb := map[string]string{"file_write": "writes", "file_delete": "deletes"}[kind]
		r.raise(writeRisk(class), fmt.Sprintf("%s a file in %s", verb, describeClass(class)))
		if agentConfigRE.MatchString(abs) {
			r.raise("high", fmt.Sprintf("%s an agent, git or shell config that runs commands later", verb))
		}
	}
	f.Risk = riskName[r.level]
	return Request{Action: kind, Facts: f, Reason: r.reason}
}

func writeRisk(class string) string {
	switch class {
	case "repo", "temp":
		return "low"
	case "home", "other":
		return "medium"
	}
	return "high" // system, secret_store
}

func describeClass(class string) string {
	return map[string]string{"repo": "the repo", "temp": "a temp folder", "home": "your home folder", "system": "a system folder", //nolint:gosec // folder class labels, not credentials
		"secret_store": "a credential store", "other": "a folder outside the repo"}[class]
}

// shell parses a command line and extracts each simple command.
func shell(line string, ctx Context) []Request {
	cmds, err := ParseShell(line)
	if err != nil {
		return []Request{{Action: "shell_exec", Facts: facts.Facts{Risk: "high"}, Reason: "the command could not be parsed"}}
	}
	if len(cmds) == 0 {
		return []Request{{Action: "shell_exec", Facts: facts.Facts{Risk: "none"}, Reason: "no command"}}
	}
	var out []Request
	for _, c := range cmds {
		out = append(out, command(c, ctx)...)
		// cd changes where later commands in the line resolve relative paths.
		// Approximate: subshells and conditional branches are not scoped.
		if (c.Program == "cd" || c.Program == "pushd") && !c.Dynamic {
			target := "~"
			if len(c.Positional) > 0 {
				target = c.Positional[0]
			}
			if dir, ok := ctx.resolve(target); ok && target != "-" {
				ctx.Cwd = dir
			}
		}
	}
	return out
}

// target is one path or host a command touches.
type target struct {
	path, host string
	op         string // read, write, delete
}

// command classifies one simple command and fans it out per target.
func command(c Command, ctx Context) []Request {
	base := facts.Facts{Program: c.Program, Subcommand: c.Subcommand, Flags: c.Flags}
	var r riskAt
	var intents []string
	var categories []string
	addIntent := func(i, category string) {
		if !slices.Contains(intents, i) {
			intents = append(intents, i)
		}
		if category != "" && !slices.Contains(categories, category) {
			categories = append(categories, category)
		}
	}

	classifyProgram(c, &r)
	targets := targetsOf(c)

	// Command-level intents.
	if forcePush(c) {
		addIntent("force_push", "catastrophic")
		r.raise("critical", "force-pushes, rewriting remote history")
	}
	if dbDrop(c) {
		addIntent("db_drop", "catastrophic")
		r.raise("critical", "drops a database, schema or table")
	}
	if packageInstall(c) {
		addIntent("package_install", "")
		r.raise("medium", "installs or runs a package")
	}
	if upload, why := networkUpload(c); upload {
		addIntent("network_upload", "exfiltration")
		r.raise("high", why)
	}
	if c.Program == "env" || c.Program == "printenv" || c.Program == "set" && len(c.Args) == 0 {
		addIntent("secret_read", "secrets")
		r.raise("high", "prints environment variables, which often hold secrets")
	}
	if c.Elevated {
		r.raise("high", "runs with sudo")
	}

	if len(targets) == 0 {
		f := base
		f.Intent, f.Category = intents, categories
		f.Risk = riskName[r.level]
		return []Request{{Action: "shell_exec", Facts: f, Reason: r.reason}}
	}

	var out []Request
	for _, t := range targets {
		f := base
		tr := r
		tIntents := slices.Clone(intents)
		tCats := slices.Clone(categories)
		add := func(i, cat string) {
			if !slices.Contains(tIntents, i) {
				tIntents = append(tIntents, i)
			}
			if cat != "" && !slices.Contains(tCats, cat) {
				tCats = append(tCats, cat)
			}
		}
		if t.host != "" {
			f.Host = t.host
		}
		if t.path != "" {
			abs, ok := ctx.resolve(t.path)
			if !ok {
				f.TargetPath = t.path
				if t.op == "recursive_delete" {
					add("recursive_delete", "")
				}
				if t.op != "read" {
					tr.raise("high", "changes a path that depends on a variable")
				}
			} else {
				class, secret := ctx.classify(abs)
				f.TargetPath, f.PathClass = abs, class
				if t.op != "read" { // a shell command only targets a file it writes or deletes
					f.TargetClass = targetClassOf(abs, class)
				}
				switch t.op {
				case "read":
					if secret {
						add("secret_read", "secrets")
						tr.raise("high", "reads a credential file")
					}
				case "write":
					tr.raise(writeRisk(class), "writes to "+describeClass(class))
					if agentConfigRE.MatchString(abs) {
						tr.raise("high", "writes an agent, git or shell config that runs commands later")
					}
				case "delete":
					tr.raise(writeRisk(class), "deletes in "+describeClass(class))
				case "recursive_delete":
					add("recursive_delete", "")
					switch {
					case class == "home" || class == "system" || class == "secret_store" || abs == ctx.Home:
						add("recursive_delete", "catastrophic")
						tr.raise("critical", "recursively deletes "+describeClass(class))
					case class == "repo" && abs == ctx.RepoRoot:
						tr.raise("high", "recursively deletes the whole repo")
					case class == "repo" || class == "temp":
						tr.raise("low", "recursively deletes inside "+describeClass(class))
					default:
						tr.raise("high", "recursively deletes "+describeClass(class))
					}
				}
			}
		}
		f.Intent, f.Category = tIntents, tCats
		f.Risk = riskName[tr.level]
		out = append(out, Request{Action: "shell_exec", Facts: f, Reason: tr.reason})
	}
	return out
}

var deletePrograms = map[string]bool{"rm": true, "rmdir": true, "unlink": true, "shred": true, "srm": true, "trash": true}
var writePrograms = map[string]bool{"cp": true, "mv": true, "mkdir": true, "touch": true, "ln": true, "chmod": true, "chown": true,
	"tee": true, "truncate": true, "install": true, "rsync": true, "dd": true, "sed": false}
var readPrograms = map[string]bool{"cat": true, "bat": true, "head": true, "tail": true, "less": true, "more": true, "grep": true,
	"rg": true, "base64": true, "xxd": true, "od": true, "strings": true, "source": true, ".": true, "open": true, "cp": true,
	"scp": true, "rsync": true, "zip": true, "tar": true, "gpg": true, "vim": true, "nano": true, "code": true, "jq": true, "yq": true}

// targetsOf lists the paths and hosts a command touches.
func targetsOf(c Command) []target {
	var out []target
	addPath := func(p, op string) {
		if p != "" && p != "-" && !strings.Contains(p, "://") && remoteHost(p) == "" {
			out = append(out, target{path: p, op: op})
		}
	}
	for _, p := range uploadSources(c) {
		addPath(p, "read")
	}
	switch {
	case deletePrograms[c.Program]:
		op := "delete"
		if c.Program == "rm" && (hasFlag(c, "-r") || hasFlag(c, "-R") || hasFlag(c, "--recursive")) {
			op = "recursive_delete"
		}
		for _, p := range c.Positional {
			addPath(p, op)
		}
	case c.Program == "find" && (hasFlag(c, "-delete") || slices.ContainsFunc(c.Args, func(a string) bool { return a == "-exec" || a == "-execdir" })):
		roots := c.Positional
		if len(roots) == 0 {
			roots = []string{"."}
		}
		if hasFlag(c, "-delete") {
			for _, p := range roots {
				addPath(p, "recursive_delete")
			}
		}
	case c.Program == "dd":
		for _, a := range c.Positional {
			if v, ok := strings.CutPrefix(a, "of="); ok {
				addPath(v, "write")
			}
			if v, ok := strings.CutPrefix(a, "if="); ok {
				addPath(v, "read")
			}
		}
	case c.Program == "sed" && (hasFlag(c, "-i") || hasFlag(c, "--in-place")):
		for _, p := range c.Positional[min(1, len(c.Positional)):] {
			addPath(p, "write")
		}
	case writePrograms[c.Program]:
		n := len(c.Positional)
		for i, p := range c.Positional {
			if (c.Program == "cp" || c.Program == "rsync") && i < n-1 {
				addPath(p, "read")
			} else if c.Program == "chmod" || c.Program == "chown" {
				if i > 0 {
					addPath(p, "write")
				}
			} else {
				addPath(p, "write")
			}
		}
	case readPrograms[c.Program]:
		for _, p := range c.Positional {
			if looksLikePath(p) || c.Program != "grep" && c.Program != "rg" {
				addPath(p, "read")
			}
		}
	default:
		for _, p := range c.Positional {
			if looksLikePath(p) {
				addPath(p, "read")
			}
		}
	}
	for _, p := range c.Writes {
		addPath(p, "write")
	}
	for _, p := range c.Reads {
		addPath(p, "read")
	}
	for _, a := range c.Args {
		if h := hostOf(a); h != "" {
			out = append(out, target{host: h})
		}
	}
	if (c.Program == "scp" || c.Program == "rsync" || c.Program == "ssh") && len(c.Positional) > 0 {
		for _, p := range c.Positional {
			if h := remoteHost(p); h != "" {
				out = append(out, target{host: h})
			}
		}
	}
	return out
}

// uploadSources returns local files a command sends elsewhere: curl -T,
// -d @file and -F name=@file, and the source of cloud copy commands.
func uploadSources(c Command) []string {
	var out []string
	switch c.Program {
	case "curl":
		for i := 0; i+1 < len(c.Args); i++ {
			flag, val := c.Args[i], c.Args[i+1]
			switch flag {
			case "-T", "--upload-file":
				out = append(out, val)
			case "-d", "--data", "--data-binary", "--data-urlencode":
				if f, ok := strings.CutPrefix(val, "@"); ok {
					out = append(out, f)
				}
			case "-F", "--form":
				if _, f, ok := strings.Cut(val, "=@"); ok {
					out = append(out, strings.SplitN(f, ";", 2)[0])
				}
			}
		}
	case "aws", "gsutil", "gcloud", "rclone", "azcopy":
		if up, _ := networkUpload(c); up {
			out = append(out, c.Positional[len(c.Positional)-2])
		}
	}
	return out
}

func looksLikePath(p string) bool {
	if strings.ContainsAny(p, " \t\n;()'\"") {
		return false // code or prose, not a path
	}
	if isDrive(slash(p)) || strings.HasPrefix(p, `.\`) || strings.HasPrefix(p, `..\`) || strings.HasPrefix(p, "%USERPROFILE%") {
		return true // Windows
	}
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "./") ||
		strings.HasPrefix(p, "../") || strings.HasPrefix(p, "$HOME") || strings.HasPrefix(p, ".env") ||
		strings.Contains(p, "/") && !strings.Contains(p, "://") && !strings.Contains(p, "@")
}

func hasFlag(c Command, f string) bool { return slices.Contains(c.Flags, f) }

func hostOf(s string) string {
	if !strings.Contains(s, "://") {
		return ""
	}
	u, err := url.Parse(strings.Trim(s, `'"`))
	if err != nil || u.Host == "" || u.Scheme == "file" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

var remoteRE = regexp.MustCompile(`^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):`)

// remoteHost returns the host of an scp-style user@host:path argument.
func remoteHost(arg string) string {
	if strings.Contains(arg, "://") {
		return ""
	}
	if m := remoteRE.FindStringSubmatch(arg); m != nil && len(m[1]) > 1 {
		return strings.ToLower(m[1])
	}
	return ""
}

func forcePush(c Command) bool {
	if c.Program != "git" || len(c.Positional) == 0 || c.Positional[0] != "push" {
		return false
	}
	if hasFlag(c, "--force") || hasFlag(c, "-f") || hasFlag(c, "--force-with-lease") || hasFlag(c, "--force-if-includes") || hasFlag(c, "--mirror") {
		return true
	}
	return slices.ContainsFunc(c.Positional[1:], func(p string) bool { return strings.HasPrefix(p, "+") })
}

var dropSQL = regexp.MustCompile(`(?i)\b(drop\s+(database|schema|table)|truncate\s+(table\s+)?\w|flushall|flushdb|dropDatabase\s*\()`)

func dbDrop(c Command) bool {
	switch c.Program {
	case "dropdb":
		return true
	case "mysqladmin":
		return slices.Contains(c.Positional, "drop")
	case "prisma":
		return c.Subcommand == "migrate reset" || strings.HasPrefix(c.Subcommand, "migrate reset ") || c.Subcommand == "db push" && hasFlag(c, "--force-reset")
	case "rails", "rake", "bin/rails":
		return slices.ContainsFunc(c.Positional, func(p string) bool { return p == "db:drop" || p == "db:reset" || p == "db:schema:load" })
	case "supabase":
		return strings.HasPrefix(c.Subcommand, "db reset")
	}
	if (c.Program == "python" || c.Program == "python3") && slices.Contains(c.Positional, "manage.py") && slices.Contains(c.Positional, "flush") {
		return true
	}
	return slices.ContainsFunc(c.Args, func(a string) bool { return dropSQL.MatchString(a) })
}

var installSubcommands = map[string][]string{
	"npm": {"install", "i", "add", "ci"}, "pnpm": {"install", "i", "add"}, "yarn": {"add", "install"}, "bun": {"add", "install", "i"},
	"pip": {"install"}, "pip3": {"install"}, "uv": {"add", "pip install", "tool install"}, "poetry": {"add", "install"},
	"cargo": {"add", "install"}, "go": {"install", "get"}, "brew": {"install", "reinstall"}, "apt": {"install"}, "apt-get": {"install"},
	"yum": {"install"}, "dnf": {"install"}, "gem": {"install"}, "composer": {"require", "install"}, "pipx": {"install", "run"},
	"dotnet": {"add package", "tool install"}, "conda": {"install"}, "mamba": {"install"},
}

func packageInstall(c Command) bool {
	switch c.Program {
	case "npx", "bunx", "uvx", "pnpx":
		return true
	case "pnpm", "yarn":
		if strings.HasPrefix(c.Subcommand, "dlx") {
			return true
		}
	}
	for _, s := range installSubcommands[c.Program] {
		if c.Subcommand == s || strings.HasPrefix(c.Subcommand, s+" ") {
			return true
		}
	}
	return false
}

// networkUpload reports whether a command sends local data to another host.
func networkUpload(c Command) (bool, string) {
	switch c.Program {
	case "curl":
		for _, f := range []string{"-T", "--upload-file", "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json", "-F", "--form"} {
			if hasFlag(c, f) {
				return true, "sends data to another host with curl " + f
			}
		}
	case "wget":
		if hasFlag(c, "--post-data") || hasFlag(c, "--post-file") || hasFlag(c, "--body-file") || hasFlag(c, "--body-data") {
			return true, "sends data to another host with wget"
		}
	case "scp", "rsync":
		if n := len(c.Positional); n > 1 && remoteHost(c.Positional[n-1]) != "" {
			return true, "copies files to another host"
		}
	case "nc", "ncat", "netcat", "socat":
		return true, "opens a raw network connection"
	case "aws", "gsutil", "gcloud", "rclone", "azcopy":
		if n := len(c.Positional); n > 1 {
			dest := c.Positional[n-1]
			if (strings.Contains(c.Subcommand, "cp") || strings.Contains(c.Subcommand, "sync") || strings.Contains(c.Subcommand, "mv") ||
				strings.Contains(c.Subcommand, "copy")) && (strings.Contains(dest, "://") || strings.Contains(dest, ":") && c.Program == "rclone") &&
				!strings.Contains(c.Positional[n-2], "://") {
				return true, "uploads files to cloud storage"
			}
		}
	case "gh":
		if strings.HasPrefix(c.Subcommand, "gist create") {
			return true, "publishes a gist"
		}
	}
	return false, ""
}

var readOnly = map[string]bool{
	"ls": true, "ll": true, "cat": true, "bat": true, "head": true, "tail": true, "less": true, "more": true, "wc": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true,
	"ack": true, "fd": true, "tree": true, "stat": true, "file": true, "du": true, "df": true, "pwd": true, "echo": true,
	"printf": true, "which": true, "whereis": true, "type": true, "date": true, "whoami": true, "id": true, "uname": true,
	"hostname": true, "true": true, "false": true, "test": true, "[": true, "basename": true, "dirname": true, "realpath": true,
	"readlink": true, "diff": true, "cmp": true, "jq": true, "yq": true, "find": true, "ps": true, "man": true, "cd": true,
	"pushd": true, "popd": true, "sleep": true, "seq": true, "xxd": true, "od": true, "strings": true, "md5sum": true,
	"shasum": true, "sha256sum": true, "nl": true, "column": true, "comm": true, "lsof": true, "history": true,
}

var gitReadOnly = map[string]bool{"status": true, "log": true, "diff": true, "show": true, "branch": true, "remote": true,
	"rev-parse": true, "ls-files": true, "blame": true, "describe": true, "shortlog": true, "reflog": true, "grep": true, "config": true}

var gitRoutine = map[string]bool{"add": true, "commit": true, "checkout": true, "switch": true, "restore": true, "stash": true,
	"fetch": true, "pull": true, "merge": true, "rebase": true, "push": true, "cherry-pick": true, "worktree": true, "tag": true,
	"init": true, "clone": true, "mv": true, "rm": true}

var buildTools = map[string][]string{
	"go":  {"build", "test", "vet", "fmt", "run", "mod", "generate", "list", "version", "env"},
	"npm": {"test", "run", "start", "exec", "ls", "outdated", "audit", "view"}, "pnpm": {"test", "run", "build", "lint", "ls"},
	"yarn": {"test", "run", "build", "lint"}, "bun": {"test", "run", "build"},
	"cargo": {"build", "test", "check", "clippy", "fmt", "run", "doc", "bench"},
	"mvn":   {"test", "compile", "package", "verify", "clean"}, "gradle": {"test", "build", "check", "assemble", "clean"},
	"dotnet": {"build", "test", "run", "format"}, "terraform": {"plan", "init", "validate", "fmt", "show", "output", "providers", "version"},
	"kubectl": {"get", "describe", "logs", "explain", "version", "top", "diff"}, "docker": {"ps", "images", "logs", "inspect", "build", "version"},
	"helm": {"list", "status", "template", "lint", "show", "get"},
}

var buildCommands = map[string]bool{"make": true, "pytest": true, "tsc": true, "eslint": true, "prettier": true, "jest": true,
	"vitest": true, "ruff": true, "black": true, "mypy": true, "gofmt": true, "golangci-lint": true, "rspec": true, "mix": true}

// classifyProgram sets the base risk of a command from what the program is.
func classifyProgram(c Command, r *riskAt) {
	sub := ""
	if len(c.Positional) > 0 {
		sub = c.Positional[0]
	}
	switch {
	case c.Program == "mkfs" || strings.HasPrefix(c.Program, "mkfs.") || c.Program == "wipefs" || c.Program == "diskutil" && strings.HasPrefix(strings.ToLower(sub), "erase"):
		r.raise("critical", "formats or erases a disk")
	case c.Program == "dd" && slices.ContainsFunc(c.Positional, func(p string) bool { return strings.HasPrefix(p, "of=/dev/") }):
		r.raise("critical", "writes directly to a device")
	case readOnly[c.Program]:
		r.raise("none", "read-only command")
	case deletePrograms[c.Program] || writePrograms[c.Program] || readPrograms[c.Program] || c.Program == "sed":
		r.raise("none", "file command")
	case c.Program == "git" && gitReadOnly[sub]:
		r.raise("none", "read-only git command")
	case c.Program == "git" && gitRoutine[sub]:
		r.raise("low", "routine git command")
		if sub == "clean" || sub == "reset" && hasFlag(c, "--hard") {
			r.raise("medium", "discards local changes")
		}
	case c.Program == "git" && (sub == "reset" || sub == "clean"):
		r.raise("medium", "may discard local changes")
	case slices.Contains(buildTools[c.Program], sub) || buildCommands[c.Program]:
		r.raise("low", "build, test or lint command")
	case c.Program == "python" || c.Program == "python3" || c.Program == "node":
		if len(c.Positional) > 0 && (c.Positional[0] == "-m" || strings.HasSuffix(c.Positional[0], ".py") || strings.HasSuffix(c.Positional[0], ".js")) {
			r.raise("low", "runs a script")
		} else {
			r.raise("medium", "runs inline code")
		}
	case c.Program == "curl" || c.Program == "wget" || c.Program == "http":
		r.raise("low", "downloads from the network")
	case c.Program == "shutdown" || c.Program == "reboot" || c.Program == "halt" || c.Program == "poweroff":
		r.raise("high", "shuts down or restarts the machine")
	case c.Program == "terraform" || c.Program == "tofu" || c.Program == "pulumi":
		r.raise("high", "changes infrastructure")
	case c.Program == "chmod" && slices.ContainsFunc(c.Positional, func(p string) bool { return p == "777" || p == "a+rwx" || p == "o+w" }):
		r.raise("high", "makes files writable by everyone")
	case c.Program == "ssh":
		r.raise("medium", "runs commands on another host")
	default:
		r.raise("medium", "command Privometry does not know")
	}
	if shells[c.Program] && len(c.Positional) == 0 && c.Stdin {
		r.raise("high", "runs a script piped from another command")
	} else if shells[c.Program] && len(c.Positional) > 0 {
		r.raise("medium", "runs a shell script")
	}
	if c.Dynamic && !readOnly[c.Program] {
		r.raise("medium", "uses values only known at run time")
	}
	if (c.Program == "python" || c.Program == "python3" || c.Program == "node" || c.Program == "ruby" || c.Program == "perl") && c.Stdin {
		r.raise("high", "runs code piped from another command")
	}
}
