// Package intent turns agent actions into the facts Cedar policies decide on.
// shell.go parses shell command lines into simple commands; extract.go
// classifies them (intents, paths, hosts, risk) and builds policy requests.
package intent

import (
	"encoding/base64"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

// Command is one simple command found in a shell line, after unwrapping
// wrappers such as sudo, env, timeout and xargs, and after descending into
// sh -c, eval and find -exec.
type Command struct {
	Program    string   // base name, for example git
	Args       []string // every argument after the program, as written
	Positional []string // arguments that are not flags or flag values
	Subcommand string   // up to four positional words, joined by spaces
	Flags      []string // flags as written, values dropped, short groups also split
	Writes     []string // files written by > or >> redirections
	Reads      []string // files read by < redirections
	Stdin      bool     // reads a pipe from the previous command
	Elevated   bool     // run through sudo or doas
	Dynamic    bool     // some words are only known at run time ($VAR, $(...))
	Via        []string // wrappers and parents, outermost first
}

// maxDepth bounds nesting through sh -c, eval and find -exec.
const maxDepth = 4

// ParseShell returns every simple command in line. A line that does not parse
// returns the error; callers treat the action as opaque and high risk.
func ParseShell(line string) ([]Command, error) {
	return parse(line, 0, nil)
}

func parse(line string, depth int, via []string) ([]Command, error) {
	line = windowsPaths(line)
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(line), "")
	if err != nil {
		return nil, err
	}
	piped := map[*syntax.Stmt]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if b, ok := n.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
			piped[b.Y] = true
		}
		return true
	})
	var out []Command
	syntax.Walk(f, func(n syntax.Node) bool {
		stmt, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		var words []string
		dynamic := false
		for _, w := range call.Args {
			s, lit := wordString(w)
			words = append(words, s)
			dynamic = dynamic || !lit
		}
		cmd := Command{Stdin: piped[stmt], Dynamic: dynamic, Via: via}
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			target, _ := wordString(r.Word)
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
				if !strings.HasPrefix(target, "&") && target != "/dev/null" {
					cmd.Writes = append(cmd.Writes, target)
				}
			case syntax.RdrIn:
				cmd.Reads = append(cmd.Reads, target)
			}
		}
		out = append(out, unwrap(words, cmd, depth)...)
		return true
	})
	return out, nil
}

// wordString renders a word. lit is false when part of it is only known at
// run time; those parts keep their shell spelling, such as $HOME.
func wordString(w *syntax.Word) (s string, lit bool) {
	var b strings.Builder
	lit = true
	var part func(p syntax.WordPart, quoted bool)
	part = func(p syntax.WordPart, quoted bool) {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(unescape(x.Value, quoted))
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				part(q, true)
			}
		case *syntax.ParamExp:
			lit = false
			if x.Param != nil {
				b.WriteString("$" + x.Param.Value)
			}
		default:
			lit = false
			b.WriteString("$(...)")
		}
	}
	for _, p := range w.Parts {
		part(p, false)
	}
	return b.String(), lit
}

// windowsRootRE matches the start of a Windows path: a drive (C:\), .\ or
// ..\, ~\, %VAR%\, $env:VAR\ or $HOME\, or a lone \ ending the line (the
// current drive's root).
var windowsRootRE = regexp.MustCompile(`^(?:[A-Za-z]:\\(?:[\w.\-$%~*? '"]|$)|\.{1,2}\\|~\\|%[A-Za-z_]\w*%\\|\$(?i:env:[A-Za-z_]\w*|home)\\|\\$)`)

// windowsPaths writes the backslashes of Windows paths as forward slashes, as
// paths are classified anyway, before the line is parsed: the shell grammar
// reads them as escapes, so C:\Users\dev would become C:Usersdev and
// "rmdir /s /q d:\" would never close its quote. A path starts at a word
// boundary, or after = or : as in -Path:C:\x, with a windowsRootRE root and
// runs to the next unquoted space or operator. Every other backslash stays a
// shell escape.
func windowsPaths(line string) string {
	if !strings.Contains(line, `\`) {
		return line
	}
	b := []byte(line)
	var quote byte
	inPath := false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inPath && quote == 0 && strings.IndexByte(" \t\n;|&<>()", ch) >= 0 {
			inPath = false
		}
		if !inPath && (i == 0 || strings.IndexByte(" \t\n'\"=:,(", b[i-1]) >= 0) && windowsRootRE.MatchString(line[i:]) {
			inPath = true
		}
		switch {
		case ch == '\\' && inPath:
			b[i] = '/'
		case ch == '\\' && quote != '\'':
			i++ // a shell escape: the next character is literal
		case ch == '\'' || ch == '"':
			switch quote {
			case 0:
				quote = ch
			case ch:
				quote = 0
			}
		}
	}
	return string(b)
}

// unescape removes shell backslash escapes, which the parser keeps in
// literals. Inside double quotes only $ ` " \ and newline are escapable.
func unescape(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (!quoted || strings.IndexByte("$`\"\\\n", s[i+1]) >= 0) {
			i++
			if s[i] == '\n' {
				continue // line continuation
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// wrapperFlags lists, per wrapper, the flags that take a separate value.
var wrapperFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-C": true, "-p": true, "-h": true, "-r": true, "-t": true, "-U": true},
	"doas":    {"-u": true, "-C": true},
	"env":     {"-u": true, "-C": true, "-S": true, "--unset": true, "--chdir": true},
	"nice":    {"-n": true, "--adjustment": true},
	"ionice":  {"-c": true, "-n": true, "-p": true},
	"xargs":   {"-n": true, "-I": true, "-L": true, "-P": true, "-d": true, "-s": true, "-E": true, "-a": true, "--max-args": true, "--max-procs": true, "--delimiter": true, "--arg-file": true, "--replace": true},
	"watch":   {"-n": true, "--interval": true, "-d": false},
	"timeout": {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"command": {}, "exec": {"-a": true}, "nohup": {}, "time": {"-f": true, "-o": true}, "builtin": {},
	"stdbuf": {"-i": true, "-o": true, "-e": true}, "caffeinate": {"-t": true, "-w": true}, "unbuffer": {}, "chronic": {},
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true}

// unwrap peels wrappers off words and returns the commands they run.
func unwrap(words []string, cmd Command, depth int) []Command {
	for len(words) > 0 {
		prog := programName(words[0])
		valueFlags, isWrapper := wrapperFlags[prog]
		if !isWrapper {
			break
		}
		cmd.Via = append(append([]string{}, cmd.Via...), prog)
		if prog == "sudo" || prog == "doas" {
			cmd.Elevated = true
		}
		i := 1
		for i < len(words) {
			w := words[i]
			switch {
			case w == "--":
				i++
				goto done
			case prog == "env" && strings.Contains(w, "=") && !strings.HasPrefix(w, "-"):
				i++
			case strings.HasPrefix(w, "-") && len(w) > 1:
				if valueFlags[w] {
					i++
				}
				i++
			default:
				goto done
			}
		}
	done:
		if prog == "timeout" && i < len(words) {
			i++ // the duration
		}
		words = words[i:]
	}
	if len(words) == 0 {
		return nil
	}

	prog := programName(words[0])
	args := words[1:]
	via := append(append([]string{}, cmd.Via...), prog)

	if depth < maxDepth {
		if shells[prog] {
			for i, a := range args {
				if a == "-c" && i+1 < len(args) {
					if inner, err := parse(args[i+1], depth+1, via); err == nil {
						return inner
					}
					break
				}
			}
		}
		if prog == "eval" && len(args) > 0 {
			if inner, err := parse(strings.Join(args, " "), depth+1, via); err == nil {
				return inner
			}
		}
		if line, ok := windowsShellLine(prog, args); ok {
			if inner, err := parse(line, depth+1, via); err == nil {
				return inner
			}
		}
	}

	cmd.Program = prog
	cmd.Args = args
	if prog == "find" {
		cmd.Positional, cmd.Flags = findArgs(args)
	} else {
		cmd.Positional, cmd.Flags = splitArgs(prog, args)
	}
	cmd.Subcommand = subcommand(cmd.Positional)
	out := []Command{cmd}

	if prog == "find" && depth < maxDepth {
		out = append(out, findExec(args, cmd, depth, via)...)
	}
	if runnerArgs := packageRunnerArgs(prog, cmd.Positional, args); runnerArgs != nil && depth < maxDepth {
		inner := Command{Elevated: cmd.Elevated, Dynamic: cmd.Dynamic, Via: via}
		out = append(out, unwrap(runnerArgs, inner, depth+1)...)
	}
	return out
}

// psHostValueParams are powershell and pwsh parameters that take a value.
var psHostValueParams = map[string]bool{"executionpolicy": true, "ex": true, "ep": true, "windowstyle": true, "w": true,
	"inputformat": true, "inp": true, "if": true, "outputformat": true, "o": true, "of": true, "configurationname": true,
	"config": true, "workingdirectory": true, "wd": true, "version": true, "v": true, "psconsolefile": true, "settingsfile": true,
	"custompipename": true}

// windowsShellLine returns the command line run by cmd /c (or /k) and by
// powershell or pwsh -Command or -EncodedCommand. Windows PowerShell also runs
// bare words as a command; pwsh runs them as a script, which then parses as
// an unknown program.
func windowsShellLine(prog string, args []string) (string, bool) {
	switch strings.ToLower(prog) {
	case "cmd":
		for i, a := range args {
			if strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k") || strings.EqualFold(a, "/r") {
				return joinWords(args[i+1:]), i+1 < len(args)
			}
		}
	case "powershell", "pwsh":
		for i := 0; i < len(args); i++ {
			name, param := strings.CutPrefix(strings.ToLower(args[i]), "-")
			switch {
			case !param:
				return joinWords(args[i:]), true
			case name == "c" || len(name) >= 3 && strings.HasPrefix("command", name):
				return joinWords(args[i+1:]), i+1 < len(args)
			case name == "e" || name == "ec" || len(name) >= 3 && strings.HasPrefix("encodedcommand", name):
				if i+1 < len(args) {
					return decodePowerShell(args[i+1])
				}
				return "", false
			case name == "f" || name == "file":
				return "", false
			case psHostValueParams[name]:
				i++
			}
		}
	}
	return "", false
}

// decodePowerShell decodes an -EncodedCommand value: base64 of UTF-16LE.
func decodePowerShell(s string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units)), true
}

// joinWords rebuilds a command line from words the outer shell already
// split, quoting words with spaces so they stay whole.
func joinWords(words []string) string {
	if len(words) == 1 {
		return words[0]
	}
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = w
		if w == "" || strings.ContainsAny(w, " \t\n") {
			quoted[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
		}
	}
	return strings.Join(quoted, " ")
}

// packageRunnerArgs returns the command a package runner executes, such as
// "prisma migrate reset" for "npx prisma migrate reset", or nil.
func packageRunnerArgs(prog string, positional, args []string) []string {
	switch prog {
	case "npx", "bunx", "pnpx", "uvx":
	case "pnpm", "yarn":
		if len(positional) == 0 || positional[0] != "dlx" {
			return nil
		}
	default:
		return nil
	}
	// The runner's own flags come first; the package name starts the command.
	for i, a := range args {
		if a == "dlx" || strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 && (args[i-1] == "-p" || args[i-1] == "--package") {
			continue
		}
		inner := append([]string{}, args[i:]...)
		inner[0] = stripVersion(inner[0])
		return inner
	}
	return nil
}

// stripVersion turns a package spec such as @scope/tool@1.2 or tool==2 into
// the command name it installs.
func stripVersion(spec string) string {
	if i := strings.Index(spec, "=="); i > 0 {
		spec = spec[:i]
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		spec = spec[:i]
	}
	return path.Base(spec)
}

// findExec returns the commands run by find's -exec, -execdir, -ok and -okdir.
func findExec(args []string, parent Command, depth int, via []string) []Command {
	var out []Command
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(args) && args[j] != ";" && args[j] != `\;` && args[j] != "+" {
				j++
			}
			if j > i+1 {
				inner := Command{Elevated: parent.Elevated, Dynamic: parent.Dynamic, Via: via}
				out = append(out, unwrap(args[i+1:j], inner, depth+1)...)
			}
			i = j
		}
	}
	return out
}

// findArgs treats find's leading arguments as the search roots and every
// predicate (-name, -delete, -exec ...) as a flag.
func findArgs(args []string) (roots, predicates []string) {
	i := 0
	for ; i < len(args) && !strings.HasPrefix(args[i], "-") && args[i] != "(" && args[i] != "!"; i++ {
		roots = append(roots, args[i])
	}
	for ; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			predicates = appendUnique(predicates, args[i])
		}
	}
	return roots, predicates
}

func programName(w string) string {
	w = path.Base(strings.ReplaceAll(w, `\`, "/"))
	return strings.TrimSuffix(strings.TrimSuffix(w, ".exe"), ".EXE")
}

// globalValueFlags lists flags that take a separate value before or around a
// program's subcommand, so the value is not mistaken for a positional word.
var globalValueFlags = map[string]map[string]bool{
	"git":       {"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true},
	"kubectl":   {"-n": true, "--namespace": true, "--context": true, "--kubeconfig": true, "-l": true, "--selector": true, "-o": true, "--output": true, "-f": true, "--filename": true},
	"helm":      {"-n": true, "--namespace": true, "--kube-context": true, "-f": true, "--values": true},
	"docker":    {"-H": true, "--host": true, "--context": true, "-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true, "--name": true, "--network": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true, "--platform": true},
	"aws":       {"--profile": true, "--region": true, "--output": true, "--endpoint-url": true},
	"gcloud":    {"--project": true, "--account": true, "--configuration": true, "--format": true, "--zone": true, "--region": true},
	"az":        {"--subscription": true, "-g": true, "--resource-group": true, "-n": true, "--name": true, "-o": true, "--output": true},
	"npm":       {"--prefix": true, "-w": true, "--workspace": true},
	"pnpm":      {"-C": true, "--dir": true, "--filter": true, "-F": true},
	"yarn":      {"--cwd": true},
	"curl":      {"-X": true, "--request": true, "-H": true, "--header": true, "-d": true, "--data": true, "--data-binary": true, "--data-raw": true, "--data-urlencode": true, "--json": true, "-F": true, "--form": true, "-T": true, "--upload-file": true, "-o": true, "--output": true, "-u": true, "--user": true, "-A": true, "--user-agent": true, "-e": true, "--referer": true, "-b": true, "--cookie": true, "-c": true, "--cookie-jar": true, "-m": true, "--max-time": true, "--connect-timeout": true, "-x": true, "--proxy": true},
	"wget":      {"-O": true, "--output-document": true, "-P": true, "--directory-prefix": true, "--post-data": true, "--post-file": true, "--header": true, "--method": true, "--body-data": true, "--body-file": true},
	"psql":      {"-c": true, "--command": true, "-h": true, "--host": true, "-U": true, "--username": true, "-d": true, "--dbname": true, "-p": true, "--port": true, "-f": true, "--file": true},
	"mysql":     {"-e": true, "--execute": true, "-h": true, "--host": true, "-u": true, "--user": true, "-P": true, "--port": true, "-D": true, "--database": true},
	"ssh":       {"-i": true, "-p": true, "-l": true, "-o": true, "-F": true, "-J": true, "-L": true, "-R": true, "-D": true},
	"scp":       {"-i": true, "-P": true, "-o": true, "-F": true, "-J": true},
	"rsync":     {"-e": true, "--rsh": true, "--exclude": true, "--include": true},
	"tar":       {"-f": true, "--file": true, "-C": true, "--directory": true},
	"terraform": {"-chdir": true, "-var": true, "-var-file": true, "-target": true, "-out": true},
	"go":        {"-run": true, "-bench": true, "-o": true, "-tags": true, "-ldflags": true, "-count": true, "-timeout": true, "-C": true},
}

// cmdSwitchPrograms take cmd.exe switches such as /s and /q, which are flags
// rather than paths (rmdir /s is never a Unix folder named /s in practice).
var cmdSwitchPrograms = map[string]bool{"rmdir": true, "rd": true, "del": true, "erase": true}

var cmdSwitchRE = regexp.MustCompile(`^/[A-Za-z?](:.*)?$`)

// removeItemNames are PowerShell's Remove-Item and its aliases, whose
// parameters are case-insensitive and may be written -Name:value.
var removeItemNames = map[string]bool{"remove-item": true, "ri": true, "rm": true, "rmdir": true, "rd": true, "del": true, "erase": true}

// psValueParams are Remove-Item and common parameters that take a value which
// is not a path. -Path and -LiteralPath values stay positional.
var psValueParams = map[string]bool{"-filter": true, "-include": true, "-exclude": true, "-credential": true, "-stream": true,
	"-erroraction": true, "-ea": true, "-warningaction": true, "-wa": true, "-informationaction": true, "-infa": true,
	"-errorvariable": true, "-ev": true, "-warningvariable": true, "-wv": true, "-informationvariable": true, "-iv": true,
	"-outvariable": true, "-ov": true, "-outbuffer": true, "-ob": true, "-pipelinevariable": true, "-pv": true}

var psPathParams = map[string]bool{"-path": true, "-literalpath": true, "-lp": true, "-pspath": true}

// psParamNames are Remove-Item's parameters and the common ones. A flag that
// abbreviates one (-Force, -fo, -Verbose) is not a group of short flags, so
// it is not split into letters such as -r.
var psParamNames = []string{"path", "literalpath", "filter", "include", "exclude", "recurse", "force", "credential", "whatif",
	"confirm", "stream", "verbose", "debug", "erroraction", "warningaction", "informationaction", "errorvariable",
	"warningvariable", "informationvariable", "outvariable", "outbuffer", "pipelinevariable"}

func psParam(flag string) bool {
	name := strings.ToLower(strings.TrimPrefix(flag, "-"))
	return slices.ContainsFunc(psParamNames, func(p string) bool { return strings.HasPrefix(p, name) })
}

// splitArgs separates flags from positional arguments. Flags keep the
// spelling they were written with, without values ("--output=x" gives
// "--output"); a group of single-dash letters is also split ("-rf" gives
// "-rf", "-r" and "-f") so rules can name either form. cmd.exe switches are
// also given in lower case ("/S" gives "/S" and "/s").
func splitArgs(prog string, args []string) (positional, flags []string) {
	valueFlags := globalValueFlags[prog]
	lower := strings.ToLower(prog)
	switches, ps := cmdSwitchPrograms[lower], removeItemNames[lower]
	afterDashes := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case !afterDashes && switches && cmdSwitchRE.MatchString(a):
			name, _, _ := strings.Cut(a, ":")
			flags = appendUnique(appendUnique(flags, name), strings.ToLower(name))
		case afterDashes || a == "-" || !strings.HasPrefix(a, "-"):
			positional = append(positional, psList(a, ps)...)
		case a == "--":
			afterDashes = true
		default:
			name, _, hasValue := strings.Cut(a, "=")
			if ps && !hasValue {
				var value string
				name, value, hasValue = strings.Cut(a, ":")
				if hasValue && psPathParams[strings.ToLower(name)] {
					positional = append(positional, psList(value, ps)...)
				}
			}
			flags = appendUnique(flags, name)
			if isShortGroup(name) && !(ps && psParam(name)) {
				for _, c := range name[1:] {
					flags = appendUnique(flags, "-"+string(c))
				}
			}
			if !hasValue && (valueFlags[name] || ps && psValueParams[strings.ToLower(name)]) && i+1 < len(args) {
				i++
			}
		}
	}
	return positional, flags
}

// psList splits a PowerShell array argument (a,b) into its items, so a second
// path cannot hide behind the first.
func psList(a string, ps bool) []string {
	if !ps || !strings.Contains(a, ",") {
		return []string{a}
	}
	var out []string
	for _, s := range strings.Split(a, ",") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isShortGroup(f string) bool {
	if len(f) < 3 || f[0] != '-' || f[1] == '-' {
		return false
	}
	for _, c := range f[1:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func subcommand(positional []string) string {
	n := min(len(positional), 4)
	return strings.Join(positional[:n], " ")
}
