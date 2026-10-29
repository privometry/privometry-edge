// Package hookclient is privometry-hook: the small program coding agents run on
// every hook event. It forwards the event to the daemon and prints the
// daemon's reply. When the daemon cannot answer in time, it decides alone
// using the fail mode of each rule category: closed denies, ask asks, open
// gives no opinion so the agent's own permission flow applies. It never
// auto-approves on its own.
//
// It must start fast: it loads no policy engine, YAML or database.
package hookclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy/intent"
	"github.com/privometry/privometry-edge/internal/redact"
)

// DefaultTimeout is how long privometry-hook waits for the daemon. The first call
// for a new repo compiles its policy, so this is above the 10 ms p95 target
// for a warm daemon.
const DefaultTimeout = 200 * time.Millisecond

// maxSpool caps the spool while no daemon imports it.
const maxSpool = 10 << 20

// Files shared with the daemon (see internal/daemon).
const (
	failModesFile = "failmodes.json"
	spoolFile     = "spool.jsonl"
)

// ProbeEnv carries a one-time probe token from privometry doctor. Without a
// daemon to check it the token means nothing, so the fail-mode path still
// spools its decision.
const ProbeEnv = "PRIVOMETRY_HOOK_PROBE"

// Options configure one run.
type Options struct {
	Env     platform.Env
	Timeout time.Duration
	Now     func() time.Time
}

// Run handles one hook invocation: privometry-hook <agent> <event>.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, opts Options) int {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if len(args) == 1 && args[0] == "version" {
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: privometry-hook <agent> <event>")
		return 0 // never break the agent over a bad registration
	}
	agent, event := args[0], args[1]
	start := opts.Now()
	payload, err := io.ReadAll(io.LimitReader(stdin, ipc.MaxMessage))
	if err != nil {
		payload = nil
	}

	reason := "daemon_unavailable"
	if addr, err := opts.Env.IPCAddress(); err == nil {
		resp, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Agent: agent, Event: event, Payload: payload, Probe: opts.Env.Getenv(ProbeEnv), PPID: os.Getppid()}}, opts.Timeout)
		if err == nil {
			_, _ = io.WriteString(stdout, resp.Stdout)
			_, _ = io.WriteString(stderr, resp.Stderr)
			return resp.ExitCode
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			reason = "timeout"
		case resp.Error != "":
			reason = "internal_error"
		}
	}
	return fallback(agent, event, payload, reason, start, stdout, opts)
}

// format is how one agent's decision event expects its reply.
type format struct {
	style string // claude (hookSpecificOutput), cursor (permission), gemini or antigravity (decision), copilot (permissionDecision)
	ask   bool   // whether the event honors ask
}

// formats lists the decision events privometry-hook can answer alone. The daemon
// renders replies from the adapter definitions; a test keeps these in step.
var formats = map[string]map[string]format{
	"claude_code": {"PreToolUse": {"claude", true}},
	"codex_cli":   {"PreToolUse": {"claude", false}},
	"cursor": {"preToolUse": {"cursor", false}, "beforeShellExecution": {"cursor", true},
		"beforeMCPExecution": {"cursor", true}, "beforeReadFile": {"cursor", false}},
	"gemini_cli":  {"BeforeTool": {"gemini", false}},
	"copilot_cli": {"preToolUse": {"copilot", true}},
	"antigravity": {"PreToolUse": {"antigravity", true}},
}

var failStrength = map[string]int{"open": 1, "ask": 2, "closed": 3}

func fallback(agent, event string, payload []byte, reason string, start time.Time, stdout io.Writer, opts Options) int {
	f, ok := formats[agent][event]
	if !ok {
		return 0 // not a decision event: nothing to decide
	}
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	action, native := actionOf(agent, event, p)
	cwd := str(p["cwd"])
	if agent == "antigravity" {
		if roots, _ := p["workspacePaths"].([]any); len(roots) > 0 {
			cwd = str(roots[0])
		}
	}
	verdict, message := decideAlone(agent, native, action, credentialText(action, toolInput(agent, p)), cwd, reason, f.ask, start, opts)
	if verdict != "" {
		_, _ = io.WriteString(stdout, reply(f.style, event, verdict, message))
	}
	return 0
}

// FailModeMCP decides one MCP tool call alone, for privometry-mcp-shim when the
// daemon cannot answer: the fail mode of the strongest category the call
// falls in applies, and the decision is spooled for the daemon. MCP servers
// cannot ask, so ask becomes deny. It returns "" when the mode is open.
func FailModeMCP(agent, session, server, tool string, args json.RawMessage, cwd, reason string, opts Options) (verdict, message string) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	var in any
	_ = json.Unmarshal(args, &in)
	action := intent.Action{Kind: "mcp_call", MCPServer: server, MCPTool: tool}
	return decideAlone(agent, session, action, flatten(in), cwd, reason, false, opts.Now(), opts)
}

// decideAlone applies the fail modes to an action, spools the fail_mode event
// and returns the verdict ("" for no opinion) and its message.
func decideAlone(agent, native string, action intent.Action, credText, cwd, reason string, canAsk bool, start time.Time, opts Options) (string, string) {
	secretKinds := redact.SecretKinds(credText)
	if cwd == "" {
		cwd = opts.Env.Home
	}
	ctx := intent.Context{Cwd: cwd, Home: opts.Env.Home, RepoRoot: intent.WorkspaceRoot(cwd, opts.Env.Home, platform.GitRoot(cwd)), TempDirs: []string{os.TempDir()}}
	modes := loadFailModes(opts.Env)

	category, mode := "other", modes["other"]
	if action.Kind == "mcp_call" && failStrength[modes["unapproved_mcp"]] > failStrength[mode] {
		category, mode = "unapproved_mcp", modes["unapproved_mcp"]
	}
	risk := "none"
	if len(secretKinds) > 0 && failStrength[modes["secrets"]] > failStrength[mode] {
		category, mode = "secrets", modes["secrets"]
	}
	for _, r := range intent.Extract(action, ctx) {
		c := categoryOf(r)
		if m := modes[c]; failStrength[m] > failStrength[mode] {
			category, mode = c, m
		}
		if riskOrder[r.Facts.Risk] > riskOrder[risk] {
			risk = r.Facts.Risk
		}
	}

	verdict := map[string]string{"closed": "deny", "ask": "ask", "open": ""}[mode]
	if verdict == "ask" && !canAsk {
		verdict = "deny"
	}
	message := "Privometry could not reach its daemon (" + strings.ReplaceAll(reason, "_", " ") + "), so it applied the " + mode + " fail mode for " + strings.ReplaceAll(category, "_", " ") + " actions. Run: privometry doctor"
	spool(opts, agent, native, action, secretKinds, risk, category, mode, reason, opts.Now().Sub(start))
	return verdict, message
}

var riskOrder = map[string]int{"": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func categoryOf(r intent.Request) string {
	has := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case has(r.Facts.Category, "catastrophic") || r.Facts.Risk == "critical":
		return "catastrophic"
	case has(r.Facts.Intent, "secret_read"):
		return "secrets"
	case has(r.Facts.Intent, "network_upload"):
		return "exfiltration"
	}
	return "other"
}

// toolInput is the tool's arguments: tool_input, or for Copilot CLI toolArgs,
// an object (a JSON-encoded string in older releases).
func toolInput(agent string, p map[string]any) map[string]any {
	if agent == "antigravity" {
		call, _ := p["toolCall"].(map[string]any)
		in, _ := call["args"].(map[string]any)
		return in
	}
	if agent != "copilot_cli" {
		in, _ := p["tool_input"].(map[string]any)
		return in
	}
	switch v := p["toolArgs"].(type) {
	case map[string]any:
		return v
	case string:
		var in map[string]any
		_ = json.Unmarshal([]byte(v), &in)
		return in
	}
	return nil
}

// actionOf reads the action from a payload without the adapter definitions.
func actionOf(agent, event string, p map[string]any) (intent.Action, string) {
	native := str(p["session_id"])
	switch agent {
	case "cursor":
		native = str(p["conversation_id"])
	case "copilot_cli":
		return copilotAction(p), str(p["sessionId"])
	case "gemini_cli":
		return geminiAction(p), native
	case "antigravity":
		return antigravityAction(p), str(p["conversationId"])
	}
	switch event {
	case "beforeShellExecution":
		return intent.Action{Kind: "shell_exec", Command: str(p["command"])}, native
	case "beforeReadFile":
		return intent.Action{Kind: "file_read", Path: str(p["file_path"])}, native
	case "beforeMCPExecution":
		return intent.Action{Kind: "mcp_call", MCPServer: str(p["mcp_server_name"]), MCPTool: str(p["tool_name"])}, native
	}
	tool := str(p["tool_name"])
	in, _ := p["tool_input"].(map[string]any)
	switch {
	case tool == "Bash" || tool == "Shell" || tool == "PowerShell":
		return intent.Action{Kind: "shell_exec", Command: str(in["command"])}, native
	case tool == "Read":
		return intent.Action{Kind: "file_read", Path: str(in["file_path"])}, native
	case tool == "Write" || tool == "Edit" || tool == "NotebookEdit":
		return intent.Action{Kind: "file_write", Path: str(in["file_path"])}, native
	case tool == "apply_patch":
		return intent.Action{Kind: "file_write"}, native
	case tool == "Delete":
		return intent.Action{Kind: "file_delete", Path: str(in["file_path"])}, native
	case tool == "WebFetch":
		return intent.Action{Kind: "network_fetch", URL: str(in["url"])}, native
	case strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "MCP:"):
		return intent.Action{Kind: "mcp_call", MCPTool: tool}, native
	}
	return intent.Action{Kind: "other"}, native
}

func copilotAction(p map[string]any) intent.Action {
	in := toolInput("copilot_cli", p)
	switch str(p["toolName"]) {
	case "bash", "powershell":
		return intent.Action{Kind: "shell_exec", Command: str(in["command"])}
	case "view":
		return intent.Action{Kind: "file_read", Path: str(in["path"])}
	case "create", "edit":
		return intent.Action{Kind: "file_write", Path: str(in["path"])}
	case "apply_patch":
		return intent.Action{Kind: "file_write"}
	case "web_fetch":
		return intent.Action{Kind: "network_fetch", URL: str(in["url"])}
	}
	if strings.Contains(str(p["toolName"]), "-") {
		return intent.Action{Kind: "mcp_call", MCPTool: str(p["toolName"])} // <server>-<tool>
	}
	return intent.Action{Kind: "other"}
}

func antigravityAction(p map[string]any) intent.Action {
	in := toolInput("antigravity", p)
	call, _ := p["toolCall"].(map[string]any)
	switch str(call["name"]) {
	case "run_command":
		return intent.Action{Kind: "shell_exec", Command: str(in["CommandLine"])}
	case "view_file":
		return intent.Action{Kind: "file_read", Path: str(in["AbsolutePath"])}
	case "write_to_file", "replace_file_content", "multi_replace_file_content":
		return intent.Action{Kind: "file_write", Path: str(in["TargetFile"])}
	case "read_url_content":
		return intent.Action{Kind: "network_fetch", URL: str(in["Url"])}
	}
	return intent.Action{Kind: "other"}
}

func geminiAction(p map[string]any) intent.Action {
	in, _ := p["tool_input"].(map[string]any)
	switch tool := str(p["tool_name"]); {
	case tool == "run_shell_command":
		return intent.Action{Kind: "shell_exec", Command: str(in["command"])}
	case tool == "read_file":
		return intent.Action{Kind: "file_read", Path: str(in["file_path"])}
	case tool == "write_file" || tool == "replace":
		return intent.Action{Kind: "file_write", Path: str(in["file_path"])}
	case strings.HasPrefix(tool, "mcp_"):
		return intent.Action{Kind: "mcp_call", MCPTool: tool}
	}
	return intent.Action{Kind: "other"}
}

// credentialText returns only the fields that can leave the agent or be
// written by it. The fallback path deliberately reuses redact's small,
// compiled credential recognizers instead of loading detector packs, YAML or
// the policy engine into the latency-sensitive hook client.
func credentialText(a intent.Action, in map[string]any) string {
	switch a.Kind {
	case "shell_exec":
		return a.Command
	case "network_fetch":
		return a.URL
	}
	switch a.Kind {
	case "mcp_call":
		return flatten(in)
	case "file_write":
		for _, key := range []string{"content", "new_string", "new_source", "file_text", "new_str", "CodeContent", "ReplacementContent", "ReplacementChunks", "command"} {
			if value := flatten(in[key]); value != "" {
				return key + ": " + value
			}
		}
	}
	return ""
}

// flatten preserves object keys so a generic field such as api_key is still
// recognized even when its value has no provider-specific prefix.
func flatten(v any) string {
	var b strings.Builder
	var walk func(string, any)
	walk = func(key string, value any) {
		prefix := ""
		if key != "" {
			prefix = key + ": "
		}
		switch x := value.(type) {
		case string:
			b.WriteString(prefix)
			b.WriteString(x)
			b.WriteByte('\n')
		case map[string]any:
			for k, item := range x {
				walk(k, item)
			}
		case []any:
			for _, item := range x {
				walk(key, item)
			}
		}
	}
	walk("", v)
	return b.String()
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// reply renders a decision in the agent's native shape.
func reply(style, event, verdict, message string) string {
	var v any
	switch style {
	case "cursor":
		v = map[string]string{"permission": verdict, "user_message": message, "agent_message": message}
	case "gemini":
		v = map[string]string{"decision": verdict, "reason": message, "systemMessage": message}
	case "copilot":
		v = map[string]string{"permissionDecision": verdict, "permissionDecisionReason": message}
	case "antigravity":
		if verdict == "ask" {
			verdict = "force_ask" // ask would honor an earlier "Always Allow"
		}
		v = map[string]string{"decision": verdict, "reason": message}
	default:
		v = map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": event, "permissionDecision": verdict, "permissionDecisionReason": message}}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func loadFailModes(env platform.Env) map[string]string {
	modes := map[string]string{}
	for k, v := range contract.DefaultFailModes() {
		modes[k] = string(v)
	}
	dir, err := env.DataDir()
	if err != nil {
		return modes
	}
	raw, err := os.ReadFile(filepath.Join(dir, failModesFile))
	if err != nil {
		return modes
	}
	var f struct {
		FailModes map[string]string `json:"fail_modes"`
	}
	if json.Unmarshal(raw, &f) == nil {
		for k, v := range f.FailModes {
			if _, ok := failStrength[v]; ok {
				modes[k] = v
			}
		}
	}
	return modes
}

// spool appends a fail_mode event for the daemon to import. Failures are
// ignored: recording must never block the agent.
func spool(opts Options, agent, native string, a intent.Action, secretKinds []string, risk, category, mode, reason string, elapsed time.Duration) {
	dir, err := opts.Env.DataDir()
	if err != nil || os.MkdirAll(dir, 0o700) != nil {
		return
	}
	target := a.Command + a.Path + a.URL + a.MCPTool
	ev := events.Event{
		Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeFailMode,
		OccurredAt: contract.At(opts.Now()), User: events.User{LocalUser: os.Getenv("USER")},
		Agent: &events.Agent{Product: contract.AgentProduct(agent), NativeSessionID: native},
		Action: &events.Action{Kind: contract.ActionKind(a.Kind), Target: redact.Redact(target, redact.Context{Home: opts.Env.Home}),
			Risk: contract.Risk(orNone(risk)), SecretTypes: secretKinds},
		FailMode: &events.FailMode{Reason: events.FailModeReason(reason), Category: contract.RuleCategory(category),
			Mode: contract.FailMode(mode), EvaluatedBy: events.FailModeEvaluatedByHookClient, ElapsedMs: ptr(float64(elapsed.Microseconds()) / 1000)},
		Redaction: map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelRedacted, "user.local_user": contract.PrivacyLevelClear},
	}
	if ev.User.LocalUser == "" {
		ev.User.LocalUser = "unknown"
	}
	// The daemon normally owns the local clear-text column. During an outage,
	// keep credentials out of the temporary spool as well.
	localTarget := redact.Secrets(target, opts.Env.Home)
	line, err := json.Marshal(map[string]any{"event": ev, "target_clear": localTarget})
	if err != nil {
		return
	}
	path := filepath.Join(dir, spoolFile)
	if info, err := os.Stat(path); err == nil && info.Size() > maxSpool {
		return // the daemon has been gone a long time; doctor reports it
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func orNone(r string) string {
	if r == "" {
		return "none"
	}
	return r
}

func ptr[T any](v T) *T { return &v }
