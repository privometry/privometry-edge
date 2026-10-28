// Package mcpshim is privometry-mcp-shim (PRD EDGE-25): it runs a local stdio
// MCP server in place of the agent launching it, relays JSON-RPC both ways,
// and asks the daemon about every tools/call before forwarding it.
//
//	privometry-mcp-shim --agent codex_cli --server tickets -- python3 server.py
//
// An allowed call is forwarded unchanged. A denied call never reaches the
// server: the agent gets a tool result with isError set and Privometry's
// reason, which the model sees. MCP has no way to ask the developer, so the
// daemon sends ask as deny. Tool results and tools/list results are reported
// after they are forwarded, so the relay adds latency only to tool calls.
// Everything else (initialize, notifications, resources, prompts, malformed
// lines) passes through byte for byte.
//
// When the daemon cannot answer, the fail mode of the call's category
// applies, as in privometry-hook.
package mcpshim

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/privometry/privometry-oss/internal/hookclient"
	"github.com/privometry/privometry-oss/internal/ipc"
	"github.com/privometry/privometry-oss/internal/platform"
)

// DefaultTimeout bounds one daemon call. A tool call waits for it, so it is
// longer than the hook client's but still short next to a model turn.
const DefaultTimeout = 2 * time.Second

// maxBody bounds what is sent to the daemon for one message. Larger
// arguments are sent as a truncated string: the pre-action scan reads 64 KB.
const maxBody = 1 << 20

// Options configure one run.
type Options struct {
	Env     platform.Env
	Agent   string // agent product whose config launched the shim, or other
	Server  string // the server's name in that config
	Command string
	Args    []string
	Stdin   io.Reader // from the agent
	Stdout  io.Writer // to the agent
	Stderr  io.Writer
	Timeout time.Duration
	// Call sends a request to the daemon; nil calls the daemon socket.
	Call func(ipc.Request, time.Duration) (ipc.Response, error)
}

type shim struct {
	opts    Options
	session string
	cwd     string

	outMu sync.Mutex
	out   io.Writer

	mu      sync.Mutex
	pending map[string]pendingCall // by JSON-RPC id

	reports sync.WaitGroup
}

type pendingCall struct {
	method string // tools/call or tools/list
	tool   string
	report bool // the daemon enforces this agent's calls, so it wants the result
}

// message is the part of a JSON-RPC message the shim reads.
type message struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
}

// Run starts the server and relays until it exits. It returns the server's
// exit code, or 127 when the server cannot start.
func Run(ctx context.Context, opts Options) int {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Agent == "" {
		opts.Agent = "other"
	}
	if opts.Call == nil {
		opts.Call = func(req ipc.Request, timeout time.Duration) (ipc.Response, error) {
			addr, err := opts.Env.IPCAddress()
			if err != nil {
				return ipc.Response{}, err
			}
			return ipc.Call(addr, req, timeout)
		}
	}
	if _, ok := opts.Stderr.(*os.File); !ok {
		// The server's stderr is copied in a goroutine unless it is a file, and
		// the shim writes there too.
		opts.Stderr = &lockedWriter{w: opts.Stderr}
	}
	s := &shim{opts: opts, session: randomID(), out: opts.Stdout, pending: map[string]pendingCall{}}
	s.cwd, _ = os.Getwd()

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...) //nolint:gosec // starting the MCP server the user configured is the shim's job
	cmd.Stderr = opts.Stderr
	// When the agent stops the shim, let the server shut down cleanly first.
	cmd.Cancel = func() error { return terminate(cmd.Process) }
	cmd.WaitDelay = 5 * time.Second
	toServer, err := cmd.StdinPipe()
	if err != nil {
		return s.fail(err)
	}
	fromServer, err := cmd.StdoutPipe()
	if err != nil {
		return s.fail(err)
	}
	if err := cmd.Start(); err != nil {
		return s.fail(err)
	}

	go func() {
		s.fromAgent(opts.Stdin, toServer)
		toServer.Close() // the agent hung up: let the server finish
	}()
	s.fromServer(fromServer)
	err = cmd.Wait()
	s.waitReports(2 * time.Second)
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode()
	case err != nil:
		return s.fail(err)
	}
	return 0
}

func (s *shim) fail(err error) int {
	fmt.Fprintf(s.opts.Stderr, "privometry-mcp-shim: %s: %v\n", s.opts.Command, err)
	return 127
}

// fromAgent forwards the agent's messages, holding back denied tool calls.
func (s *shim) fromAgent(r io.Reader, server io.Writer) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if fwd := s.screen(line); fwd != nil {
				if _, werr := server.Write(fwd); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// screen returns what to forward for one line from the agent, or nil when
// nothing is, after answering denied calls itself.
func (s *shim) screen(line []byte) []byte {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return line
	}
	if trimmed[0] != '[' {
		var m message
		if json.Unmarshal(trimmed, &m) != nil {
			return line
		}
		if denial := s.request(m); denial != nil {
			s.write(append(denial, '\n'))
			return nil
		}
		return line
	}
	// A batch: forward the allowed messages, answer the denied ones together.
	var batch []json.RawMessage
	if json.Unmarshal(trimmed, &batch) != nil {
		return line
	}
	var keep, denials []json.RawMessage
	for _, raw := range batch {
		var m message
		if json.Unmarshal(raw, &m) == nil {
			if denial := s.request(m); denial != nil {
				denials = append(denials, denial)
				continue
			}
		}
		keep = append(keep, raw)
	}
	if len(denials) == 0 {
		return line
	}
	out, _ := json.Marshal(denials)
	s.write(append(out, '\n'))
	if len(keep) == 0 {
		return nil
	}
	fwd, _ := json.Marshal(keep)
	return append(fwd, '\n')
}

// request handles one message from the agent and returns the denial to send
// back, or nil to forward it.
func (s *shim) request(m message) json.RawMessage {
	if len(m.ID) == 0 {
		return nil // a notification
	}
	switch m.Method {
	case "tools/list":
		s.track(m.ID, pendingCall{method: m.Method})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(m.Params, &p)
		dec := s.decide(m.ID, p.Name, p.Arguments)
		if dec.Verdict == "deny" {
			return denial(m.ID, dec.Message)
		}
		s.track(m.ID, pendingCall{method: m.Method, tool: p.Name, report: dec.Enforced})
	}
	return nil
}

// decide asks the daemon about one tool call, or applies the fail modes when
// it cannot answer.
func (s *shim) decide(id json.RawMessage, tool string, args json.RawMessage) ipc.MCPDecision {
	resp, err := s.opts.Call(ipc.Request{Op: "mcp", MCP: s.mcpRequest("call", id, tool, args)}, s.opts.Timeout)
	if err == nil {
		var dec ipc.MCPDecision
		if json.Unmarshal(resp.Data, &dec) == nil && dec.Verdict != "" {
			return dec
		}
		err = errors.New("unreadable daemon reply")
	}
	reason := "daemon_unavailable"
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		reason = "timeout"
	case resp.Error != "":
		reason = "internal_error"
	}
	verdict, msg := hookclient.FailModeMCP(s.opts.Agent, "mcp-shim:"+s.session, s.opts.Server, tool, args, s.cwd, reason,
		hookclient.Options{Env: s.opts.Env})
	if verdict == "" {
		verdict = "allow"
	}
	return ipc.MCPDecision{Verdict: verdict, Message: msg, Enforced: true}
}

func (s *shim) mcpRequest(phase string, id json.RawMessage, tool string, body json.RawMessage) *ipc.MCPRequest {
	if len(body) > maxBody {
		body, _ = json.Marshal(string(body[:maxBody]))
	}
	return &ipc.MCPRequest{Agent: s.opts.Agent, Server: s.opts.Server, Session: s.session, Cwd: s.cwd,
		Phase: phase, CallID: string(id), Tool: tool, Body: body}
}

// denial is the result an MCP client shows the model for a blocked call: a
// tool error, not a protocol error, so the model reads the reason.
func denial(id json.RawMessage, message string) json.RawMessage {
	if message == "" {
		message = "Privometry blocked this tool call."
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
		"content": []map[string]string{{"type": "text", "text": "Privometry blocked this tool call: " + message}},
		"isError": true,
	}})
	return b
}

func (s *shim) track(id json.RawMessage, p pendingCall) {
	s.mu.Lock()
	s.pending[string(id)] = p
	s.mu.Unlock()
}

// fromServer forwards the server's messages at once and reports tool results
// and tool lists afterwards.
func (s *shim) fromServer(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			s.write(line)
			s.observe(bytes.TrimSpace(line))
		}
		if err != nil {
			return
		}
	}
}

func (s *shim) observe(line []byte) {
	if len(line) == 0 {
		return
	}
	var msgs []message
	if line[0] == '[' {
		_ = json.Unmarshal(line, &msgs)
	} else {
		var m message
		if json.Unmarshal(line, &m) == nil {
			msgs = []message{m}
		}
	}
	for _, m := range msgs {
		if len(m.ID) == 0 || m.Method != "" || len(m.Result) == 0 {
			continue
		}
		s.mu.Lock()
		p, ok := s.pending[string(m.ID)]
		delete(s.pending, string(m.ID))
		s.mu.Unlock()
		switch {
		case !ok:
		case p.method == "tools/list":
			s.report(s.mcpRequest("tools", m.ID, "", m.Result))
		case p.report:
			s.report(s.mcpRequest("result", m.ID, p.tool, m.Result))
		}
	}
}

// report sends a result to the daemon in the background; the agent already
// has it.
func (s *shim) report(req *ipc.MCPRequest) {
	s.reports.Add(1)
	go func() {
		defer s.reports.Done()
		if _, err := s.opts.Call(ipc.Request{Op: "mcp", MCP: req}, s.opts.Timeout); err != nil {
			fmt.Fprintf(s.opts.Stderr, "privometry-mcp-shim: could not report %s for %s: %v\n", req.Phase, s.opts.Server, err)
		}
	}()
}

func (s *shim) waitReports(limit time.Duration) {
	done := make(chan struct{})
	go func() { s.reports.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(limit):
	}
}

func (s *shim) write(b []byte) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_, _ = s.out.Write(b)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
