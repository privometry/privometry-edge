// Package ipc is the protocol between privometry-hook (and the CLI) and the
// daemon: one newline-terminated JSON request and one response per
// connection, over a Unix socket (a named pipe on Windows) only the user can
// reach.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Version is the protocol version; the daemon rejects others.
const Version = 1

// MaxMessage bounds one message. Hook payloads are small, but Write tool
// inputs carry whole files.
const MaxMessage = 8 << 20

// Request is one call to the daemon.
type Request struct {
	V    int          `json:"v"`
	Op   string       `json:"op"` // hook, mcp, ping, status, events or probe
	Hook *HookRequest `json:"hook,omitempty"`
	MCP  *MCPRequest  `json:"mcp,omitempty"`
	// Query is the argument of non-hook operations, such as events.
	Query json.RawMessage `json:"query,omitempty"`
}

// HookRequest carries one agent hook invocation as received on stdin.
type HookRequest struct {
	Agent   string          `json:"agent"`   // agent product, for example claude_code
	Event   string          `json:"event"`   // the agent's event name, for example PreToolUse
	Payload json.RawMessage `json:"payload"` // the hook's stdin, verbatim
	// Probe is a one-time token from the probe operation. A hook call that
	// carries a valid one is decided as usual but not recorded, so privometry
	// doctor can test the whole path without writing fake agent activity.
	Probe string `json:"probe,omitempty"`
	// PPID is privometry-hook's parent process, usually a shell the agent
	// started, so the daemon can tell which running agents call it.
	PPID int `json:"ppid,omitempty"`
}

// MCPRequest carries one message privometry-mcp-shim saw between an agent and
// the local MCP server it wraps.
type MCPRequest struct {
	Agent   string `json:"agent"`   // agent product whose config launched the shim, or other
	Server  string `json:"server"`  // the server's name in that config
	Session string `json:"session"` // one per shim process
	Cwd     string `json:"cwd"`
	// Phase is call (a tools/call request, before it is forwarded), result (its
	// result) or tools (a tools/list result).
	Phase  string          `json:"phase"`
	CallID string          `json:"call_id,omitempty"` // the JSON-RPC id of the tools/call
	Tool   string          `json:"tool,omitempty"`
	Body   json.RawMessage `json:"body,omitempty"` // the call's arguments, its result, or the tools/list result
}

// MCPDecision is the Data of the response to an mcp call.
type MCPDecision struct {
	Verdict string `json:"verdict"` // allow or deny; the shim cannot ask
	Message string `json:"message,omitempty"`
	// Enforced is false when the agent's own Privometry hook decides its MCP
	// calls, so the shim only watches.
	Enforced bool `json:"enforced"`
}

// Response is the daemon's answer. For a hook, Stdout, Stderr and ExitCode
// are exactly what privometry-hook writes and returns.
type Response struct {
	V        int    `json:"v"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	EventID  string `json:"event_id,omitempty"`
	// Data carries the result of non-hook operations, such as status.
	Data json.RawMessage `json:"data,omitempty"`
}

// Call sends req to the daemon at addr and waits for the response, all
// within timeout.
func Call(addr string, req Request, timeout time.Duration) (Response, error) {
	req.V = Version
	conn, err := dial(addr, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Response{}, err
	}
	if err := writeMessage(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := readMessage(conn, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, fmt.Errorf("daemon: %s", resp.Error)
	}
	return resp, nil
}

func writeMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func readMessage(r io.Reader, v any) error {
	br := bufio.NewReaderSize(io.LimitReader(r, MaxMessage+1), 64<<10)
	line, err := br.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return err
	}
	if len(line) > MaxMessage {
		return errors.New("ipc: message too large")
	}
	return json.Unmarshal(line, v)
}

// Handler answers one request.
type Handler func(Request) Response

// Serve accepts connections until l is closed, answering each request with h
// on its own goroutine. Each connection must finish within timeout.
func Serve(l net.Listener, h Handler, timeout time.Duration) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(timeout))
			var req Request
			resp := Response{}
			switch err := readMessage(conn, &req); {
			case err != nil:
				resp.Error = "bad request: " + err.Error()
			case req.V != Version:
				resp.Error = fmt.Sprintf("protocol version %d not supported (want %d)", req.V, Version)
			default:
				resp = h(req)
			}
			resp.V = Version
			_ = writeMessage(conn, resp)
		}()
	}
}
