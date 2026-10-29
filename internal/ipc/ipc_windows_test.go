//go:build windows

package ipc_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/ipc"
)

func pipeName(t *testing.T) string {
	b := make([]byte, 6)
	rand.Read(b)
	return `\\.\pipe\privometry-test-` + hex.EncodeToString(b)
}

func TestPipeRoundTrip(t *testing.T) {
	addr := pipeName(t)
	l, err := ipc.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go ipc.Serve(l, func(r ipc.Request) ipc.Response {
		var p map[string]any
		if r.Hook != nil {
			_ = json.Unmarshal(r.Hook.Payload, &p)
		}
		tool, _ := p["tool_name"].(string)
		return ipc.Response{OK: true, Stdout: "tool=" + tool}
	}, 2*time.Second)

	for i := 0; i < 20; i++ { // each call is a new pipe instance
		resp, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Agent: "claude_code", Event: "PreToolUse",
			Payload: json.RawMessage(`{"tool_name":"Bash"}`)}}, time.Second)
		if err != nil || resp.Stdout != "tool=Bash" {
			t.Fatalf("call %d: %+v %v", i, resp, err)
		}
	}
	big := `{"tool_name":"Write","content":"` + strings.Repeat("x", 2<<20) + `"}`
	if resp, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Payload: json.RawMessage(big)}}, 2*time.Second); err != nil || resp.Stdout != "tool=Write" {
		t.Fatalf("2 MB payload: %+v %v", resp, err)
	}
	if _, err := ipc.Listen(addr); err == nil || !strings.Contains(err.Error(), "another daemon") {
		t.Errorf("second listen: %v", err)
	}
}

func TestPipeTimeoutsAndClose(t *testing.T) {
	addr := pipeName(t)
	l, err := ipc.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- ipc.Serve(l, func(ipc.Request) ipc.Response { time.Sleep(300 * time.Millisecond); return ipc.Response{OK: true} }, time.Second)
	}()
	start := time.Now()
	if _, err := ipc.Call(addr, ipc.Request{Op: "ping"}, 50*time.Millisecond); err == nil {
		t.Error("a slow daemon must time out")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("timeout took %v", time.Since(start))
	}
	l.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not stop Accept")
	}
	start = time.Now()
	if _, err := ipc.Call(addr, ipc.Request{Op: "ping"}, 50*time.Millisecond); err == nil {
		t.Error("no daemon must be an error")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("a missing pipe took %v to fail", time.Since(start))
	}
	// The name is free again once the slow request's connection, still
	// sleeping in the handler, closes its pipe instance.
	var l2 net.Listener
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if l2, err = ipc.Listen(addr); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("listen after close: %v", err)
	}
	l2.Close()
}
