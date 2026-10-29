//go:build unix

package ipc_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/ipc"
)

// shortDir keeps socket paths under the 104-byte limit on macOS.
func shortDir(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "privometry-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d")
}

func TestRoundTrip(t *testing.T) {
	addr := filepath.Join(shortDir(t), "s")
	l, err := ipc.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go ipc.Serve(l, func(r ipc.Request) ipc.Response {
		if r.Op == "ping" {
			return ipc.Response{OK: true}
		}
		var p map[string]any
		_ = json.Unmarshal(r.Hook.Payload, &p)
		return ipc.Response{OK: true, Stdout: "tool=" + p["tool_name"].(string), ExitCode: 0}
	}, 5*time.Second) // the daemon's timeout; a 2 MB request under -race can take over a second on CI

	if info, _ := os.Stat(addr); info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(addr)); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", info.Mode().Perm())
	}
	resp, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Agent: "claude_code", Event: "PreToolUse",
		Payload: json.RawMessage(`{"tool_name":"Bash"}`)}}, time.Second)
	if err != nil || resp.Stdout != "tool=Bash" {
		t.Fatalf("%+v %v", resp, err)
	}
	big := `{"tool_name":"Write","content":"` + strings.Repeat("x", 2<<20) + `"}`
	if _, err := ipc.Call(addr, ipc.Request{Op: "hook", Hook: &ipc.HookRequest{Payload: json.RawMessage(big)}}, 5*time.Second); err != nil {
		t.Fatalf("2 MB payload: %v", err)
	}

	// A second daemon must not steal a live socket.
	if _, err := ipc.Listen(addr); err == nil || !strings.Contains(err.Error(), "another daemon") {
		t.Errorf("second listen: %v", err)
	}
}

func TestStaleSocketAndTimeouts(t *testing.T) {
	addr := filepath.Join(shortDir(t), "s")
	l, err := ipc.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	l.Close() // leaves a socket file nobody listens on (as after a crash)
	if _, err := os.Stat(addr); err != nil {
		os.WriteFile(addr, nil, 0o600) // net may remove it on close; recreate a stale file
	}
	l2, err := ipc.Listen(addr)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	defer l2.Close()
	go ipc.Serve(l2, func(ipc.Request) ipc.Response { time.Sleep(300 * time.Millisecond); return ipc.Response{OK: true} }, time.Second)
	start := time.Now()
	if _, err := ipc.Call(addr, ipc.Request{Op: "ping"}, 50*time.Millisecond); err == nil {
		t.Error("a slow daemon must time out")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("timeout took %v", time.Since(start))
	}
	if _, err := ipc.Call(filepath.Join(filepath.Dir(addr), "missing"), ipc.Request{Op: "ping"}, 50*time.Millisecond); err == nil {
		t.Error("no daemon must be an error")
	}
}
