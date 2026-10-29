//go:build unix

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-edge/internal/platform"
)

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

// MaxSocketPath is the longest Unix socket path every supported OS accepts
// (macOS allows 104 bytes including the terminator).
const MaxSocketPath = 103

// Listen opens the daemon socket at addr. The parent directory must be
// private to the user; a stale socket left by a crashed daemon is removed,
// but a live one is an error.
func Listen(addr string) (net.Listener, error) {
	if len(addr) > MaxSocketPath {
		return nil, fmt.Errorf("ipc: socket path is %d bytes, over the %d-byte limit: %s (set PRIVOMETRY_HOME to a shorter folder)", len(addr), MaxSocketPath, addr)
	}
	if err := platform.EnsurePrivateDir(filepath.Dir(addr)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(addr); err == nil {
		if c, err := net.DialTimeout("unix", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("ipc: another daemon is listening on %s", addr)
		}
		if err := os.Remove(addr); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(addr, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
