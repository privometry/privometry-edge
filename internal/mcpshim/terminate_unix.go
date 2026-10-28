//go:build !windows

package mcpshim

import (
	"os"
	"syscall"
)

// terminate asks the server to stop; WaitDelay kills it if it does not.
func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
