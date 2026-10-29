//go:build darwin || windows

package platform

import (
	"context"
	"os/exec"
	"time"
)

// run executes a system tool (lsof, powershell.exe) with a timeout and the C locale.
func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // callers pass fixed tools (ps, lsof, powershell.exe)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	return cmd.Output()
}
