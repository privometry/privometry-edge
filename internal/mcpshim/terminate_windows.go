//go:build windows

package mcpshim

import "os"

// terminate ends the server. Windows has no polite stop signal for a console
// child process, so the server is ended outright.
func terminate(p *os.Process) error { return p.Kill() }
