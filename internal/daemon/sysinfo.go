package daemon

import (
	"os/exec"
	"runtime"
	"strings"
)

// osVersion reports the OS version for event device records.
func osVersion() string {
	var out []byte
	switch runtime.GOOS {
	case "darwin":
		out, _ = exec.Command("sw_vers", "-productVersion").Output()
	case "linux":
		out, _ = exec.Command("uname", "-r").Output()
	}
	if v := strings.TrimSpace(string(out)); v != "" {
		return v
	}
	return "unknown"
}
