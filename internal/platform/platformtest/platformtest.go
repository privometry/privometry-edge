// Package platformtest helps tests check file privacy the same way on every OS.
package platformtest

import (
	"os"
	"runtime"
	"testing"

	"github.com/privometry/privometry-edge/internal/platform"
)

// Private fails t unless path is private to the user: mode 0600 on macOS and
// Linux, and on Windows, which has no mode bits, an access list granting only
// the user, SYSTEM and Administrators.
func Private(t testing.TB, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if err := platform.CheckPrivate(path); err != nil {
			t.Errorf("%s must be private: %v", path, err)
		}
		return
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("%s must be private: %v %v", path, info, err)
	}
}

// UnixPaths skips t on Windows. It is for tests that simulate a macOS or
// Linux machine with paths such as /home/dev, which a Windows file system
// turns into \home\dev; the macOS and Linux jobs run them.
func UnixPaths(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("simulates Unix paths; runs on macOS and Linux")
	}
}
