//go:build unix

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// lock takes an exclusive lock on <dir>/privometryd.lock, so only one daemon runs
// per data directory even if its socket file was deleted.
func lock(dir string) (func(), error) { return Lock(dir, "privometryd.lock") }

// Lock takes an exclusive lock on <dir>/<name> and writes this process's PID
// into it; privometryd -supervise holds one too. It fails while another
// process holds the lock, naming that process.
func Lock(dir, name string) (func(), error) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		pid, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("another privometryd is running (pid %s, lock %s)", string(pid), path)
	}
	// The pid is only for the "already running" message, so failing to write it is not an error.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
