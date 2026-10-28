//go:build windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

// lockOffset is the byte locked in privometryd.lock. It lies past the PID
// written at the start, so others can still read who holds the lock.
const lockOffset = 1 << 30

// lock takes an exclusive lock on <dir>/privometryd.lock, so only one daemon runs
// per data directory.
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
	ov := &windows.Overlapped{Offset: lockOffset}
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ov); err != nil {
		pid, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("another privometryd is running (pid %s, lock %s)", string(pid), path)
	}
	f.Truncate(0)
	f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, &windows.Overlapped{Offset: lockOffset})
		f.Close()
	}, nil
}
