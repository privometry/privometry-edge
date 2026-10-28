//go:build unix

package platform

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func checkOwner(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("platform: cannot read owner of %s", path)
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrInsecure, path, st.Uid, uid)
	}
	return nil
}

func checkPrivate(path string, info fs.FileInfo) error {
	if err := checkOwner(path, info); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %#o, want no group or other access", ErrInsecure, path, perm)
	}
	return nil
}

// tighten sets mode 0700 on a directory the user owns that others can use.
func tighten(dir string, info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 && checkOwner(dir, info) == nil {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

func writableByOthers(_ string, info fs.FileInfo) (bool, error) {
	return info.Mode().Perm()&0o022 != 0, nil
}
