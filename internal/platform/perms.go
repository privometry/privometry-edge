package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrInsecure reports a file or directory that other users can tamper with or read.
var ErrInsecure = errors.New("platform: insecure permissions")

// EnsurePrivateDir creates dir (and parents) private to the user if missing,
// then verifies that it is owned by the current user and closed to everyone
// else. An existing directory the user owns but left open to others (for
// example one launchd created for a log file) is tightened; a symlink or a
// directory owned by someone else is refused.
//
// Private means mode 0700 on macOS and Linux, and on Windows an access list
// granting only the user, SYSTEM and Administrators.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		if err := tighten(dir, info); err != nil {
			return err
		}
	}
	return CheckPrivate(dir)
}

// CheckPrivate fails unless path is owned by the current user and nobody
// else may use it. Used for the data dir, database and socket.
func CheckPrivate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	return checkPrivate(path, info)
}

// WritableByOthers reports whether users other than the owner can modify path.
// The scanner uses it for the "writable system config directory" posture check.
func WritableByOthers(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return writableByOthers(path, info)
}
