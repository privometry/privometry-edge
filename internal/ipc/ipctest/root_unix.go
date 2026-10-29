//go:build unix

package ipctest

// TempRoot is the folder for a test's daemon home: /tmp keeps the socket path
// under the 104-byte limit on macOS, where the default temp folder is long.
const TempRoot = "/tmp"
