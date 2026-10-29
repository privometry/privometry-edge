//go:build windows

package ipctest

// TempRoot is the folder for a test's daemon home. Named pipes have no path
// limit, so the default temp folder will do.
const TempRoot = ""
