//go:build windows

package service

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detached starts privometryd outside the console's process group, so a
// Ctrl+C in the terminal that ran privometry daemon install does not stop it.
func detached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS, HideWindow: true}
}
