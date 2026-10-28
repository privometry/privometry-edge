//go:build !windows

package service

import "syscall"

// detached is only needed on Windows, the one OS with a started fallback.
func detached() *syscall.SysProcAttr { return nil }
