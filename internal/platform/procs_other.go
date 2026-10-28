//go:build !linux && !darwin && !windows

package platform

import "time"

func processes() ([]Process, error)    { return nil, ErrNoProcessInfo }
func processInfo(int) (Process, error) { return Process{}, ErrNoProcessInfo }
func processCwd(int) (string, error)   { return "", ErrNoProcessInfo }
func processEnv(int) ([]string, error) { return nil, ErrNoProcessInfo }
func bootTime() (time.Time, error)     { return time.Time{}, ErrNoProcessInfo }
