//go:build !windows

package keystore

import "github.com/privometry/privometry-edge/internal/platform"

func dpapiStore(platform.Env) Store { return nil }
