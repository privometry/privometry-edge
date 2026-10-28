//go:build !windows

package keystore

import "github.com/privometry/privometry-oss/internal/platform"

func dpapiStore(platform.Env) Store { return nil }
