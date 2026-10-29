// Package buildinfo holds version metadata injected at link time by goreleaser.
package buildinfo

import "fmt"

// Set with -ldflags "-X github.com/privometry/privometry-edge/internal/buildinfo.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a one-line version description.
func String(binary string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", binary, Version, Commit, Date)
}
