// Command privometry is the Privometry CLI: scan, guard, daemon, timeline,
// policy and doctor. See internal/cli. The connected build, from
// privometry-connect, adds the commands that sign a machine up with an
// organization.
package main

import (
	"os"

	"github.com/privometry/privometry-edge/pkg/edge"
)

// Exit codes: 0 success, 1 findings at or above --fail-on, 2 usage or runtime error.
func main() {
	os.Exit(edge.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
