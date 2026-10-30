// Command privometry is the Privometry CLI: scan, guard, daemon, timeline,
// policy, doctor, and signing up with an organization (login, console). See
// internal/cli.
package main

import (
	"os"

	"github.com/privometry/privometry-edge/internal/cloud/cloudcli"
	"github.com/privometry/privometry-edge/pkg/edge"
)

// Exit codes: 0 success, 1 findings at or above --fail-on, 2 usage or runtime error.
func main() {
	// The cloud commands still ship in this repository until they move to
	// privometry-connect.
	for _, c := range cloudcli.Commands() {
		edge.AddCommand(c)
	}
	os.Exit(edge.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
