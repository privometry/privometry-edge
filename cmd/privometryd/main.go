// Command privometryd is the Privometry daemon. It answers privometry-hook over a
// user-only socket and keeps the local timeline. See internal/daemoncmd.
package main

import (
	"os"

	"github.com/privometry/privometry-edge/internal/cloud/connector"
	"github.com/privometry/privometry-edge/pkg/edge"
)

func main() {
	// The cloud connector still ships in this repository until it moves to
	// privometry-connect.
	edge.SetConnector(connector.New)
	os.Exit(edge.RunDaemon(os.Args[1:]))
}
