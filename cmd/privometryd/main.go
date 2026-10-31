// Command privometryd is the Privometry daemon. It answers privometry-hook over a
// user-only socket and keeps the local timeline. See internal/daemoncmd.
package main

import (
	"os"

	"github.com/privometry/privometry-edge/pkg/edge"
)

func main() {
	os.Exit(edge.RunDaemon(os.Args[1:]))
}
