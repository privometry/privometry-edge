// Package cloudcli is the privometry commands that sign a machine up with an
// organization and keep it enrolled. A connected build adds them to the CLI
// (extension.AddCommand).
package cloudcli

import (
	"fmt"
	"io"

	"github.com/privometry/privometry-edge/internal/extension"
)

// Commands are the cloud commands, in the order privometry lists them.
func Commands() []extension.Command {
	return []extension.Command{
		{Name: "login", Summary: "Sign this machine up with your organization and enroll it", Run: loginCmd},
		{Name: "console", Summary: "Open the Privometry console in your browser, signed in", Run: consoleCmd},
		{Name: "enroll", Summary: "Enroll this device with a token from an admin or your MDM", Run: enrollCmd},
		{Name: "device", Summary: "Show this device's enrollment, or renew its certificate", Run: deviceCmd},
		{Name: "bundle", Summary: "Show or fetch the organization's signed policy bundle", Run: bundleCmd},
	}
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "privometry:", err)
	return 2
}
