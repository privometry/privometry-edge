package cli

import (
	"fmt"
	"io"
	"slices"

	"github.com/privometry/privometry-edge/internal/extension"
)

// connectedOnly are the commands of the connected build. This build answers
// them with what to install instead, unless a connector added them.
var connectedOnly = []string{"login", "enroll", "console", "device", "bundle"}

const connectedURL = "https://github.com/privometry/privometry-edge/wiki/Connecting-to-Privometry"

// connectedStub explains that cmd needs the connected build.
func connectedStub(cmd string, stderr io.Writer) int {
	fmt.Fprintf(stderr, `privometry %s: this is the open-source build, which never contacts Privometry's cloud.

Signing this machine up with an organization (login, enroll) needs the
connected build of Privometry. It keeps everything this build does and adds
the organization's policies, event upload and approvals. Install it over
this one; your hooks keep working.

See %s
`, cmd, connectedURL)
	return 2
}

// isConnectedOnly reports whether name is a connected-build command no
// connector has added.
func isConnectedOnly(name string) bool {
	if !slices.Contains(connectedOnly, name) {
		return false
	}
	return !slices.ContainsFunc(extension.Commands(), func(c extension.Command) bool { return c.Name == name })
}
