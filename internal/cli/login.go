package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/privometry/privometry-edge/internal/extension"
)

// connectedOnly are the commands of the connected build. This build answers
// them with what to install instead, unless a connector added them.
var connectedOnly = []string{"login", "enroll", "console", "device", "bundle"}

const connectedURL = "https://github.com/privometry/privometry-edge/wiki/Connecting-to-Privometry"

// connectedStub explains that cmd needs the connected build. For login it
// offers to install that build and then runs its login with the same args.
func connectedStub(cmd string, args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, `privometry %s: this is the open-source build, which never contacts Privometry's cloud.

Signing this machine up with an organization (login, enroll) needs the
connected build of Privometry. It keeps everything this build does and adds
the organization's policies, event upload and approvals. It installs over
this one, signed with Privometry's release key; your hooks keep working.

Install it with: privometry update --connected
See %s
`, cmd, connectedURL)
	if cmd != "login" {
		return 2
	}
	answer, err := prompter.Line("\nInstall the connected build now? [y/N] ")
	if err != nil {
		return 2 // not a terminal
	}
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return 2
	}
	if code := updateCmd([]string{"--connected"}, stdout, stderr); code != 0 {
		return code
	}
	privometry, err := sibling("", "privometry")
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "\nNow signing this machine up with the connected build:")
	return runConnected(privometry, append([]string{"login"}, args...), stdout, stderr)
}

// runConnected runs the newly installed privometry; tests swap it.
var runConnected = func(path string, args []string, stdout, stderr io.Writer) int {
	c := exec.Command(path, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, stdout, stderr
	err := c.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode()
	case err != nil:
		return fail(stderr, err)
	}
	return 0
}

// isConnectedOnly reports whether name is a connected-build command no
// connector has added.
func isConnectedOnly(name string) bool {
	if !slices.Contains(connectedOnly, name) {
		return false
	}
	return !slices.ContainsFunc(extension.Commands(), func(c extension.Command) bool { return c.Name == name })
}
