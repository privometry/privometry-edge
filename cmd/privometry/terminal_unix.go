//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

// terminal is the controlling terminal, so piped input is never mistaken for
// an answer.
type terminal struct{ in, out *os.File }

func openTerminal() (*terminal, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("this command needs a terminal")
	}
	return &terminal{in: tty, out: tty}, nil
}

func (t *terminal) echo(on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = t.in
	return cmd.Run()
}

func (t *terminal) Close() error { return t.in.Close() }
