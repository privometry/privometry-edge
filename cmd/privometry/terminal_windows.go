//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// terminal is the console (CONIN$ and CONOUT$), so piped input is never
// mistaken for an answer.
type terminal struct {
	in, out *os.File
	mode    uint32 // the input mode before echo was turned off
}

func openTerminal() (*terminal, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("this command needs a console")
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, errors.New("this command needs a console")
	}
	t := &terminal{in: in, out: out}
	if err := windows.GetConsoleMode(windows.Handle(in.Fd()), &t.mode); err != nil {
		t.Close()
		return nil, errors.New("this command needs a console")
	}
	return t, nil
}

func (t *terminal) echo(on bool) error {
	mode := t.mode
	if !on {
		mode &^= windows.ENABLE_ECHO_INPUT
	}
	return windows.SetConsoleMode(windows.Handle(t.in.Fd()), mode)
}

func (t *terminal) Close() error {
	t.out.Close()
	return t.in.Close()
}
