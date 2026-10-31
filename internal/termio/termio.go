// Package termio is the CLI's terminal and desktop: prompts that read the
// controlling terminal, opening the browser, and the machine's name.
package termio

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
)

// Prompter asks the person for answers.
type Prompter interface {
	Line(prompt string) (string, error)
	Secret(prompt string) (string, error) // not echoed
}

// TTY reads from the controlling terminal, so piped input is never mistaken
// for an answer.
type TTY struct{}

// Line asks for one line of input.
func (TTY) Line(prompt string) (string, error) {
	t, err := openTerminal()
	if err != nil {
		return "", err
	}
	defer t.Close()
	fmt.Fprint(t.out, prompt)
	return readLine(t.in)
}

// Secret asks for one line of input without echoing it.
func (TTY) Secret(prompt string) (string, error) {
	t, err := openTerminal()
	if err != nil {
		return "", err
	}
	defer t.Close()
	fmt.Fprint(t.out, prompt)
	if err := t.echo(false); err != nil {
		return "", fmt.Errorf("cannot hide what you type: %w", err)
	}
	// Turn echo back on however this ends, including Ctrl-C.
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-interrupted:
			_ = t.echo(true)
			fmt.Fprintln(t.out)
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(interrupted)
		_ = t.echo(true)
		fmt.Fprintln(t.out)
	}()
	return readLine(t.in)
}

func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// HostName is the machine's name, without a trailing .local.
func HostName() string {
	h, _ := os.Hostname()
	return strings.TrimSuffix(h, ".local")
}

// OpenBrowser opens url in the default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
