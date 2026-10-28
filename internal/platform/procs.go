package platform

import (
	"errors"
	"strings"
	"time"
)

// Process is one running process. PID and Start together identify it, since
// PIDs are reused; Start is truncated to the second on every OS, so a listing
// and a single-process read agree.
type Process struct {
	PID, PPID int
	Start     time.Time
	// Args are the program and its arguments. Callers look for specific
	// programs and flags and must never store or log them: command lines can
	// hold secrets. Empty from ProcessInfo.
	Args []string
}

// Key identifies the process across PID reuse.
func (p Process) Key() ProcessKey { return ProcessKey{PID: p.PID, Start: p.Start.Unix()} }

// ProcessKey is a PID with its start time.
type ProcessKey struct {
	PID   int
	Start int64 // Unix seconds
}

// ErrNoProcessInfo is returned where the OS gives no way to read what was
// asked: another process's working folder or environment on Windows.
var ErrNoProcessInfo = errors.New("platform: not available on this OS")

// Processes lists the processes running now. Linux reads /proc, macOS asks
// ps, Windows asks CIM; on macOS and Windows a command line is split on
// spaces outside double quotes.
func Processes() ([]Process, error) { return processes() }

// ProcessInfo reads one process's parent and start time, without its
// arguments: /proc/<pid>/stat on Linux, sysctl kern.proc.pid on macOS, a
// Toolhelp snapshot and the process's times on Windows. It is cheap enough to
// call while answering a hook.
func ProcessInfo(pid int) (Process, error) { return processInfo(pid) }

// ProcessCwd returns a process's working folder: /proc/<pid>/cwd on Linux,
// lsof on macOS. Windows returns ErrNoProcessInfo.
func ProcessCwd(pid int) (string, error) { return processCwd(pid) }

// ProcessEnv returns the values of the named variables in a process's
// environment, and nothing else from it: /proc/<pid>/environ on Linux, sysctl
// KERN_PROCARGS2 on macOS (the user's own processes). Windows would have to
// read the process's memory, so it returns ErrNoProcessInfo.
func ProcessEnv(pid int, names []string) (map[string]string, error) {
	env, err := processEnv(pid)
	if err != nil {
		return nil, err
	}
	return pickEnv(env, names), nil
}

// BootTime returns when the system last started.
func BootTime() (time.Time, error) { return bootTime() }

// Ancestors returns pid's parent chain, nearest first, up to limit
// processes, stopping at PID 1 or at the first process it cannot read.
func Ancestors(pid, limit int, info func(int) (Process, error)) []Process {
	if info == nil {
		info = ProcessInfo
	}
	var out []Process
	for len(out) < limit && pid > 1 {
		p, err := info(pid)
		if err != nil {
			break
		}
		out = append(out, p)
		if p.PPID == pid {
			break
		}
		pid = p.PPID
	}
	return out
}

// pickEnv keeps the named variables from NAME=value entries.
func pickEnv(entries []string, names []string) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		for _, n := range names {
			if k == n {
				out[k] = v
			}
		}
	}
	return out
}

// SplitCommandLine splits a command line on spaces outside double quotes.
func SplitCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	quoted, inArg := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, inArg = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args
}
