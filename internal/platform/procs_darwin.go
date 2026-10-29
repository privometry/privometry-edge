package platform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// processes reads the process table with one sysctl, and each command line
// with KERN_PROCARGS2, as ps does: several times faster than running ps. A
// process whose arguments cannot be read (another user's) is listed by name.
func processes() ([]Process, error) {
	ks, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	procs := make([]Process, 0, len(ks))
	for _, k := range ks {
		pid := int(k.Proc.P_pid)
		if pid == 0 {
			continue
		}
		args, _, err := procArgs(pid, false)
		if err != nil || len(args) == 0 {
			name := unix.ByteSliceToString(k.Proc.P_comm[:])
			if name == "" {
				continue
			}
			args = []string{name}
		}
		procs = append(procs, Process{PID: pid, PPID: int(k.Eproc.Ppid), Start: time.Unix(k.Proc.P_starttime.Sec, 0), Args: args})
	}
	return procs, nil
}

func processInfo(pid int) (Process, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return Process{}, err
	}
	if int(k.Proc.P_pid) != pid {
		return Process{}, errors.New("platform: no such process")
	}
	return Process{PID: pid, PPID: int(k.Eproc.Ppid), Start: time.Unix(k.Proc.P_starttime.Sec, 0)}, nil
}

func processCwd(pid int) (string, error) {
	out, err := run("lsof", "-a", "-d", "cwd", "-Fn", "-p", strconv.Itoa(pid))
	if err != nil {
		return "", err
	}
	for _, l := range lines(out) {
		if p, ok := strings.CutPrefix(l, "n"); ok {
			return p, nil
		}
	}
	return "", errors.New("platform: no working folder")
}

func processEnv(pid int) ([]string, error) {
	_, env, err := procArgs(pid, true)
	return env, err
}

// procArgs reads KERN_PROCARGS2: argc, the executable path, padding, argc
// arguments, then the environment, each NUL-terminated. The environment is
// parsed only when asked for.
func procArgs(pid int, withEnv bool) (args, env []string, err error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < 4 {
		return nil, nil, errors.New("platform: short procargs")
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	rest := raw[4:]
	i := bytes.IndexByte(rest, 0) // the executable path
	if i < 0 {
		return nil, nil, errors.New("platform: malformed procargs")
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	parts := strings.SplitN(string(rest), "\x00", argc+1)
	if len(parts) < argc {
		return nil, nil, errors.New("platform: malformed procargs")
	}
	if withEnv && len(parts) > argc {
		for e := range strings.SplitSeq(parts[argc], "\x00") {
			if e == "" {
				break
			}
			env = append(env, e)
		}
	}
	return parts[:argc], env, nil
}

func bootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), nil
}

func lines(out []byte) []string {
	var ls []string
	for _, l := range bytes.Split(out, []byte("\n")) {
		if s := strings.TrimSpace(string(l)); s != "" {
			ls = append(ls, s)
		}
	}
	return ls
}
