package platform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// psLine is one line of ps -o pid=,ppid=,lstart=,args=; lstart is five
// fields, such as "Tue Oct 28 09:14:02 2026" (with LC_ALL=C).
var psLine = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)$`)

func processes() ([]Process, error) {
	out, err := run("ps", "-axww", "-o", "pid=,ppid=,lstart=,args=")
	if err != nil {
		return nil, err
	}
	var procs []Process
	for _, line := range lines(out) {
		m := psLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pid, _ := strconv.Atoi(m[1])
		ppid, _ := strconv.Atoi(m[2])
		start, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(strings.Fields(m[3]), " "), time.Local)
		if err != nil {
			continue
		}
		if args := SplitCommandLine(m[4]); len(args) > 0 {
			procs = append(procs, Process{PID: pid, PPID: ppid, Start: start, Args: args})
		}
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

// processEnv reads KERN_PROCARGS2: argc, the executable path, padding, argc
// arguments, then the environment, each NUL-terminated.
func processEnv(pid int) ([]string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, errors.New("platform: short procargs")
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	rest := raw[4:]
	i := bytes.IndexByte(rest, 0) // the executable path
	if i < 0 {
		return nil, errors.New("platform: malformed procargs")
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	parts := strings.Split(string(rest), "\x00")
	if len(parts) < argc {
		return nil, errors.New("platform: malformed procargs")
	}
	var env []string
	for _, e := range parts[argc:] {
		if e == "" {
			break
		}
		env = append(env, e)
	}
	return env, nil
}

func bootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), nil
}
