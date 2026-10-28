package platform

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// clockTicks is USER_HZ, the unit of starttime in /proc/<pid>/stat: 100 on
// every Linux architecture Privometry builds for.
const clockTicks = 100

func processes() ([]Process, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	boot, err := bootTime()
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		p, err := readStat(pid, boot)
		if err != nil {
			continue // gone
		}
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil || len(raw) == 0 {
			continue // gone, or a kernel thread
		}
		p.Args = strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		out = append(out, p)
	}
	return out, nil
}

func processInfo(pid int) (Process, error) {
	boot, err := bootTime()
	if err != nil {
		return Process{}, err
	}
	return readStat(pid, boot)
}

// readStat reads the parent and start time from /proc/<pid>/stat, whose
// second field (the command name, in parentheses) may hold spaces.
func readStat(pid int, boot time.Time) (Process, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Process{}, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return Process{}, errors.New("platform: malformed stat")
	}
	f := strings.Fields(string(raw[end+1:]))
	if len(f) < 20 {
		return Process{}, errors.New("platform: short stat")
	}
	ppid, err1 := strconv.Atoi(f[1])
	ticks, err2 := strconv.ParseInt(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return Process{}, errors.New("platform: malformed stat")
	}
	start := boot.Add(time.Duration(ticks) * time.Second / clockTicks).Truncate(time.Second)
	return Process{PID: pid, PPID: ppid, Start: start}, nil
}

func processCwd(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
}

func processEnv(pid int) ([]string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"), nil
}

func bootTime() (time.Time, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, errors.New("platform: no btime in /proc/stat")
}
