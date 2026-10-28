package platform

import (
	"encoding/json"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func processes() ([]Process, error) {
	out, err := run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, "+
			"@{n='Start';e={if ($_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')}}}, CommandLine | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ProcessId, ParentProcessId int
		Start, CommandLine         string
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	var procs []Process
	for _, r := range rows {
		start, _ := time.Parse(time.RFC3339Nano, r.Start)
		args := SplitCommandLine(r.CommandLine)
		if len(args) == 0 {
			continue
		}
		procs = append(procs, Process{PID: r.ProcessId, PPID: r.ParentProcessId, Start: start.Truncate(time.Second), Args: args})
	}
	return procs, nil
}

func processInfo(pid int) (Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return Process{}, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if int(e.ProcessID) != pid {
			continue
		}
		p := Process{PID: pid, PPID: int(e.ParentProcessID)}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return Process{}, err
		}
		defer windows.CloseHandle(h)
		var created, exited, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
			return Process{}, err
		}
		p.Start = time.Unix(0, created.Nanoseconds()).Truncate(time.Second)
		return p, nil
	}
	return Process{}, errors.New("platform: no such process")
}

func processCwd(int) (string, error)   { return "", ErrNoProcessInfo }
func processEnv(int) ([]string, error) { return nil, ErrNoProcessInfo }

func bootTime() (time.Time, error) {
	return time.Now().Add(-windows.DurationSinceBoot()), nil
}
