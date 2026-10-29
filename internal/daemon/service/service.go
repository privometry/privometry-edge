// Package service installs privometryd as a per-user background service: a
// launchd agent on macOS, a systemd user unit on Linux, and a Task Scheduler
// task started at logon on Windows. It runs as the user, never as root or an
// administrator, and restarts the daemon if it exits.
//
// On Windows a Service Control Manager service would run outside the user's
// session, need an administrator to install, and could not reach the user's
// DPAPI-protected keys, so the logon task takes its place. Where a policy
// stops standard users from creating scheduled tasks, a value under the
// user's Run key starts privometryd -supervise at logon instead, and it
// restarts the daemon as the task would.
package service

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/privometry/privometry-edge/internal/platform"
)

// Label is the launchd label; Unit is the systemd unit name; Task is the
// Task Scheduler task; RunKey and RunValue start privometryd at logon when
// Windows refuses the task.
const (
	Label    = "dev.privometry.privometryd"
	Unit     = "privometryd.service"
	Task     = `Privometry\privometryd`
	RunKey   = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	RunValue = "Privometry"
)

// Runner runs a service manager command and returns its combined output.
type Runner func(name string, args ...string) (string, error)

// Options describe the install.
type Options struct {
	Env         platform.Env
	Privometryd string // absolute path of privometryd
	Root        string // prefixes written paths, for tests
	Run         Runner
	UID         int
	// Start starts a program without waiting for it; nil starts it for real.
	Start func(name string, args ...string) error
}

// ErrUnsupported is returned on systems without a supported service manager.
var ErrUnsupported = errors.New("service: background service install is not supported on this OS yet")

// Plan is the service file and the commands that load it.
type Plan struct {
	Path    string // where the file goes (without Root)
	Content []byte
	// UTF16 writes Content as UTF-16 with a byte order mark, as schtasks
	// expects of task XML.
	UTF16  bool
	Load   [][]string // commands to (re)load and start
	Unload [][]string // commands to stop and unload
	// Start is started without waiting, after Load.
	Start []string

	// Fallback is installed instead when the first Load command fails: on
	// Windows, the Run key value. Its file holds the command line, so Check
	// and Restart can tell which one is installed.
	Fallback *Plan
	// Note says why Install used the fallback; empty otherwise.
	Note string
}

// file is Content as written to disk.
func (p *Plan) file() []byte {
	if !p.UTF16 {
		return p.Content
	}
	u := utf16.Encode([]rune(string(p.Content)))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xff, 0xfe
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2+2*i:], c)
	}
	return b
}

// mayFail reports a stop command that fails harmlessly when nothing runs.
func mayFail(cmd []string) bool {
	return cmd[0] == "launchctl" && cmd[1] == "bootout" || cmd[0] == "schtasks" && cmd[1] == "/End"
}

func start(opts Options, cmd []string) error {
	if opts.Start != nil {
		return opts.Start(cmd[0], cmd[1:]...)
	}
	c := exec.Command(cmd[0], cmd[1:]...) //nolint:gosec // the plan's command is privometryd's own path and fixed arguments
	c.SysProcAttr = detached()
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}

// For returns the plan for env's OS.
func For(opts Options) (*Plan, error) {
	dataDir, err := opts.Env.DataDir()
	if err != nil {
		return nil, err
	}
	log := filepath.Join(dataDir, "privometryd.log")
	privometryHome := opts.Env.Getenv("PRIVOMETRY_HOME")
	switch opts.Env.GOOS {
	case "darwin":
		path := filepath.Join(opts.Env.Home, "Library", "LaunchAgents", Label+".plist")
		domain := fmt.Sprintf("gui/%d", opts.UID)
		return &Plan{
			Path:    path,
			Content: plist(opts.Privometryd, log, privometryHome),
			Load:    [][]string{{"launchctl", "bootout", domain + "/" + Label}, {"launchctl", "bootstrap", domain, path}},
			Unload:  [][]string{{"launchctl", "bootout", domain + "/" + Label}},
		}, nil
	case "linux":
		config := opts.Env.Getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(opts.Env.Home, ".config")
		}
		path := filepath.Join(config, "systemd", "user", Unit)
		return &Plan{
			Path:    path,
			Content: unit(opts.Privometryd, privometryHome),
			Load:    [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", Unit}, {"systemctl", "--user", "restart", Unit}},
			Unload:  [][]string{{"systemctl", "--user", "disable", "--now", Unit}},
		}, nil
	case "windows":
		user := opts.Env.Getenv("USERNAME")
		if user == "" {
			return nil, errors.New("service: USERNAME is not set")
		}
		if domain := opts.Env.Getenv("USERDOMAIN"); domain != "" {
			user = domain + `\` + user
		}
		path := winJoin(dataDir, "privometryd-task.xml")
		// privometryd for Windows is built without a console window, so it
		// writes its log with -log; neither the task nor the Run key has an
		// environment of its own, so a side-by-side home goes in -home.
		args := []string{"-log", winJoin(dataDir, "privometryd.log")}
		if privometryHome != "" {
			args = append(args, "-home", privometryHome)
		}
		supervise := append([]string{opts.Privometryd, "-supervise"}, args...)
		var quoted []string
		for _, a := range supervise {
			quoted = append(quoted, winQuote(a))
		}
		cmdline := strings.Join(quoted, " ")
		return &Plan{
			Path:    path,
			Content: task(opts.Privometryd, user, args),
			UTF16:   true,
			Load: [][]string{{"schtasks", "/Create", "/TN", Task, "/XML", path, "/F"},
				{"schtasks", "/End", "/TN", Task}, {"schtasks", "/Run", "/TN", Task}},
			Unload: [][]string{{"schtasks", "/End", "/TN", Task}, {"schtasks", "/Delete", "/TN", Task, "/F"}},
			Fallback: &Plan{
				Path:    winJoin(dataDir, "privometryd-run.txt"),
				Content: []byte(cmdline + "\r\n"),
				Load:    [][]string{{"reg", "add", RunKey, "/v", RunValue, "/t", "REG_SZ", "/d", cmdline, "/f"}},
				Unload:  [][]string{{"reg", "delete", RunKey, "/v", RunValue, "/f"}},
				Start:   supervise,
			},
		}, nil
	}
	return nil, ErrUnsupported
}

func winJoin(dir, name string) string { return strings.TrimRight(dir, `\/`) + `\` + name }

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // writes to a bytes.Buffer, which cannot fail
	return b.String()
}

func plist(privometryd, log, privometryHome string) []byte {
	env := ""
	if privometryHome != "" {
		env = "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>PRIVOMETRY_HOME</key>\n\t\t<string>" + xmlEscape(privometryHome) + "</string>\n\t</dict>\n"
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(privometryd) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Adaptive</string>
` + env + `	<key>StandardOutPath</key>
	<string>` + xmlEscape(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(log) + `</string>
</dict>
</plist>
`)
}

// systemdQuote quotes a value for an ExecStart= or Environment= line.
func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\%$") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

func unit(privometryd, privometryHome string) []byte {
	env := ""
	if privometryHome != "" {
		env = "Environment=" + systemdQuote("PRIVOMETRY_HOME="+privometryHome) + "\n"
	}
	return []byte(`[Unit]
Description=Privometry daemon (local guard for coding agents)
Documentation=https://github.com/privometry/privometry-edge

[Service]
ExecStart=` + systemdQuote(privometryd) + `
` + env + `Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`)
}

// winQuote quotes one argument the way Windows programs split command lines.
func winQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, c := range s {
		switch c {
		case '\\':
			slashes++
		case '"':
			// Backslashes before a quote are doubled, and the quote escaped.
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteRune(c)
	}
	b.WriteString(strings.Repeat(`\`, slashes)) // so the closing quote stays a quote
	b.WriteByte('"')
	return b.String()
}

// task is a Task Scheduler definition that starts privometryd at the user's
// logon, in their session with their normal rights, and restarts it every
// minute if it stops.
func task(privometryd, user string, args []string) []byte {
	var quoted []string
	for _, a := range args {
		quoted = append(quoted, winQuote(a))
	}
	return []byte(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Privometry daemon (local guard for coding agents)</Description>
    <URI>\` + Task + `</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(user) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(user) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(privometryd) + `</Command>
      <Arguments>` + xmlEscape(strings.Join(quoted, " ")) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`)
}

// Install writes the service file and loads it. Loading an already loaded
// service restarts it, so this also upgrades.
func Install(p *Plan, opts Options) error {
	// Create the data directory first, private, so the service manager does
	// not create it with its default mode when it opens the log file.
	if dir, err := opts.Env.DataDir(); err == nil {
		if err := platform.EnsurePrivateDir(filepath.Join(opts.Root, dir)); err != nil {
			return err
		}
	}
	if p.Fallback != nil {
		stopSupervisor(opts) // a Run key install being upgraded or replaced
	}
	i, err := load(p, opts)
	switch {
	case err == nil && p.Fallback != nil:
		// The task works now: a Run key install is not needed any more.
		if _, err := os.Stat(filepath.Join(opts.Root, p.Fallback.Path)); err == nil {
			_ = unload(p.Fallback, opts)
		}
		return nil
	case err == nil:
		return nil
	case i != 0 || p.Fallback == nil:
		return err
	}
	if _, ferr := load(p.Fallback, opts); ferr != nil {
		return fmt.Errorf("%w; starting privometryd from the Run key instead failed too: %w", err, ferr)
	}
	os.Remove(filepath.Join(opts.Root, p.Path)) // so Check and Restart see the Run key install
	p.Note = fmt.Sprintf("Windows refused the logon task (%v), so privometryd starts from %s\\%s at logon instead, and privometryd -supervise restarts it if it stops.",
		err, RunKey, RunValue)
	return nil
}

// load writes the plan's file, runs its Load commands and starts its Start
// command. It returns the index of the command that failed.
func load(p *Plan, opts Options) (int, error) {
	realPath := filepath.Join(opts.Root, p.Path)
	if err := os.MkdirAll(filepath.Dir(realPath), 0o755); err != nil { //nolint:gosec // service manager folders (LaunchAgents, systemd user units) are 0755
		return -1, err
	}
	if err := os.WriteFile(realPath, p.file(), 0o644); err != nil { //nolint:gosec // launchd and systemd read unit files that are 0644
		return -1, err
	}
	for i, cmd := range p.Load {
		if out, err := opts.Run(cmd[0], cmd[1:]...); err != nil {
			// Stopping fails when nothing runs yet; that is fine.
			if mayFail(cmd) {
				continue
			}
			return i, fmt.Errorf("%s: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out))
		}
	}
	if len(p.Start) > 0 {
		if err := start(opts, p.Start); err != nil {
			return len(p.Load), fmt.Errorf("starting %s: %w", p.Start[0], err)
		}
	}
	return 0, nil
}

// unload runs the plan's Unload commands and removes its file.
func unload(p *Plan, opts Options) error {
	for _, cmd := range p.Unload {
		_, _ = opts.Run(cmd[0], cmd[1:]...) // not loaded is fine
	}
	err := os.Remove(filepath.Join(opts.Root, p.Path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// stopSupervisor ends privometryd -supervise and the daemon it started. Its
// PID is in the lock file it holds; the image name filter keeps a reused PID
// from ending anything else.
func stopSupervisor(opts Options) {
	dir, err := opts.Env.DataDir()
	if err != nil {
		return
	}
	pid, err := os.ReadFile(filepath.Join(opts.Root, winJoin(dir, "privometryd-supervisor.lock")))
	if n, _ := strconv.Atoi(strings.TrimSpace(string(pid))); err != nil || n <= 0 {
		return
	}
	image := opts.Privometryd[strings.LastIndexAny(opts.Privometryd, `\/`)+1:]
	_, _ = opts.Run("taskkill", "/F", "/T", "/IM", image, "/FI", "PID eq "+strings.TrimSpace(string(pid)))
}

// runKeyInstalled reports a Run key install: its file without the task's.
func runKeyInstalled(p *Plan, opts Options) bool {
	if p.Fallback == nil {
		return false
	}
	_, task := os.Stat(filepath.Join(opts.Root, p.Path))
	_, run := os.Stat(filepath.Join(opts.Root, p.Fallback.Path))
	return task != nil && run == nil
}

// Uninstall stops the service and removes its file.
func Uninstall(p *Plan, opts Options) error {
	if p.Fallback != nil {
		stopSupervisor(opts)
		if err := unload(p.Fallback, opts); err != nil {
			return err
		}
	}
	return unload(p, opts)
}

// Status is the service manager's view of privometryd.
type Status struct {
	Installed bool   `json:"installed"` // the service file exists
	Current   bool   `json:"current"`   // and matches what Install would write
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Path      string `json:"path"`
	// RunKey is set when Windows refused the logon task and the Run key
	// starts privometryd instead.
	RunKey bool `json:"run_key,omitempty"`
}

var (
	launchdPID   = regexp.MustCompile(`(?m)^\s*pid = (\d+)`)
	launchdState = regexp.MustCompile(`(?m)^\s*state = running`)
	systemdPID   = regexp.MustCompile(`(?m)^MainPID=(\d+)`)
)

// Check reports whether the service is installed, current and running.
func Check(p *Plan, opts Options) Status {
	s := Status{Path: p.Path}
	if runKeyInstalled(p, opts) {
		got, _ := os.ReadFile(filepath.Join(opts.Root, p.Fallback.Path))
		s.Path, s.RunKey = p.Fallback.Path, true
		_, err := opts.Run("reg", "query", RunKey, "/v", RunValue)
		s.Installed, s.Current = err == nil, bytes.Equal(got, p.Fallback.file())
		s.PID = windowsDaemon(opts)
		s.Running = s.PID != 0
		return s
	}
	got, err := os.ReadFile(filepath.Join(opts.Root, p.Path))
	if err != nil {
		return s
	}
	s.Installed, s.Current = true, bytes.Equal(got, p.file())
	switch opts.Env.GOOS {
	case "darwin":
		out, err := opts.Run("launchctl", "print", fmt.Sprintf("gui/%d/%s", opts.UID, Label))
		if err == nil && launchdState.MatchString(out) {
			s.Running = true
			if m := launchdPID.FindStringSubmatch(out); m != nil {
				s.PID, _ = strconv.Atoi(m[1])
			}
		}
	case "linux":
		out, err := opts.Run("systemctl", "--user", "show", "-p", "MainPID", "-p", "ActiveState", Unit)
		if err == nil && strings.Contains(out, "ActiveState=active") {
			s.Running = true
			if m := systemdPID.FindStringSubmatch(out); m != nil {
				s.PID, _ = strconv.Atoi(m[1])
			}
		}
	case "windows":
		// schtasks prints the state in the system's language; the PowerShell enum does not.
		out, err := opts.Run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`(Get-ScheduledTask -TaskPath '\Privometry\' -TaskName 'privometryd').State`)
		if err == nil && strings.TrimSpace(out) == "Running" {
			s.Running = true
			// privometryd writes its PID into the lock file it holds.
			if dir, err := opts.Env.DataDir(); err == nil {
				if pid, err := os.ReadFile(filepath.Join(opts.Root, winJoin(dir, "privometryd.lock"))); err == nil {
					s.PID, _ = strconv.Atoi(strings.TrimSpace(string(pid)))
				}
			}
		}
	}
	return s
}

// windowsDaemon is the PID in privometryd's lock file when a privometryd
// process has it, else 0.
func windowsDaemon(opts Options) int {
	dir, err := opts.Env.DataDir()
	if err != nil {
		return 0
	}
	raw, err := os.ReadFile(filepath.Join(opts.Root, winJoin(dir, "privometryd.lock")))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0
	}
	out, err := opts.Run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-Process -Id %d -ErrorAction SilentlyContinue).ProcessName", pid))
	if err != nil || !strings.EqualFold(strings.TrimSpace(out), "privometryd") {
		return 0
	}
	return pid
}

// Restart restarts a loaded service.
func Restart(opts Options) error {
	var cmd []string
	switch opts.Env.GOOS {
	case "darwin":
		cmd = []string{"launchctl", "kickstart", "-k", fmt.Sprintf("gui/%d/%s", opts.UID, Label)}
	case "linux":
		cmd = []string{"systemctl", "--user", "restart", Unit}
	case "windows":
		if p, err := For(opts); err == nil && runKeyInstalled(p, opts) {
			stopSupervisor(opts)
			return start(opts, p.Fallback.Start)
		}
		_, _ = opts.Run("schtasks", "/End", "/TN", Task) // not running is fine
		cmd = []string{"schtasks", "/Run", "/TN", Task}
	default:
		return ErrUnsupported
	}
	if out, err := opts.Run(cmd[0], cmd[1:]...); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(out))
	}
	return nil
}
