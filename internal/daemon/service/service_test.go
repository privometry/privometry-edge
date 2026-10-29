package service

import (
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/platform"
)

type recorder struct {
	calls  []string
	output map[string]string
	fail   map[string]bool
}

func (r *recorder) run(name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	for prefix, out := range r.output {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	for prefix := range r.fail {
		if strings.HasPrefix(cmd, prefix) {
			return "not loaded", errors.New("exit status 5")
		}
	}
	return "", nil
}

func opts(t *testing.T, goos string, vars map[string]string, r *recorder) Options {
	return Options{Env: platform.Env{GOOS: goos, Home: "/home/dev", Getenv: func(k string) string { return vars[k] }},
		Privometryd: "/opt/privometry tools/privometryd", Root: t.TempDir(), Run: r.run, UID: 501}
}

func TestLaunchd(t *testing.T) {
	r := &recorder{fail: map[string]bool{"launchctl bootout": true}}
	o := opts(t, "darwin", map[string]string{"PRIVOMETRY_HOME": "/tmp/p&q"}, r)
	p, err := For(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path != "/home/dev/Library/LaunchAgents/dev.privometry.privometryd.plist" {
		t.Errorf("path %s", p.Path)
	}
	text := string(p.Content)
	for _, want := range []string{"<string>/opt/privometry tools/privometryd</string>", "<string>/tmp/p&amp;q</string>", "<key>KeepAlive</key>", "/tmp/p&amp;q/privometryd.log"} {
		if !strings.Contains(text, want) {
			t.Errorf("plist lacks %s:\n%s", want, text)
		}
	}
	// A not-yet-loaded agent makes bootout fail; install still bootstraps.
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != "launchctl bootout gui/501/dev.privometry.privometryd; launchctl bootstrap gui/501 /home/dev/Library/LaunchAgents/dev.privometry.privometryd.plist" {
		t.Errorf("calls: %s", got)
	}
	r.output = map[string]string{"launchctl print": "gui/501/dev.privometry.privometryd = {\n\tstate = running\n\tpid = 4242\n}"}
	if s := Check(p, o); !s.Installed || !s.Current || !s.Running || s.PID != 4242 {
		t.Errorf("status %+v", s)
	}
	if err := Uninstall(p, o); err != nil {
		t.Fatal(err)
	}
	if s := Check(p, o); s.Installed {
		t.Error("plist left after uninstall")
	}

	// plutil validates the generated file where it exists (macOS).
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("plutil"); err == nil {
			f := filepath.Join(t.TempDir(), "x.plist")
			os.WriteFile(f, p.Content, 0o644)
			if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
				t.Errorf("plutil: %s", out)
			}
		}
	}
}

func TestSystemd(t *testing.T) {
	r := &recorder{}
	o := opts(t, "linux", map[string]string{"XDG_CONFIG_HOME": "/home/dev/.cfg", "PRIVOMETRY_HOME": "/srv/privometry data"}, r)
	p, err := For(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path != "/home/dev/.cfg/systemd/user/privometryd.service" {
		t.Errorf("path %s", p.Path)
	}
	text := string(p.Content)
	for _, want := range []string{`ExecStart="/opt/privometry tools/privometryd"`, `Environment="PRIVOMETRY_HOME=/srv/privometry data"`, "Restart=on-failure", "WantedBy=default.target"} {
		if !strings.Contains(text, want) {
			t.Errorf("unit lacks %s:\n%s", want, text)
		}
	}
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != "systemctl --user daemon-reload; systemctl --user enable privometryd.service; systemctl --user restart privometryd.service" {
		t.Errorf("calls: %s", got)
	}
	r.output = map[string]string{"systemctl --user show": "MainPID=77\nActiveState=active\n"}
	if s := Check(p, o); !s.Running || s.PID != 77 {
		t.Errorf("status %+v", s)
	}
	// A changed privometryd path makes the installed unit out of date.
	o.Privometryd = "/usr/local/bin/privometryd"
	p2, _ := For(o)
	if s := Check(p2, o); !s.Installed || s.Current {
		t.Errorf("stale unit: %+v", s)
	}
	r.fail = map[string]bool{"systemctl --user restart": true}
	r.output = nil
	if err := Install(p2, o); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Errorf("a failing restart must be reported: %v", err)
	}
	if _, err := For(Options{Env: platform.Env{GOOS: "freebsd", Home: "/home/dev", Getenv: func(string) string { return "" }}}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("freebsd: %v", err)
	}
}

func TestTaskScheduler(t *testing.T) {
	r := &recorder{fail: map[string]bool{"schtasks /End": true}}
	vars := map[string]string{"LOCALAPPDATA": `C:\Users\dev\AppData\Local`, "USERNAME": "dev", "USERDOMAIN": "ACME"}
	o := opts(t, "windows", vars, r)
	o.Privometryd = `C:\Program Files\Privometry\privometryd.exe`
	p, err := For(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Path != `C:\Users\dev\AppData\Local\Privometry\privometryd-task.xml` {
		t.Errorf("path %s", p.Path)
	}
	text := string(p.Content)
	for _, want := range []string{
		`<UserId>ACME\dev</UserId>`, "<LogonType>InteractiveToken</LogonType>", "<RunLevel>LeastPrivilege</RunLevel>",
		`<Command>C:\Program Files\Privometry\privometryd.exe</Command>`,
		`<Arguments>-log C:\Users\dev\AppData\Local\Privometry\privometryd.log</Arguments>`,
		"<RestartOnFailure>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", `<URI>\Privometry\privometryd</URI>`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("task lacks %s:\n%s", want, text)
		}
	}
	// The task XML parses, and is written as UTF-16 with a byte order mark.
	if err := xml.Unmarshal([]byte(strings.Replace(text, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)), new(struct{})); err != nil {
		t.Errorf("task XML: %v", err)
	}
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(filepath.Join(o.Root, p.Path))
	if len(written) != 2+2*len([]rune(text)) || written[0] != 0xff || written[1] != 0xfe || written[2] != '<' || written[3] != 0 {
		t.Errorf("not UTF-16LE with a BOM: % x", written[:8])
	}
	if got := strings.Join(r.calls, "; "); got != `schtasks /Create /TN Privometry\privometryd /XML C:\Users\dev\AppData\Local\Privometry\privometryd-task.xml /F; `+
		`schtasks /End /TN Privometry\privometryd; schtasks /Run /TN Privometry\privometryd` {
		t.Errorf("calls: %s", got)
	}
	r.output = map[string]string{"powershell.exe": "Running\r\n"}
	os.MkdirAll(filepath.Join(o.Root, `C:\Users\dev\AppData\Local\Privometry`), 0o700)
	os.WriteFile(filepath.Join(o.Root, `C:\Users\dev\AppData\Local\Privometry\privometryd.lock`), []byte("4711"), 0o600)
	if s := Check(p, o); !s.Installed || !s.Current || !s.Running || s.PID != 4711 {
		t.Errorf("status %+v", s)
	}
	r.calls = nil
	if err := Restart(o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != `schtasks /End /TN Privometry\privometryd; schtasks /Run /TN Privometry\privometryd` {
		t.Errorf("restart calls: %s", got)
	}
	if err := Uninstall(p, o); err != nil {
		t.Fatal(err)
	}
	if s := Check(p, o); s.Installed {
		t.Error("task file left after uninstall")
	}

	// A side-by-side home goes on the command line; the task has no environment.
	vars["PRIVOMETRY_HOME"] = `D:\privometry home\`
	p, _ = For(o)
	if !strings.Contains(string(p.Content), `-home &#34;D:\privometry home\\&#34;`) {
		t.Errorf("home argument:\n%s", p.Content)
	}
}

// Where a policy stops standard users from creating scheduled tasks, the Run
// key starts privometryd -supervise at logon instead.
func TestRunKeyWhenTheTaskIsRefused(t *testing.T) {
	r := &recorder{fail: map[string]bool{"schtasks /Create": true}}
	vars := map[string]string{"LOCALAPPDATA": `C:\Users\dev\AppData\Local`, "USERNAME": "dev"}
	o := opts(t, "windows", vars, r)
	o.Privometryd = `C:\Program Files\Privometry\privometryd.exe`
	var started []string
	o.Start = func(name string, args ...string) error {
		started = append(started, name+" "+strings.Join(args, " "))
		return nil
	}
	data := `C:\Users\dev\AppData\Local\Privometry`
	p, _ := For(o)
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	cmdline := `"C:\Program Files\Privometry\privometryd.exe" -supervise -log C:\Users\dev\AppData\Local\Privometry\privometryd.log`
	if got := strings.Join(r.calls, "; "); got != `schtasks /Create /TN Privometry\privometryd /XML `+data+`\privometryd-task.xml /F; `+
		`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Privometry /t REG_SZ /d `+cmdline+` /f` {
		t.Errorf("calls: %s", got)
	}
	if len(started) != 1 || started[0] != `C:\Program Files\Privometry\privometryd.exe -supervise -log `+data+`\privometryd.log` {
		t.Errorf("started %q", started)
	}
	if !strings.Contains(p.Note, "Windows refused the logon task") || !strings.Contains(p.Note, "not loaded") {
		t.Errorf("note %q", p.Note)
	}
	if _, err := os.Stat(filepath.Join(o.Root, p.Path)); err == nil {
		t.Error("the refused task's file is left behind")
	}

	// Status: the Run key value and a privometryd holding the lock.
	os.WriteFile(filepath.Join(o.Root, data+`\privometryd.lock`), []byte("4711"), 0o600)
	os.WriteFile(filepath.Join(o.Root, data+`\privometryd-supervisor.lock`), []byte("4700"), 0o600)
	r.output = map[string]string{"powershell.exe": "privometryd\r\n"}
	if s := Check(p, o); !s.Installed || !s.Current || !s.RunKey || !s.Running || s.PID != 4711 || s.Path != data+`\privometryd-run.txt` {
		t.Errorf("status %+v", s)
	}
	r.fail["reg query"] = true
	if s := Check(p, o); s.Installed {
		t.Error("installed without the Run key value")
	}
	delete(r.fail, "reg query")

	// Restart ends the supervisor and its daemon, and starts it again.
	r.calls, started = nil, nil
	if err := Restart(o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); got != `taskkill /F /T /IM privometryd.exe /FI PID eq 4700` || len(started) != 1 {
		t.Errorf("restart: %s, started %q", got, started)
	}

	// Once the policy allows the task, installing again moves to it.
	delete(r.fail, "schtasks /Create")
	r.calls = nil
	if err := Install(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); !strings.HasPrefix(got, `taskkill /F /T /IM privometryd.exe /FI PID eq 4700; schtasks /Create`) ||
		!strings.HasSuffix(got, `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Privometry /f`) {
		t.Errorf("move to the task: %s", got)
	}
	if s := Check(p, o); s.RunKey || !s.Installed {
		t.Errorf("after the move %+v", s)
	}

	// Uninstall removes both.
	r.fail["schtasks /Create"] = true
	Install(p, o)
	r.calls = nil
	if err := Uninstall(p, o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, "; "); !strings.Contains(got, "reg delete") || !strings.Contains(got, "schtasks /Delete") || !strings.Contains(got, "taskkill") {
		t.Errorf("uninstall: %s", got)
	}
	if s := Check(p, o); s.Installed {
		t.Errorf("after uninstall %+v", s)
	}
}

func TestWinQuote(t *testing.T) {
	for in, want := range map[string]string{
		`C:\a\b.log`:   `C:\a\b.log`,
		`C:\a b\c.log`: `"C:\a b\c.log"`,
		`D:\dir with\`: `"D:\dir with\\"`,
		`say "hi"`:     `"say \"hi\""`,
		`a\"b`:         `"a\\\"b"`,
		"":             `""`,
	} {
		if got := winQuote(in); got != want {
			t.Errorf("winQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
