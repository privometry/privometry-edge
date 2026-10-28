package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/events"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/timeline"
)

func TestDoctorAndBundle(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("macOS and Linux only")
	}
	home := t.TempDir()
	data, err := os.MkdirTemp("/tmp", "privometry-doc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(data)
	os.Chmod(data, 0o700)
	env := platform.Env{GOOS: runtime.GOOS, Home: home, Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	daemonEnv = func() (platform.Env, error) { return env, nil }
	serviceRunner = func(string, ...string) (string, error) { return "", nil }
	defer func() { daemonEnv = platform.CurrentEnv }()

	token := "ghp_" + strings.Repeat("Ab3", 12) // a GitHub token shape
	plain := "cat " + home + "/.ssh/id_rsa --password hunter2-secret-value"
	store, err := timeline.Open(filepath.Join(data, "privometry.db"))
	if err != nil {
		t.Fatal(err)
	}
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeAction,
		OccurredAt: contract.At(time.Now()), Device: events.Device{DeviceID: "dev_x", OS: "macos"},
		User:      events.User{LocalUser: "jdoe-local"},
		Agent:     &events.Agent{Product: contract.AgentProductClaudeCode, SessionID: "ses_A"},
		Action:    &events.Action{Kind: contract.ActionKindShellExec, Target: "cat ~/<redacted_path> --password <redacted>"},
		Decision:  &events.Decision{Verdict: contract.VerdictAsk},
		Redaction: map[string]contract.PrivacyLevel{}}
	if err := store.Append(ev, plain); err != nil {
		t.Fatal(err)
	}
	store.Close()
	os.WriteFile(filepath.Join(data, "privometryd.log"), []byte("time=x level=INFO msg=\"privometryd listening\" socket="+data+"/privometryd.sock\ntime=x level=WARN msg=oops token="+token+"\n"), 0o600)
	os.WriteFile(filepath.Join(data, "spool.jsonl"), []byte(`{"target_clear":"SPOOLED-FULL-COMMAND"}`+"\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".privometry"), 0o700)
	os.WriteFile(filepath.Join(home, ".privometry", "policy.yaml"), []byte("schema: privometry.policy/v1\nname: mine\nrules:\n  - id: allow-ls\n    when: { action: shell_exec, program: ls }\n    verdict: allow\n"), 0o600)

	out := filepath.Join(t.TempDir(), "b.zip")
	t.Chdir(t.TempDir()) // outside any repo: this one's own .privometry/policy.yaml would add a repo layer
	var stdout, stderr bytes.Buffer
	code := run([]string{"doctor", "--no-probe", "--bundle", "--output", out}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("doctor must fail while the service and daemon are missing: exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"✗ Service", "Fix: privometry daemon install", "✓ Data folder", "1 decisions made while privometryd was down", "and the user policy", "Wrote " + out} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("doctor output lacks %q:\n%s", want, stdout.String())
		}
	}

	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	for _, name := range []string{"README.txt", "doctor.json", "system.json", "guard.json", "policy/user.yaml", "policy/merged.json", "policy/enforce.cedar", "service/" + filepath.Base(launchOrUnit(home)), "privometryd.log", "events.jsonl", "spool.txt"} {
		if _, ok := files[name]; !ok {
			t.Errorf("bundle lacks %s (has %v)", name, keys(files))
		}
	}
	for name, body := range files {
		for _, leak := range []string{"hunter2-secret-value", "SPOOLED-FULL-COMMAND", token, "jdoe-local", home} {
			if strings.Contains(body, leak) {
				t.Errorf("%s leaks %q", name, leak)
			}
		}
	}
	var checks []Check
	if err := json.Unmarshal([]byte(files["doctor.json"]), &checks); err != nil || len(checks) < 8 {
		t.Errorf("doctor.json: %v %d checks", err, len(checks))
	}
	if lines := strings.Count(files["events.jsonl"], "\n"); lines != 1 || !strings.Contains(files["events.jsonl"], `"local_user":"<user>"`) {
		t.Errorf("events.jsonl:\n%s", files["events.jsonl"])
	}
	if !strings.Contains(files["privometryd.log"], "privometryd listening") || !strings.Contains(files["policy/user.yaml"], "allow-ls") {
		t.Error("log and policy must be kept, scrubbed")
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("bundle must be private: %v", err)
	}

	// Never overwrite an existing file.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"doctor", "--no-probe", "--bundle", "--output", out}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "exists") {
		t.Errorf("second bundle to the same path: exit %d %s", code, stderr.String())
	}
}

func launchOrUnit(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library/LaunchAgents/dev.privometry.privometryd.plist")
	}
	return filepath.Join(home, ".config/systemd/user/privometryd.service")
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUpdateRefusesWithoutReleaseKeys(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"update", "--check"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "no release signing keys") {
		t.Errorf("exit %d: %s%s", code, stdout.String(), stderr.String())
	}
}
