package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/platform"
)

func testEnv(home string) platform.Env {
	return platform.Env{GOOS: runtime.GOOS, Home: home, Getenv: func(string) string { return "" }}
}

// setup writes hooks into the project only, and refuses anything that could
// be a user-level config.
func TestSetupWritesOnlyTheProject(t *testing.T) {
	for agent, file := range map[string]string{
		"claude_code": ".claude/settings.json",
		"codex_cli":   ".codex/hooks.json",
		"cursor":      ".cursor/hooks.json",
		"gemini_cli":  ".gemini/settings.json",
		"copilot_cli": ".github/hooks/privometry-recorder.json",
		"antigravity": ".agents/hooks.json",
	} {
		t.Run(agent, func(t *testing.T) {
			home, out := t.TempDir(), t.TempDir()
			project := filepath.Join(home, "scratch", "rec")
			var stdout bytes.Buffer
			if err := setup([]string{"-agent", agent, "-project", project, "-out", out}, testEnv(home), &stdout); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(project, filepath.FromSlash(file)))
			if err != nil {
				t.Fatal(err)
			}
			recorder, _ := json.Marshal(filepath.Join(out, "hook-recorder")) // Windows backslashes are escaped in JSON
			if !strings.Contains(string(raw), strings.Trim(string(recorder), `"`)) || !strings.Contains(string(raw), " "+agent+" ") {
				t.Errorf("hooks file:\n%s", raw)
			}
			// Nothing in the home folder but the project.
			entries, _ := os.ReadDir(home)
			if len(entries) != 1 || entries[0].Name() != "scratch" {
				t.Errorf("home holds %v", entries)
			}
			if _, err := os.Stat(filepath.Join(out, "recordings")); err != nil {
				t.Error(err)
			}
			if !strings.Contains(stdout.String(), "sanitize -agent "+agent) {
				t.Errorf("instructions:\n%s", stdout.String())
			}
			// A second setup in the same project is refused.
			if err := setup([]string{"-agent", agent, "-project", project, "-out", out}, testEnv(home), &stdout); err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Errorf("second setup: %v", err)
			}
		})
	}
	home := t.TempDir()
	for _, project := range []string{home, filepath.Dir(home)} {
		if err := setup([]string{"-agent", "gemini_cli", "-project", project}, testEnv(home), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "home folder") {
			t.Errorf("setup in %s: %v", project, err)
		}
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("refused setups wrote %v", entries)
	}
}

func TestRecordAndSanitize(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "scratch", "rec")
	rec, fixtures := t.TempDir(), t.TempDir()
	t.Setenv("PRIVOMETRY_RECORD_DIR", rec)
	payload := `{"conversationId":"c1","workspacePaths":["` + project + `"],"toolCall":{"name":"run_command","args":{"CommandLine":"ls ` + home + `/notes"}}}`
	var stdout bytes.Buffer
	hook([]string{"antigravity", "PreToolUse"}, strings.NewReader(payload), &stdout, os.Stderr)
	hook([]string{"antigravity", "PreToolUse"}, strings.NewReader(payload), &stdout, os.Stderr)
	hook([]string{"antigravity", "SessionStart"}, strings.NewReader(`{"conversationId":"c1"}`), &stdout, os.Stderr)
	if stdout.String() != "{}{}{}" {
		t.Errorf("replies %q", stdout.String())
	}

	var out bytes.Buffer
	if err := sanitize([]string{"-agent", "antigravity", "-version", "1.1.21", "-in", rec, "-project", project, "-fixtures", fixtures}, testEnv(home), &out); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(fixtures, "antigravity", "1.1.21", "hooks")
	got, err := os.ReadFile(filepath.Join(dir, "pretooluse-run-command.json"))
	if err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(string(got), `"/home/dev/acme-api"`) || !strings.Contains(string(got), `ls /home/dev/notes`) || strings.Contains(string(got), home) {
		t.Errorf("sanitized:\n%s", got)
	}
	for _, name := range []string{"pretooluse-run-command-2.json", "sessionstart.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Error(err)
		}
	}
	if err := sanitize([]string{"-agent", "antigravity", "-version", "1.1.21", "-in", rec, "-fixtures", fixtures}, testEnv(home), &out); err == nil {
		t.Error("a recorded version is not overwritten")
	}
}

func TestScrubEmails(t *testing.T) {
	in := `{"user_email": "jane.doe+ci@corp.example.co.uk", "remote": "git@github.com:acme/api.git", "url": "https://example.com"}`
	want := `{"user_email": "dev@example.com", "remote": "git@github.com:acme/api.git", "url": "https://example.com"}`
	if got := scrubEmails(in); got != want {
		t.Errorf("scrubEmails:\n got %s\nwant %s", got, want)
	}
}

func TestCursorReplies(t *testing.T) {
	for event, want := range map[string]string{"preToolUse": `{"permission":"allow"}`, "beforeShellExecution": `{"permission":"ask"}`, "stop": ""} {
		if got := reply("cursor", event); got != want {
			t.Errorf("cursor %s: %q, want %q", event, got, want)
		}
	}
	if reply("antigravity", "PreToolUse") != "{}" || reply("claude_code", "PreToolUse") != "" {
		t.Error("other agents' replies changed")
	}
}

func TestCleanerDashedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Cursor's dashed folder names are recorded on macOS")
	}
	home := t.TempDir()
	project := filepath.Join(home, "rec-cursor")
	in := filepath.Join(home, ".cursor", "projects", dashed(project), "agent-transcripts", "t.jsonl")
	got := cleaner(testEnv(home), project).Replace(in)
	if want := "/home/dev/.cursor/projects/home-dev-acme-api/agent-transcripts/t.jsonl"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
