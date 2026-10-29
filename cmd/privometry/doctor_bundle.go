package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/redact"
	"github.com/privometry/privometry-edge/internal/timeline"
)

const (
	bundleLogLines = 2000
	bundleEvents   = 500
)

const bundleReadme = `Privometry diagnostic bundle

Made by privometry doctor --bundle on %s, to share with whoever helps you debug
Privometry. Read it before you send it.

Included:
  doctor.json      every doctor check and its result
  system.json      versions, OS, daemon status, Privometry-related settings
  guard.json       each agent's hook state
  failmodes.json   what privometry-hook does when the daemon is down
  policy/          your user and repo policy files, and the merged policy
  service/         the launchd or systemd file privometry daemon install writes
  privometryd.log       the last %d lines of the daemon log
  events.jsonl     the last %d timeline events in their redacted form, the
                   one that would be uploaded: commands are kept, but secrets
                   and paths outside the repo are replaced

Left out:
  The unredacted commands and paths the agents used (the timeline's
  local-only "target_clear" column), and the contents of spool.jsonl, which
  holds them. Agent config files, which can hold API keys.

Secrets that match Privometry's redaction rules (tokens, keys, passwords,
credentials in URLs, emails) are replaced with placeholders everywhere.
Paths are kept so the log stays useful; your home folder is shown as ~ and
other users' names are hidden.
`

// writeBundle writes a redacted diagnostic zip. It never overwrites a file.
func writeBundle(path string, r *doctorRun) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	b := &bundle{zw: zw, home: r.env.Home, now: time.Now()}

	b.text("README.txt", fmt.Sprintf(bundleReadme, b.now.Format(time.RFC1123), bundleLogLines, bundleEvents), false)
	b.json("doctor.json", r.checks)
	b.json("system.json", map[string]any{
		"privometry": buildinfo.String("privometry"),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"data_dir":   r.dataDir,
		"env":        envSettings(r),
		"daemon":     r.status,
	})
	b.json("guard.json", r.guards)
	b.file("failmodes.json", filepath.Join(r.dataDir, daemon.FailModesFile))
	b.file("policy/user.yaml", filepath.Join(r.env.Home, policy.UserPolicyPath))
	if r.repo != "" {
		b.file("policy/repo.yaml", filepath.Join(r.repo, policy.RepoPolicyPath))
	}
	if r.merged != nil {
		b.json("policy/merged.json", map[string]any{
			"packs": r.merged.Packs, "unmatched": r.merged.Unmatched, "fail_modes": r.merged.FailModes,
			"rules": r.merged.Rules, "diagnostics": r.merged.Diagnostics,
		})
		b.text("policy/enforce.cedar", r.merged.Enforce, true)
		b.text("policy/monitor.cedar", r.merged.Monitor, true)
	}
	if r.plan != nil {
		b.text("service/"+filepath.Base(r.plan.Path), string(r.plan.Content), true)
	}
	b.logTail("privometryd.log", filepath.Join(r.dataDir, "privometryd.log"))
	b.events(r)
	b.spoolCount(filepath.Join(r.dataDir, daemon.SpoolFile))

	if b.err == nil {
		b.err = zw.Close()
	}
	if cerr := f.Close(); b.err == nil {
		b.err = cerr
	}
	if b.err != nil {
		os.Remove(path)
	}
	return b.err
}

type bundle struct {
	zw   *zip.Writer
	home string
	now  time.Time
	err  error
}

func (b *bundle) clean(s string) string { return redact.Secrets(s, b.home) }

func (b *bundle) text(name, content string, scrub bool) {
	if b.err != nil {
		return
	}
	if scrub {
		content = b.clean(content)
	}
	w, err := b.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: b.now})
	if err != nil {
		b.err = err
		return
	}
	_, b.err = w.Write([]byte(content))
}

func (b *bundle) json(name string, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		b.err = err
		return
	}
	b.text(name, buf.String(), true)
}

// file copies a small text file, scrubbed; a missing file is skipped.
func (b *bundle) file(name, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	b.text(name, string(raw), true)
}

func (b *bundle) logTail(name, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > bundleLogLines {
			lines = lines[1:]
		}
	}
	b.text(name, strings.Join(lines, "\n")+"\n", true)
}

// events writes the stored events without target_clear, the column that
// keeps full commands on this machine.
func (b *bundle) events(r *doctorRun) {
	dbPath, err := r.env.DBPath()
	if err != nil {
		return
	}
	store, err := timeline.OpenReadOnly(dbPath)
	if err != nil {
		return
	}
	defer store.Close()
	rows, err := store.Events(timeline.Query{Limit: bundleEvents})
	if err != nil {
		b.err = err
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for i := len(rows) - 1; i >= 0; i-- {
		ev := rows[i].Event // rows[i].TargetClear is deliberately dropped
		ev.User.LocalUser = "<user>"
		if err := enc.Encode(ev); err != nil {
			b.err = err
			return
		}
	}
	b.text("events.jsonl", buf.String(), true)
}

func (b *bundle) spoolCount(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	n := bytes.Count(raw, []byte("\n"))
	b.text("spool.txt", fmt.Sprintf("spool.jsonl: %d decisions waiting for import, %d bytes. Contents not included: they hold full commands.\n", n, len(raw)), false)
}

// envSettings lists the environment variables Privometry reads, scrubbed.
func envSettings(r *doctorRun) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"PRIVOMETRY_HOME", "PRIVOMETRY_HOOK_TIMEOUT_MS", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "NO_COLOR"} {
		if v := r.env.Getenv(k); v != "" {
			out[k] = v
		}
	}
	return out
}
