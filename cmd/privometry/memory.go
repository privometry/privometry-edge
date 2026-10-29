package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/privometry/privometry-edge/internal/daemon"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/ipc"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/timeline"
)

const memoryUsage = `Usage: privometry memory <list|history|show|diff|restore> [flags]

  list                      Memory and instruction files Privometry keeps versions of
  history FILE              Every kept version of FILE: when, who changed it, findings
  show FILE --version N     Print version N
  diff FILE [--version N]   What changed between version N (default: the previous one) and the file now
  restore FILE --version N  Write version N back
  restore FILE --last-good  Write back the newest version that scans clean with today's detectors

Versions are kept on this machine only, for 90 days and at least the last 20
per file. Restoring keeps the file's current content as a version first.

Flags:
`

// memoryCall asks the daemon; the versions live in its database.
func memoryCall(env platform.Env, q daemon.MemoryQuery, out any) error {
	addr, err := env.IPCAddress()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(q)
	resp, err := ipc.Call(addr, ipc.Request{Op: "memory", Query: body}, 5*time.Second)
	switch {
	case err == nil:
		return json.Unmarshal(resp.Data, out)
	case resp.V != 0 && strings.Contains(resp.Error, "unknown op"):
		return errors.New("privometryd is older than this CLI; run privometry daemon restart")
	case resp.V != 0:
		return errors.New(resp.Error)
	}
	return fmt.Errorf("privometryd is not running (privometry daemon install), and it keeps the versions: %w", err)
}

// absPath expands ~ and makes a path absolute, as the daemon stores them.
func absPath(env platform.Env, p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = filepath.Join(env.Home, p[1:])
	}
	return filepath.Abs(p)
}

func memoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, memoryUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("memory "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, memoryUsage); fs.PrintDefaults() }
	version := fs.Int64("version", 0, "show, diff, restore: the version number from history")
	lastGood := fs.Bool("last-good", false, "restore: the newest version that scans clean")
	yes := fs.Bool("yes", false, "restore: do not ask for confirmation")
	format := fs.String("format", "table", "list, history: table or json")
	if err := parseInterspersed(fs, args[1:]); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	needPath := func() (string, bool) {
		if fs.NArg() != 1 {
			fs.Usage()
			return "", false
		}
		p, err := absPath(env, fs.Arg(0))
		if err != nil {
			fail(stderr, err)
			return "", false
		}
		return p, true
	}
	display := func(p string) string { return platform.DisplayPath(p, env.Home, "") }

	switch sub {
	case "list":
		var files []daemon.MemoryFileState
		if err := memoryCall(env, daemon.MemoryQuery{Action: "list"}, &files); err != nil {
			return fail(stderr, err)
		}
		if *format == "json" {
			return writeJSON(stdout, files)
		}
		if len(files) == 0 {
			fmt.Fprintln(stdout, "No memory or instruction files seen yet.")
			return 0
		}
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "FILE\tAGENT\tVERSIONS\tLAST CHANGE\tBY\tFINDINGS\tNOW")
		for _, f := range files {
			now := "as kept"
			switch {
			case f.Current == "":
				now = "deleted"
			case f.Current != f.SHA256:
				now = "changed since"
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%s\n", f.Display, f.Agent, f.Versions, f.ObservedAt.Local().Format("2006-01-02 15:04"), f.ChangedBy, f.Findings, now)
		}
		w.Flush()
		return 0
	case "history":
		path, ok := needPath()
		if !ok {
			return 2
		}
		var vs []timeline.MemoryVersion
		if err := memoryCall(env, daemon.MemoryQuery{Action: "history", Path: path}, &vs); err != nil {
			return fail(stderr, err)
		}
		if *format == "json" {
			return writeJSON(stdout, vs)
		}
		fmt.Fprintf(stdout, "%s\n", display(path))
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "VERSION\tSEEN\tBY\tSIZE\tFINDINGS\tNOTE")
		for _, v := range vs {
			note := ""
			switch {
			case v.SHA256 == "":
				note = "file deleted"
			case v.RestoredFrom != 0:
				note = fmt.Sprintf("restored from %d", v.RestoredFrom)
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%s\n", v.ID, v.ObservedAt.Local().Format("2006-01-02 15:04"), v.ChangedBy, v.Size, v.Findings, note)
		}
		w.Flush()
		return 0
	case "show":
		if _, ok := needPath(); !ok || *version == 0 {
			fmt.Fprintln(stderr, "privometry: show needs FILE and --version")
			return 2
		}
		var v daemon.MemoryVersionContent
		if err := memoryCall(env, daemon.MemoryQuery{Action: "show", Version: *version}, &v); err != nil {
			return fail(stderr, err)
		}
		_, _ = io.WriteString(stdout, v.Content)
		return 0
	case "diff":
		path, ok := needPath()
		if !ok {
			return 2
		}
		from := *version
		if from == 0 {
			var vs []timeline.MemoryVersion
			if err := memoryCall(env, daemon.MemoryQuery{Action: "history", Path: path}, &vs); err != nil {
				return fail(stderr, err)
			}
			if len(vs) < 2 {
				fmt.Fprintln(stdout, "Only one version is kept; nothing to compare.")
				return 0
			}
			from = vs[1].ID
		}
		var v daemon.MemoryVersionContent
		if err := memoryCall(env, daemon.MemoryQuery{Action: "show", Version: from}, &v); err != nil {
			return fail(stderr, err)
		}
		now, _ := os.ReadFile(path)
		fmt.Fprintf(stdout, "version %d -> %s now\n", from, display(path))
		_, _ = io.WriteString(stdout, guard.Diff([]byte(v.Content), now))
		return 0
	case "restore":
		path, ok := needPath()
		if !ok {
			return 2
		}
		if (*version == 0) == !*lastGood {
			fmt.Fprintln(stderr, "privometry: restore needs --version N or --last-good")
			return 2
		}
		if !*yes {
			// Find the version first, show what restoring it changes, then
			// restore exactly that version.
			var plan daemon.RestoreResult
			if err := memoryCall(env, daemon.MemoryQuery{Action: "restore", Path: path, Version: *version, LastGood: *lastGood, DryRun: true}, &plan); err != nil {
				return fail(stderr, err)
			}
			*version, *lastGood = plan.From, false
			var v daemon.MemoryVersionContent
			if err := memoryCall(env, daemon.MemoryQuery{Action: "show", Version: *version}, &v); err != nil {
				return fail(stderr, err)
			}
			now, _ := os.ReadFile(path)
			fmt.Fprintf(stdout, "Restoring version %d of %s changes it like this:\n%s", *version, display(path), guard.Diff(now, []byte(v.Content)))
			if !v.Clean {
				fmt.Fprintln(stdout, "Version", *version, "has content findings with today's detectors.")
			}
			answer, err := prompter.Line("Restore it? [y/N] ")
			if err != nil {
				return fail(stderr, err)
			}
			if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
				fmt.Fprintln(stdout, "Nothing changed.")
				return 1
			}
		}
		var res daemon.RestoreResult
		if err := memoryCall(env, daemon.MemoryQuery{Action: "restore", Path: path, Version: *version, LastGood: *lastGood}, &res); err != nil {
			return fail(stderr, err)
		}
		what := fmt.Sprintf("Restored %s to version %d", display(path), res.From)
		if res.Deleted {
			what = fmt.Sprintf("Removed %s, as it was in version %d", display(path), res.From)
		}
		fmt.Fprintf(stdout, "%s (now version %d).", what, res.Version)
		if res.Previous != 0 {
			fmt.Fprintf(stdout, " Its content before the restore is version %d.", res.Previous)
		}
		fmt.Fprintln(stdout)
		return 0
	}
	fmt.Fprint(stderr, memoryUsage)
	return 2
}
