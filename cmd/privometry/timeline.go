package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/privometry/privometry-oss/internal/ipc"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/timeline"
)

const timelineUsage = `Usage: privometry timeline [flags]

Show what coding agents did and what Privometry decided, oldest first.

  privometry timeline                       the last 50 events
  privometry timeline --verdict deny --since 24h
  privometry timeline --search terraform --agent cursor
  privometry timeline --follow              keep printing new events
  privometry timeline --web                 open the timeline in your browser

Flags:
`

func timelineCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, timelineUsage); fs.PrintDefaults() }
	agent := fs.String("agent", "", "only this agent, for example claude_code")
	verdict := fs.String("verdict", "", "only allow, ask or deny")
	typ := fs.String("type", "", "only action, prompt, config_change, integrity, fail_mode, inventory or content_finding")
	search := fs.String("search", "", "only events whose command or path contains this text")
	since := fs.String("since", "", "only events newer than this, for example 30m, 24h or 7d")
	limit := fs.Int("limit", 50, "how many events to show")
	format := fs.String("format", "table", "table or json")
	follow := fs.Bool("follow", false, "keep printing new events")
	web := fs.Bool("web", false, "serve the timeline in your browser")
	port := fs.Int("port", 0, "port for --web (default: a free one)")
	noOpen := fs.Bool("no-open", false, "with --web, print the URL instead of opening a browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := daemonEnv()
	if err != nil {
		return fail(stderr, err)
	}
	q := timeline.Query{Agent: *agent, Verdict: *verdict, Type: *typ, Search: *search, Limit: *limit}
	if *since != "" {
		d, err := parseSince(*since)
		if err != nil {
			fmt.Fprintf(stderr, "privometry timeline: --since: %v\n", err)
			return 2
		}
		q.Since = time.Now().Add(-d)
	}
	if *web {
		return serveTimeline(env, *port, !*noOpen, stdout, stderr)
	}

	rows, source, err := queryEvents(env, q)
	if err != nil {
		return fail(stderr, err)
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return 0
	}
	color := useColor(stdout)
	switch {
	case len(rows) > 0 || *follow:
	case q.Agent != "" || q.Verdict != "" || q.Type != "" || q.Search != "" || !q.Since.IsZero():
		fmt.Fprintln(stdout, "No matching events.")
	default:
		fmt.Fprintln(stdout, "No events yet. Once privometry guard install is done, agent queries and actions appear here.")
	}
	printRows(stdout, reverse(rows), color, env.Home, true)
	switch source {
	case "database":
		fmt.Fprintln(stderr, "(the daemon is not running; read the database directly)")
	case "outdated":
		fmt.Fprintln(stderr, "(the daemon is older than this CLI; read the database directly. Run privometry daemon restart to update it)")
	}
	if !*follow {
		return 0
	}
	var last int64
	if len(rows) > 0 {
		last = rows[0].Event.DeviceSeq
	}
	for {
		time.Sleep(time.Second)
		fq := q
		fq.AfterSeq, fq.Since, fq.Limit = last, time.Time{}, 500
		newer, _, err := queryEvents(env, fq)
		if err != nil {
			continue
		}
		if len(newer) > 0 {
			printRows(stdout, newer, color, env.Home, false)
			last = newer[len(newer)-1].Event.DeviceSeq
		}
	}
}

// queryEvents asks the daemon, or reads the database when it is not running.
func queryEvents(env platform.Env, q timeline.Query) ([]timeline.Row, string, error) {
	addr, err := env.IPCAddress()
	if err != nil {
		return nil, "", err
	}
	body, _ := json.Marshal(q)
	source := "database"
	resp, err := ipc.Call(addr, ipc.Request{Op: "events", Query: body}, 2*time.Second)
	switch {
	case err == nil:
		var rows []timeline.Row
		if err := json.Unmarshal(resp.Data, &rows); err != nil {
			return nil, "", err
		}
		return rows, "daemon", nil
	case resp.V != 0:
		// The daemon answered but does not know this operation: it is an
		// older build than this CLI.
		source = "outdated"
	}
	dbPath, err := env.DBPath()
	if err != nil {
		return nil, "", err
	}
	store, err := timeline.OpenReadOnly(dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, source, nil
		}
		return nil, "", err
	}
	defer store.Close()
	rows, err := store.Events(q)
	return rows, source, err
}

func reverse(rows []timeline.Row) []timeline.Row {
	out := make([]timeline.Row, len(rows))
	for i, r := range rows {
		out[len(rows)-1-i] = r
	}
	return out
}

// what is a row's target cut to fit a terminal line.
func what(r timeline.Row, home string) string {
	s := r.Target(home)
	if len([]rune(s)) > 70 {
		s = string([]rune(s)[:69]) + "…"
	}
	return s
}

var colors = map[string]string{"FINDING": "\x1b[35m", "BLOCKED": "\x1b[31m", "BLOCKED*": "\x1b[31m", "ALERT": "\x1b[31;1m", "ASKED": "\x1b[33m", "AUTO": "\x1b[32m", "ALLOWED": "\x1b[32m"}

// printRows writes rows as a table; header adds the column names (the first
// batch of --follow has one, later batches do not).
func printRows(w io.Writer, rows []timeline.Row, color bool, home string, header bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if header && len(rows) > 0 {
		fmt.Fprintln(tw, "TIME\tAGENT\tOUTCOME\tKIND\tWHAT\tWHY")
	}
	today := time.Now().Format("2006-01-02")
	for _, r := range rows {
		t := r.Event.OccurredAt.Local()
		ts := t.Format("15:04:05")
		if t.Format("2006-01-02") != today {
			ts = t.Format("Jan 02 15:04")
		}
		agent := r.AgentName()
		l := r.Label()
		if c, ok := colors[l]; ok && color {
			l = c + l + "\x1b[0m"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", ts, agent, l, orDash(r.Kind()), what(r, home), r.Why())
	}
	tw.Flush()
}

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// parseSince accepts Go durations and a d suffix for days.
func parseSince(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return d, nil
}
