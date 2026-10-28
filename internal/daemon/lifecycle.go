package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/events"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/redact"
	"github.com/privometry/privometry-oss/internal/timeline"
)

// Files in the data directory that say whether privometryd was running.
const (
	AliveFile = "alive.json"   // rewritten every minute while running
	StopFile  = "stopped.json" // written on a graceful stop, removed at the next start
)

const (
	// downAfter is how long privometryd may be down before it says so: a
	// restart by launchd or systemd, or an upgrade, takes seconds.
	downAfter = 5 * time.Minute
	// uploadWait bounds how long an uninstall waits for its event to reach
	// the cloud before the sensor stops.
	uploadWait = 5 * time.Second
)

type lifeMark struct {
	At  contract.Time `json:"at"`
	PID int           `json:"pid"`
}

// MarkAlive records that privometryd is running now.
func (d *Daemon) MarkAlive() error { return d.writeMark(AliveFile) }

// MarkStopped records a graceful stop, so the next start can tell it from a
// kill.
func (d *Daemon) MarkStopped() error { return d.writeMark(StopFile) }

func (d *Daemon) writeMark(name string) error {
	b, _ := json.Marshal(lifeMark{At: contract.At(d.cfg.Now()), PID: os.Getpid()})
	tmp := filepath.Join(d.dataDir, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.dataDir, name))
}

func (d *Daemon) readMark(name string) (time.Time, bool) {
	raw, err := os.ReadFile(filepath.Join(d.dataDir, name))
	if err != nil {
		return time.Time{}, false
	}
	var m lifeMark
	if json.Unmarshal(raw, &m) != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, m.At.String())
	return t, err == nil
}

// CheckLastRun runs at start, before the first MarkAlive: when the previous
// run ended more than five minutes ago and the system has not restarted
// since, it records sensor_stopped with how long privometryd was down,
// whether it was stopped (a stop marker) or killed (none), and how many
// actions privometry-hook decided with its fail modes meanwhile (from the
// spool, before it is imported). A shutdown or reboot is nothing to report.
// It reports whether it recorded an event.
func (d *Daemon) CheckLastRun() (bool, error) {
	alive, ok := d.readMark(AliveFile)
	if !ok {
		return false, nil // the first run
	}
	since, reason := alive, events.IntegrityReasonKilled
	if stopped, ok := d.readMark(StopFile); ok && !stopped.Before(alive) {
		since, reason = stopped, events.IntegrityReasonStopped
	}
	if err := os.Remove(filepath.Join(d.dataDir, StopFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if boot, err := d.cfg.BootTime(); err == nil && boot.After(since) {
		return false, nil
	}
	now := d.cfg.Now()
	down := now.Sub(since)
	if down < downAfter {
		return false, nil
	}
	actions := d.spooledSince(since)
	how := "was killed"
	if reason == events.IntegrityReasonStopped {
		how = "was stopped"
	}
	detail := fmt.Sprintf("privometryd %s and stayed down for %s, outside a shutdown or reboot.", how, down.Round(time.Minute))
	if actions > 0 {
		detail += fmt.Sprintf(" Meanwhile privometry-hook decided %d actions with its fail modes alone.", actions)
	}
	secs, n := int64(down/time.Second), int64(actions)
	in := &events.Integrity{Check: events.IntegrityCheckSensorStopped, Reason: reason, DownSeconds: &secs, ActionsWhileDown: &n, Detail: detail}
	d.cfg.Logger.Warn("privometryd was down", "since", since, "reason", reason, "actions", actions)
	return true, d.recordLifecycle(in)
}

// spooledSince counts the decisions privometry-hook spooled at or after t.
func (d *Daemon) spooledSince(t time.Time) int {
	f, err := os.Open(filepath.Join(d.dataDir, SpoolFile))
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		var e SpoolEntry
		if line == "" || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if at, err := time.Parse(time.RFC3339Nano, e.Event.OccurredAt.String()); err == nil && !at.Before(t) {
			n++
		}
	}
	return n
}

// Lifecycle is the query of the lifecycle operation: the CLI telling the
// daemon what a person just did to it, before or after doing it.
type Lifecycle struct {
	// Event is sensor_uninstalled (privometry daemon uninstall, before the
	// service stops) or hook_removed (privometry guard uninstall, after the
	// hook entries are gone).
	Event string                `json:"event"`
	Agent contract.AgentProduct `json:"agent,omitempty"`
}

// lifecycle records what the CLI reports and waits up to five seconds for
// it to be uploaded, so the organization hears of an uninstall even though
// the sensor is about to stop. A hook removed this way updates the watched
// file's state, so the file watcher does not report it a second time.
func (d *Daemon) lifecycle(q Lifecycle) error {
	switch q.Event {
	case "sensor_uninstalled":
		in := &events.Integrity{Check: events.IntegrityCheckSensorUninstalled,
			Detail: "privometry daemon uninstall removed the sensor's background service; agent hooks now apply fail modes only."}
		if err := d.recordLifecycle(in); err != nil {
			return err
		}
	case "hook_removed":
		a, ok := d.cfg.Registry.Get(q.Agent)
		if !ok {
			return fmt.Errorf("%w %q", errUnknownAgent, q.Agent)
		}
		var w *watched
		for _, x := range d.watchList() {
			if x.install && x.agent.Agent == a.Agent {
				w = &x
				break
			}
		}
		if w == nil {
			return fmt.Errorf("%s has no hook file", a.DisplayName)
		}
		if guard.Installed(a, guard.Options{Env: d.cfg.Env}) {
			return fmt.Errorf("%s's hook is still installed", a.DisplayName)
		}
		prev, err := d.store.ConfigHashes()
		if err != nil {
			return err
		}
		h := timeline.ConfigHash{Path: w.path, Tier: string(w.tier), Agent: string(a.Agent), SHA256: hashOf(*w)}
		if err := d.store.SetConfigHash(h, d.cfg.Now()); err != nil {
			return err
		}
		in := &events.Integrity{Check: events.IntegrityCheckHookRemoved, AgentProduct: a.Agent, Tier: w.tier,
			Path:   redact.Redact(w.path, redact.Context{Home: d.cfg.Env.Home}),
			Detail: "Privometry's hook was removed with privometry guard uninstall; the agent is no longer checked."}
		if old := prev[w.path].SHA256; old != "" {
			in.ExpectedSHA256 = old
		}
		if h.SHA256 != "" {
			in.ObservedSHA256 = h.SHA256
		}
		if err := d.recordLifecycle(in); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown lifecycle event %q", q.Event)
	}
	d.cloud.UploadSoon()
	ctx, cancel := context.WithTimeout(d.stop, uploadWait)
	defer cancel()
	d.CloudSync(ctx)
	return nil
}

func (d *Daemon) recordLifecycle(in *events.Integrity) error {
	ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeIntegrity,
		OccurredAt: contract.At(d.cfg.Now()), Device: d.device, User: events.User{LocalUser: localUser()}, Integrity: in,
		Redaction: map[string]contract.PrivacyLevel{"user.local_user": contract.PrivacyLevelClear}}
	if in.Path != "" {
		ev.Redaction["integrity.path"] = contract.PrivacyLevelRedacted
	}
	return d.appendEvent(ev, "")
}
