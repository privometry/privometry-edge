package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/privometry/privometry-oss/internal/events"
)

// SpoolEntry is one line privometry-hook appends when it decides without the
// daemon. The daemon completes the event (device, sequence) on import.
type SpoolEntry struct {
	Event       events.Event `json:"event"`
	TargetClear string       `json:"target_clear,omitempty"`
}

// ImportSpool moves the spool aside and records its events. It returns how
// many it imported; malformed lines are skipped.
func (d *Daemon) ImportSpool() (int, error) {
	path := filepath.Join(d.dataDir, SpoolFile)
	work := path + ".importing"
	if err := os.Rename(path, work); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	f, err := os.Open(work)
	if err != nil {
		return 0, err
	}
	defer os.Remove(work)
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e SpoolEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		e.Event.Device = d.device
		if e.Event.Agent != nil && e.Event.Agent.SessionID == "" {
			native := e.Event.Agent.NativeSessionID
			if native == "" {
				native = "unknown"
			}
			if s, err := d.store.Session(string(e.Event.Agent.Product), native, "", d.cfg.Now()); err == nil {
				e.Event.Agent.SessionID = s.ID
			}
		}
		if err := d.appendEvent(&e.Event, e.TargetClear); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}
