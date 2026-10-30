// Package cloudsync keeps an enrolled device in step with its organization,
// from the daemon: it renews the device certificate before it expires,
// fetches the signed policy bundle, uploads the timeline's events and sends
// heartbeats, applying the commands they bring back. A device that is not
// enrolled does nothing here, and nothing here can turn local protection off:
// when the cloud is unreachable the device keeps its bundle and its events
// wait in the timeline.
package cloudsync

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/heartbeat"
	"github.com/privometry/privometry-edge/internal/cloud/inventory"
	"github.com/privometry/privometry-edge/internal/cloud/upload"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/riskfeed"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// Intervals; the heartbeat interval comes from the cloud after the first one.
const (
	DefaultInterval    = 5 * time.Minute // bundle refresh (PRD CP-14: within one refresh interval)
	UploadEvery        = 30 * time.Second
	DefaultHeartbeat   = 60 * time.Second
	InventoryEvery     = 24 * time.Hour
	FeedEvery          = time.Hour // risk feed deltas are published hourly
	retryInventory     = time.Hour
	retryRenew         = time.Hour
	maxUploadBackoff   = 10 * time.Minute
	firstUploadBackoff = 15 * time.Second
)

// Local is what the daemon tells the cloud about this machine.
type Local interface {
	Timeline() *timeline.Store
	SensorVersion() string
	AdapterSetVersion() int64
	Hooks() []cloud.HeartbeatHook
	// Rescan runs the scans a rescan command asks for, in the background.
	Rescan()
	// Scan runs a machine scan for the inventory snapshot.
	Scan() (*scanner.Result, error)
}

// Syncer does the cloud work that is due each time Tick runs.
type Syncer struct {
	Env      platform.Env
	HTTP     *http.Client // server roots to trust; nil means the system's
	Logger   *slog.Logger
	Interval time.Duration // bundle refresh; 0 means DefaultInterval
	Local    Local         // nil: no upload or heartbeat (tests of bundles alone)

	mu            sync.Mutex
	nextBundle    time.Time
	nextRenew     time.Time
	nextUpload    time.Time
	uploadBackoff time.Duration
	refused       bool
	refusedCert   string // the certificate the cloud refused; a new enrollment replaces it
	nextBeat      time.Time
	nextInventory time.Time
	nextFeed      time.Time
	acked         []string
	ignored       map[string]bool
}

// RefreshBundle makes the next Tick fetch the bundle whatever the interval.
func (s *Syncer) RefreshBundle() {
	s.mu.Lock()
	s.nextBundle = time.Time{}
	s.mu.Unlock()
}

// UploadSoon makes the next Tick upload whatever the interval, unless the
// cloud refused this device or asked it to back off.
func (s *Syncer) UploadSoon() {
	s.mu.Lock()
	if s.uploadBackoff == 0 {
		s.nextUpload = time.Time{}
	}
	s.mu.Unlock()
}

// Tick does whatever is due. It reports whether a new bundle was stored.
func (s *Syncer) Tick(ctx context.Context, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := enroll.Load(s.Env)
	if err != nil {
		s.log().Warn("device identity unreadable", "err", err)
		return false
	}
	if id == nil {
		return false
	}
	if s.refused && id.Certificate != s.refusedCert {
		s.refused = false // enrolled again since the refusal
		s.nextUpload = time.Time{}
	}
	keys, err := keystore.Open(s.Env, id.Keystore)
	if err != nil {
		s.log().Warn("keystore unavailable", "err", err)
		return false
	}
	base := s.HTTP
	if base == nil {
		base = &http.Client{Transport: http.DefaultTransport}
	}
	if !now.Before(s.nextRenew) && id.CertificateExpiresAt.Sub(now) < enroll.RenewBefore {
		if renewed, err := enroll.Renew(ctx, base, s.Env, keys); err != nil {
			s.log().Warn("certificate renewal failed", "err", err, "expires", id.CertificateExpiresAt)
			s.nextRenew = now.Add(retryRenew)
		} else {
			s.log().Info("device certificate renewed", "expires", renewed.CertificateExpiresAt)
			s.refused = false
		}
	}
	changed := false
	if !now.Before(s.nextBundle) {
		changed = s.syncBundle(ctx, base, keys, now)
	}
	if !now.Before(s.nextFeed) {
		s.nextFeed = now.Add(FeedEvery)
		if updated, err := riskfeed.Sync(ctx, base, s.Env, keys, now); err != nil {
			s.log().Warn("risk feed sync failed; keeping the feed this device holds", "err", err)
		} else if updated {
			s.log().Info("risk feed updated")
		}
	}
	if s.Local != nil {
		if !now.Before(s.nextInventory) {
			s.inventory(ctx, base, keys, now)
		}
		s.upload(ctx, base, keys, id.Certificate, now)
		if !now.Before(s.nextBeat) {
			changed = s.heartbeat(ctx, base, keys, now) || changed
		}
	}
	return changed
}

func (s *Syncer) syncBundle(ctx context.Context, base *http.Client, keys keystore.Store, now time.Time) bool {
	interval := s.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	s.nextBundle = now.Add(interval)
	res, err := bundles.Sync(ctx, base, s.Env, keys, now)
	if err != nil {
		s.log().Warn("bundle sync failed; keeping the bundle this device holds", "err", err)
		return false
	}
	if res.Changed {
		s.log().Info("organization bundle updated", "version", res.Held.Bundle.Version, "bundle_id", res.Held.Bundle.BundleID)
	}
	return res.Changed
}

func (s *Syncer) upload(ctx context.Context, base *http.Client, keys keystore.Store, cert string, now time.Time) {
	if s.refused || now.Before(s.nextUpload) {
		return
	}
	var privacy *bundles.BundlePrivacy
	if held, err := bundles.Load(s.Env, now); err == nil && held != nil {
		if !held.Entitlements.Features["cloud_sync"] {
			s.nextUpload = now.Add(UploadEvery)
			return // the organization is not entitled to cloud sync: events stay local
		}
		privacy = held.Bundle.Privacy
	}
	res, err := upload.Run(ctx, base, s.Local.Timeline(), s.Env, keys, privacy)
	switch {
	case errors.Is(err, upload.ErrRefused):
		s.log().Warn("uploads stopped until this device enrolls or renews again", "err", err)
		s.refused = true
		s.refusedCert = cert
	case err != nil:
		if s.uploadBackoff == 0 {
			s.uploadBackoff = firstUploadBackoff
		} else {
			s.uploadBackoff = min(2*s.uploadBackoff, maxUploadBackoff)
		}
		wait := s.uploadBackoff
		if res != nil && res.RetryAfter > wait {
			wait = res.RetryAfter
		}
		s.nextUpload = now.Add(wait)
		s.log().Warn("event upload failed; events stay in the timeline", "err", err, "retry_in", wait)
	default:
		s.uploadBackoff = 0
		s.nextUpload = now.Add(UploadEvery)
		if res.Remaining > 0 {
			s.nextUpload = now // a backlog continues on the next tick
		}
		if res.Rejected > 0 {
			s.log().Warn("the cloud rejected events; they will not be sent again", "rejected", res.Rejected)
		}
	}
}

func (s *Syncer) heartbeat(ctx context.Context, base *http.Client, keys keystore.Store, now time.Time) bool {
	store := s.Local.Timeline()
	r := heartbeat.Report{SensorVersion: s.Local.SensorVersion(), AdapterSetVersion: s.Local.AdapterSetVersion(), Hooks: s.Local.Hooks(), Acked: s.acked}
	r.DeviceSeq, _ = store.LastSeq()
	cursor, _ := upload.Cursor(store)
	if b, err := store.BacklogAfter(cursor); err == nil {
		r.Queue = cloud.HeartbeatUploadQueue{Events: int64(b.Events), Bytes: b.Bytes}
		if !b.Oldest.IsZero() {
			at := contract.At(b.Oldest)
			r.Queue.OldestAt = &at
		}
	}
	resp, err := heartbeat.Send(ctx, base, s.Env, keys, r, now)
	if err != nil {
		s.nextBeat = now.Add(DefaultHeartbeat)
		s.log().Warn("heartbeat failed", "err", err)
		return false
	}
	s.acked = nil
	s.nextBeat = now.Add(time.Duration(resp.NextHeartbeatSeconds) * time.Second)
	changed := false
	for _, c := range resp.Commands {
		switch c.Type {
		case cloud.CommandTypeRefreshBundle:
			changed = s.syncBundle(ctx, base, keys, now) || changed
			s.acked = append(s.acked, c.CommandID)
		case cloud.CommandTypeRescan:
			s.Local.Rescan()
			s.inventory(ctx, base, keys, now)
			s.acked = append(s.acked, c.CommandID)
		default:
			// Kill-switch and diagnostics commands are not supported by this sensor yet; leaving them
			// unacknowledged keeps the console honest about what the device did.
			if s.ignored == nil {
				s.ignored = map[string]bool{}
			}
			if !s.ignored[c.CommandID] {
				s.ignored[c.CommandID] = true
				s.log().Warn("command not supported by this sensor", "type", c.Type, "command_id", c.CommandID)
			}
		}
	}
	return changed
}

// inventory scans the machine and sends the snapshot (PRD CP-07).
func (s *Syncer) inventory(ctx context.Context, base *http.Client, keys keystore.Store, now time.Time) {
	res, err := s.Local.Scan()
	if err != nil {
		s.nextInventory = now.Add(retryInventory)
		s.log().Warn("inventory scan failed", "err", err)
		return
	}
	seq, _ := s.Local.Timeline().LastSeq()
	if _, err := inventory.Send(ctx, base, s.Env, keys, inventory.Snapshot(res, seq)); err != nil {
		s.nextInventory = now.Add(retryInventory)
		s.log().Warn("inventory upload failed", "err", err)
		return
	}
	s.nextInventory = now.Add(InventoryEvery)
}

func (s *Syncer) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}
