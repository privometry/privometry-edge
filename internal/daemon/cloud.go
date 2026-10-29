package daemon

import (
	"context"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// cloudTick is how often the daemon checks whether cloud work is due; the
// syncer decides what actually runs (cloudsync intervals).
const cloudTick = 10 * time.Second

// cloudLoop keeps an enrolled device in step with its organization.
func (d *Daemon) cloudLoop(ctx context.Context) {
	tick := time.NewTicker(cloudTick)
	defer tick.Stop()
	for {
		d.refreshFingerprintKey()
		d.cloud.Tick(ctx, d.cfg.Now())
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// refreshFingerprintKey keys credential fingerprints with the organization's
// hash key once the device is enrolled, so the same leaked secret has the
// same fingerprint on every device of the organization (PRD SCAN-15), and
// goes back to the device's own salt when it is not.
func (d *Daemon) refreshFingerprintKey() {
	id, err := enroll.Load(d.cfg.Env)
	if err != nil {
		return
	}
	cur := d.content.FingerprintKeyID()
	if id == nil {
		if cur != "" {
			d.content.SetFingerprintKey(nil, "")
		}
		return
	}
	if id.HashKeyID == cur {
		return
	}
	keys, err := keystore.Open(d.cfg.Env, id.Keystore)
	if err != nil {
		d.cfg.Logger.Warn("keystore unavailable; fingerprints stay on this device's salt", "err", err)
		return
	}
	key, kid, err := enroll.HashKey(keys)
	if err != nil {
		d.cfg.Logger.Warn("organization hash key unavailable; fingerprints stay on this device's salt", "err", err)
		return
	}
	d.content.SetFingerprintKey(key, kid)
	d.cfg.Logger.Info("credential fingerprints use the organization hash key", "hash_key_id", kid)
}

// The daemon is the cloud syncer's view of this machine (cloudsync.Local).
type cloudLocal struct{ d *Daemon }

func (c cloudLocal) Timeline() *timeline.Store { return c.d.store }

func (c cloudLocal) SensorVersion() string { return c.d.device.SensorVersion }

func (c cloudLocal) AdapterSetVersion() int64 { return c.d.cfg.AdapterSetVersion }

// Hooks reports each supported agent's Privometry hook as installed,
// modified (partial or pointing at another hook client), disabled (a user or
// managed setting turns the agent's hooks off) or missing.
func (c cloudLocal) Hooks() []cloud.HeartbeatHook {
	var out []cloud.HeartbeatHook
	for _, a := range c.d.cfg.Registry.All() {
		st := guard.Check(a, guard.Options{Env: c.d.cfg.Env})
		status := cloud.HeartbeatHookStatusMissing
		switch st.State {
		case "installed":
			status = cloud.HeartbeatHookStatusInstalled
		case "partial", "stale":
			status = cloud.HeartbeatHookStatusModified
		case "disabled":
			status = cloud.HeartbeatHookStatusDisabled
		case "unsupported":
			status = cloud.HeartbeatHookStatusUnsupported
		}
		out = append(out, cloud.HeartbeatHook{AgentProduct: a.Agent, Tier: contract.ConfigTierUser, Status: status})
	}
	return out
}

// Scan runs a machine scan for the inventory snapshot, without content
// detectors, and keeps its MCP servers for catalog matching.
func (c cloudLocal) Scan() (*scanner.Result, error) {
	res, err := scanner.Scan(c.d.cfg.Registry, scanner.Options{Options: discover.Options{Env: c.d.cfg.Env, Machine: true}})
	if err != nil {
		return nil, err
	}
	c.d.rememberServers(res)
	return res, nil
}

// Rescan rehashes agent configs and memory files in the background.
func (c cloudLocal) Rescan() {
	d := c.d
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		if _, err := d.CheckIntegrity(); err != nil {
			d.cfg.Logger.Warn("rescan: integrity check failed", "err", err)
		}
		if _, err := d.CheckMemory(); err != nil {
			d.cfg.Logger.Warn("rescan: memory check failed", "err", err)
		}
	}()
}
