package daemon

import (
	"context"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/extension"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// connectorTick is how often the daemon gives the connector a chance to work;
// the connector decides what actually runs.
const connectorTick = 10 * time.Second

// connectorLoop keeps the device in step with its control plane.
func (d *Daemon) connectorLoop(ctx context.Context) {
	tick := time.NewTicker(connectorTick)
	defer tick.Stop()
	for {
		d.conn.Sync(ctx, d.cfg.Now())
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// host is the daemon as its connector sees it (extension.Host).
type host struct{ d *Daemon }

func (h host) Timeline() *timeline.Store { return h.d.store }

func (h host) SensorVersion() string { return h.d.device.SensorVersion }

func (h host) AdapterSetVersion() int64 { return h.d.cfg.AdapterSetVersion }

// Hooks reports each supported agent's Privometry hook as installed,
// modified (partial or pointing at another hook client), disabled (a user or
// managed setting turns the agent's hooks off) or missing.
func (h host) Hooks() []extension.HookStatus {
	var out []extension.HookStatus
	for _, a := range h.d.cfg.Registry.All() {
		st := guard.Check(a, guard.Options{Env: h.d.cfg.Env})
		state := extension.HookMissing
		switch st.State {
		case "installed":
			state = extension.HookInstalled
		case "partial", "stale":
			state = extension.HookModified
		case "disabled":
			state = extension.HookDisabled
		case "unsupported":
			state = extension.HookUnsupported
		}
		out = append(out, extension.HookStatus{Agent: a.Agent, Tier: contract.ConfigTierUser, State: state})
	}
	return out
}

// Scan runs a machine scan for the inventory snapshot, without content
// detectors, and keeps its MCP servers for catalog matching.
func (h host) Scan() (*scanner.Result, error) {
	res, err := scanner.Scan(h.d.cfg.Registry, scanner.Options{Options: discover.Options{Env: h.d.cfg.Env, Machine: true}})
	if err != nil {
		return nil, err
	}
	h.d.rememberServers(res)
	return res, nil
}

// Rescan rehashes agent configs and memory files in the background.
func (h host) Rescan() {
	d := h.d
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

func (h host) SetFingerprintKey(key []byte, id string) { h.d.content.SetFingerprintKey(key, id) }

func (h host) FingerprintKeyID() string { return h.d.content.FingerprintKeyID() }
