// Package connector is Privometry's cloud connection as the edge's connector
// (internal/extension): an enrolled device renews its certificate, syncs its
// organization's signed bundle and risk feed, uploads its timeline, sends
// heartbeats and inventory, keys credential fingerprints with its
// organization's hash key, and routes asks to the organization's chat. A
// device that is not enrolled does nothing here.
package connector

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/approvals"
	"github.com/privometry/privometry-edge/internal/cloud/cloudsync"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/extension"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
)

// Connector is the cloud connection of one daemon.
type Connector struct {
	host extension.Host
	env  platform.Env
	http *http.Client // server roots to trust; nil means the system's
	log  *slog.Logger
	sync *cloudsync.Syncer
}

// New is the connector for the system's server roots (an
// extension.NewConnector).
func New(h extension.Host, o extension.Options) (extension.Connector, error) {
	return WithHTTP(nil)(h, o)
}

// WithHTTP makes connectors whose cloud requests trust c's server roots;
// tests use it to reach their own server.
func WithHTTP(c *http.Client) extension.NewConnector {
	return func(h extension.Host, o extension.Options) (extension.Connector, error) {
		log := o.Logger
		if log == nil {
			log = slog.Default()
		}
		conn := &Connector{host: h, env: o.Env, http: c, log: log,
			sync: &cloudsync.Syncer{Env: o.Env, HTTP: c, Logger: log, Local: h}}
		conn.refreshFingerprintKey()
		return conn, nil
	}
}

// Sync does the cloud work that is due at now.
func (c *Connector) Sync(ctx context.Context, now time.Time) bool {
	c.refreshFingerprintKey()
	return c.sync.Tick(ctx, now)
}

// UploadSoon makes the next Sync upload whatever the interval.
func (c *Connector) UploadSoon() { c.sync.UploadSoon() }

// RequestApproval asks the organization's approvers through the cloud.
func (c *Connector) RequestApproval(ctx context.Context, r extension.ApprovalRequest) (extension.Approval, error) {
	client, err := approvals.New(c.http, c.env)
	if err != nil {
		return extension.Approval{}, err
	}
	a, err := client.Create(ctx, cloud.ApprovalCreate{EventID: r.EventID, SessionID: r.SessionID, AgentProduct: r.AgentProduct,
		RepoRemote: r.RepoRemote, Message: r.Message, TimeoutSeconds: r.TimeoutSeconds,
		Action: cloud.ApprovalCreateAction{Kind: r.Kind, ToolName: r.ToolName, Target: r.Target, RuleIDs: r.RuleIDs, Risk: r.Risk}})
	if err != nil {
		return extension.Approval{}, err
	}
	return approval(a), nil
}

// WaitApproval long-polls the cloud for the approval's outcome.
func (c *Connector) WaitApproval(ctx context.Context, id string, max time.Duration) (extension.Approval, error) {
	client, err := approvals.New(c.http, c.env)
	if err != nil {
		return extension.Approval{}, err
	}
	a, err := client.Wait(ctx, id, max)
	if err != nil {
		return extension.Approval{}, err
	}
	return approval(a), nil
}

func approval(a *cloud.Approval) extension.Approval {
	out := extension.Approval{ID: a.ApprovalID, Status: extension.ApprovalStatus(a.Status)}
	if a.Responder != nil {
		out.Responder = a.Responder.DisplayName
	}
	return out
}

// refreshFingerprintKey keys credential fingerprints with the organization's
// hash key once the device is enrolled, so the same leaked secret has the
// same fingerprint on every device of the organization (PRD SCAN-15), and
// goes back to the device's own salt when it is not.
func (c *Connector) refreshFingerprintKey() {
	id, err := enroll.Load(c.env)
	if err != nil {
		return
	}
	cur := c.host.FingerprintKeyID()
	if id == nil {
		if cur != "" {
			c.host.SetFingerprintKey(nil, "")
		}
		return
	}
	if id.HashKeyID == cur {
		return
	}
	keys, err := keystore.Open(c.env, id.Keystore)
	if err != nil {
		c.log.Warn("keystore unavailable; fingerprints stay on this device's salt", "err", err)
		return
	}
	key, kid, err := enroll.HashKey(keys)
	if err != nil {
		c.log.Warn("organization hash key unavailable; fingerprints stay on this device's salt", "err", err)
		return
	}
	c.host.SetFingerprintKey(key, kid)
	c.log.Info("credential fingerprints use the organization hash key", "hash_key_id", kid)
}
