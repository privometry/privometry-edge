// Package heartbeat reports this sensor's health to the cloud every minute
// (PRD EDGE-29, EDGE-24; POST /edge/v1/heartbeat): its version, the newest
// event and the upload backlog, the bundle and key set it holds, and each
// agent's hook state, so the organization sees removed or modified hooks.
// The answer carries commands, repeated until the sensor acknowledges them.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/cloud/keyset"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/riskfeed"
)

// Report is what the sensor knows about itself for one heartbeat.
type Report struct {
	SensorVersion     string
	DeviceSeq         int64
	AdapterSetVersion int64
	Queue             cloud.HeartbeatUploadQueue
	Hooks             []cloud.HeartbeatHook
	Acked             []string // commands applied since the last heartbeat
}

// Send posts a heartbeat and returns the cloud's answer.
func Send(ctx context.Context, base *http.Client, env platform.Env, keys keystore.Store, r Report, now time.Time) (*cloud.HeartbeatResponse, error) {
	id, err := enroll.Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, bundles.ErrNotEnrolled
	}
	hb := cloud.Heartbeat{SentAt: contract.At(now), SensorVersion: r.SensorVersion, DeviceSeq: r.DeviceSeq, AdapterSetVersion: r.AdapterSetVersion,
		UploadQueue: r.Queue, Hooks: r.Hooks, AckedCommands: r.Acked}
	if hb.Hooks == nil {
		hb.Hooks = []cloud.HeartbeatHook{}
	}
	if held, err := bundles.Load(env, now); err == nil && held != nil {
		v := held.Bundle.Version
		hb.BundleID, hb.BundleVersion = held.Bundle.BundleID, &v
	}
	if feed, err := riskfeed.Load(env); err == nil && feed != nil {
		seq := feed.Sequence
		hb.RiskfeedSequence = &seq
	}
	if ks, err := keyset.Load(env); err == nil && ks != nil {
		v := int64(ks.Keys.Version)
		hb.KeysetVersion = &v
	}
	body, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	client, err := enroll.MutualTLS(base, id, keys, 30*time.Second)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimSuffix(id.APIBaseURL, "/") + "/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", hex.EncodeToString(key))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(raw, &p)
		return nil, fmt.Errorf("heartbeat: %s answered %d %s", endpoint, resp.StatusCode, strings.TrimSpace(p.Title+" "+p.Detail))
	}
	var out cloud.HeartbeatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	return &out, nil
}
