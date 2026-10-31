// Package inventory turns a machine scan into the snapshot the cloud keeps
// for this device (PRD CP-07; POST /edge/v1/inventory): its agents with
// versions, their MCP servers (with the package or host they run), skills,
// plugins and other hooks, and posture issues. Snapshots carry names and
// versions, never command lines, paths or values.
package inventory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/scanner"
)

// Schema is the snapshot's schema identifier.
const Schema = "privometry.inventory_snapshot/v1"

// Snapshot builds the inventory snapshot of a machine scan.
func Snapshot(res *scanner.Result, deviceSeq int64) cloud.InventorySnapshot {
	if deviceSeq < 1 {
		deviceSeq = 1
	}
	snap := cloud.InventorySnapshot{Schema: Schema, ScannedAt: res.ScannedAt, DeviceSeq: deviceSeq, Items: []events.InventoryItem{}}
	add := func(it events.InventoryItem) {
		if len(it.ItemID) > 128 {
			sum := sha256.Sum256([]byte(it.ItemID))
			it.ItemID = string(it.Kind) + ":" + hex.EncodeToString(sum[:16])
		}
		snap.Items = append(snap.Items, it)
	}
	for _, a := range res.Agents {
		if !a.Installed {
			continue
		}
		p := a.Product
		add(events.InventoryItem{ItemID: "agent:" + string(p), Kind: events.InventoryItemKindAgent, AgentProduct: p, Name: string(p), Version: a.Version})
		for _, m := range a.MCPServers {
			it := events.InventoryItem{ItemID: "mcp:" + string(p) + ":" + string(m.Tier) + ":" + m.Name, Kind: events.InventoryItemKindMCPServer,
				AgentProduct: p, Name: m.Name, Tier: m.Tier, PathClass: pathClass(m.Tier), Package: scanner.PackageName(m.Package), Host: hostOf(m.URL)}
			switch m.Transport {
			case "stdio":
				it.MCPTransport = events.InventoryItemMCPTransportStdio
			case "http", "sse", "streamable-http":
				it.MCPTransport = events.InventoryItemMCPTransportHTTP
			}
			add(it)
		}
		for _, s := range a.Skills {
			add(events.InventoryItem{ItemID: "skill:" + string(p) + ":" + string(s.Tier) + ":" + s.Name, Kind: events.InventoryItemKindSkill,
				AgentProduct: p, Name: s.Name, Tier: s.Tier, PathClass: pathClass(s.Tier)})
		}
		for _, pl := range a.Plugins {
			add(events.InventoryItem{ItemID: "plugin:" + string(p) + ":" + string(pl.Tier) + ":" + pl.ID, Kind: events.InventoryItemKindPlugin,
				AgentProduct: p, Name: pl.Name, Version: pl.Version, Tier: pl.Tier, PathClass: pathClass(pl.Tier)})
		}
		seen := map[string]int{}
		for _, h := range a.Hooks {
			if h.Privometry {
				continue // Privometry's own hooks are reported by heartbeats
			}
			key := string(h.Tier) + ":" + h.Event
			seen[key]++
			add(events.InventoryItem{ItemID: fmt.Sprintf("hook:%s:%s:%d", p, key, seen[key]), Kind: events.InventoryItemKindHook,
				AgentProduct: p, Name: h.Event, Tier: h.Tier, PathClass: pathClass(h.Tier)})
		}
	}
	for _, f := range res.Findings {
		it := events.InventoryItem{ItemID: "posture:" + string(f.Agent) + ":" + string(f.Tier) + ":" + f.Check, Kind: events.InventoryItemKindPostureIssue,
			Name: f.Check, Tier: f.Tier, Posture: &events.InventoryItemPosture{CheckID: f.Check, Severity: f.Severity, Message: truncate(f.Message, 1024)}}
		if f.Agent != "" {
			it.AgentProduct = f.Agent
		}
		if f.Tier != "" {
			it.PathClass = pathClass(f.Tier)
		}
		add(it)
	}
	return snap
}

func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func pathClass(t contract.ConfigTier) contract.PathClass {
	switch t {
	case contract.ConfigTierProject:
		return contract.PathClassRepo
	case contract.ConfigTierManaged:
		return contract.PathClassSystem
	}
	return contract.PathClassHome
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Send uploads a snapshot as this device.
func Send(ctx context.Context, base *http.Client, env platform.Env, keys keystore.Store, snap cloud.InventorySnapshot) (*cloud.InventoryReceipt, error) {
	id, err := enroll.Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, bundle.ErrNotEnrolled
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	client, err := enroll.MutualTLS(base, id, keys, 60*time.Second)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimSuffix(id.APIBaseURL, "/") + "/inventory"
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
		return nil, fmt.Errorf("inventory: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted {
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(raw, &p)
		return nil, fmt.Errorf("inventory: %s answered %d %s", endpoint, resp.StatusCode, strings.TrimSpace(p.Title+" "+p.Detail))
	}
	var out cloud.InventoryReceipt
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	return &out, nil
}
