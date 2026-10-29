// Package cloudtest is a fake Privometry region for tests: throwaway root,
// policy and license keys, and an edge API over mutual TLS that enrolls
// devices and serves the bundle a test sets. Every message it sends or
// receives is checked against specs/edge-api/v1. Its keys are generated per
// test and never trusted anywhere else.
package cloudtest

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

// Region holds a region's signing keys and its key set signed by root.
type Region struct {
	Root, Policy, License, Feed ed25519.PrivateKey
	KeySet                      contract.Envelope
	OrgID                       string
}

// NewRegion makes fresh keys for one organization's region.
func NewRegion(t testing.TB) *Region {
	t.Helper()
	r := &Region{Root: key(), Policy: key(), License: key(), Feed: key(), OrgID: contract.NewID("org")}
	var keys []map[string]any
	for _, k := range []struct {
		role string
		priv ed25519.PrivateKey
	}{{"root", r.Root}, {"policy", r.Policy}, {"license", r.License}, {"feed", r.Feed}} {
		pub := k.priv.Public().(ed25519.PublicKey)
		keys = append(keys, map[string]any{"keyid": signing.KeyID(k.role, "test-1", pub), "role": k.role,
			"public_key": base64.StdEncoding.EncodeToString(pub), "not_before": "2026-01-01T00:00:00.000Z"})
	}
	doc, _ := json.Marshal(map[string]any{"schema": "privometry.keyset/v1", "version": 1, "issued_at": "2026-01-01T00:00:00.000Z", "keys": keys})
	r.KeySet = r.Sign("root", signing.PayloadTypeKeySet, doc)
	return r
}

func key() ed25519.PrivateKey {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv
}

// Sign signs a payload with the region's key for role.
func (r *Region) Sign(role, payloadType string, payload []byte) contract.Envelope {
	priv := map[string]ed25519.PrivateKey{"root": r.Root, "policy": r.Policy, "license": r.License, "feed": r.Feed}[role]
	return signing.Sign(payloadType, payload, signing.KeyID(role, "test-1", priv.Public().(ed25519.PublicKey)), priv)
}

// Entitlements returns trial entitlements for org signed with the license key.
func (r *Region) Entitlements(t testing.TB, org string, now time.Time) contract.Envelope {
	t.Helper()
	pub := r.License.Public().(ed25519.PublicKey)
	doc := map[string]any{"schema": "privometry.entitlements/v1", "org_id": org, "edition": "trial",
		"features": map[string]bool{"cloud_sync": true, "shared_policies": true}, "limits": map[string]any{"seats": 25, "retention_days": 30,
			"events_per_day": nil, "devices_per_user": 3}, "valid_from": contract.At(now.Add(-time.Hour)), "valid_until": contract.At(now.Add(14 * 24 * time.Hour)),
		"grace_days": 15, "post_expiry_retention_days": 30, "state": "trial", "issued_at": contract.At(now), "key_id": signing.KeyID("license", "test-1", pub)}
	raw := mustJSON(t, doc, "entitlements/v1/entitlements.schema.json")
	return r.Sign("license", "application/vnd.privometry.entitlements+json", raw)
}

// Source is one organization policy file in a bundle.
type Source struct {
	Name, Version, Content string
}

// Bundle is what a test bundle carries.
type Bundle struct {
	Version   int64
	OrgID     string // defaults to the region's organization
	CreatedAt time.Time
	ExpiresAt time.Time
	Sources   []Source
	Catalog   []map[string]any // bundle catalog entries
	Approvals map[string]any   // the bundle's approvals section, when set
}

// Signed returns the bundle as a DSSE envelope signed with the policy key.
func (r *Region) Signed(t testing.TB, b Bundle) []byte {
	t.Helper()
	return r.SignedWith(t, b, "policy")
}

// SignedWith signs the bundle with the region's key for role, so tests can
// present a bundle signed by the wrong key.
func (r *Region) SignedWith(t testing.TB, b Bundle, role string) []byte {
	t.Helper()
	org := b.OrgID
	if org == "" {
		org = r.OrgID
	}
	sources := []map[string]string{}
	for _, s := range b.Sources {
		sources = append(sources, map[string]string{"layer": "org", "name": s.Name, "version": s.Version, "content": s.Content})
	}
	doc := map[string]any{"schema": "privometry.bundle/v1", "bundle_id": contract.NewID("bnd"), "version": b.Version, "org_id": org,
		"created_at": contract.At(b.CreatedAt), "expires_at": contract.At(b.ExpiresAt),
		"defaults":       map[string]any{"unmatched": "auto", "fail_modes": map[string]string{"catastrophic": "closed"}},
		"cedar_policies": "", "cedar_monitor_policies": "", "rules": []any{}, "catalog": map[string]any{"entries": catalog(b.Catalog)},
		"entitlements": r.Entitlements(t, org, b.CreatedAt), "sources": sources}
	if b.Approvals != nil {
		doc["approvals"] = b.Approvals
	}
	raw := mustJSON(t, doc, "policy/v1/bundle.schema.json")
	out, _ := json.Marshal(r.Sign(role, "application/vnd.privometry.bundle+json", raw))
	return out
}

func catalog(entries []map[string]any) []map[string]any {
	if entries == nil {
		return []map[string]any{}
	}
	return entries
}

func mustJSON(t testing.TB, v any, schema string) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := specs.Validate(schema, "cloudtest", raw); err != nil {
		t.Fatalf("cloudtest made an invalid %s: %v", schema, err)
	}
	return raw
}

// Edge is a fake edge API over mutual TLS.
type Edge struct {
	*Region
	t       testing.TB
	Server  *httptest.Server
	ca      *x509.Certificate
	caKey   ed25519.PrivateKey
	mu      sync.Mutex
	bundle  []byte
	Fetches int // GET /bundle requests that presented a valid certificate

	events     map[string]json.RawMessage // uploaded, by event_id
	order      []string                   // event IDs in upload order
	uploadFail int                        // answer uploads with this status, when set
	beats      []cloud.Heartbeat
	snapshots  []cloud.InventorySnapshot
	approvals  map[string]*cloud.Approval
	feeds      map[string][]byte // risk feed documents by "feed snapshot" or "feed delta <base>"
	asked      []cloud.ApprovalCreate
	commands   []cloud.Command // sent in every heartbeat answer until acknowledged
}

// Token is the enrollment token the fake edge accepts.
const Token = "pet_cloudtest-token-0123456789"

// NewEdge starts a fake edge API for the region.
func NewEdge(t testing.TB, r *Region) *Edge {
	t.Helper()
	caKey := key()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cloudtest device CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	ca, _ := x509.ParseCertificate(der)
	e := &Edge{Region: r, t: t, ca: ca, caKey: caKey, events: map[string]json.RawMessage{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /edge/v1/enroll", e.enroll)
	mux.HandleFunc("GET /edge/v1/bundle", e.getBundle)
	mux.HandleFunc("POST /edge/v1/events:batch", e.uploadEvents)
	mux.HandleFunc("POST /edge/v1/heartbeat", e.heartbeat)
	mux.HandleFunc("POST /edge/v1/inventory", e.inventory)
	mux.HandleFunc("POST /edge/v1/approvals", e.createApproval)
	mux.HandleFunc("GET /edge/v1/riskfeed", e.riskfeed)
	mux.HandleFunc("GET /edge/v1/approvals/{id}", e.getApproval)
	e.Server = httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	e.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	e.Server.StartTLS()
	t.Cleanup(e.Server.Close)
	return e
}

// URL is the edge API's base URL.
func (e *Edge) URL() string { return e.Server.URL + "/edge/v1" }

// Client trusts the fake edge's server certificate.
func (e *Edge) Client() *http.Client { return e.Server.Client() }

// Serve sets the bundle envelope GET /bundle returns.
func (e *Edge) Serve(raw []byte) {
	e.mu.Lock()
	e.bundle = raw
	e.mu.Unlock()
}

func (e *Edge) enroll(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/EnrollRequest", "req.json", raw); err != nil {
		e.t.Errorf("EnrollRequest: %v", err)
	}
	var req cloud.EnrollRequest
	_ = json.Unmarshal(raw, &req)
	if req.EnrollmentToken != Token || r.Header.Get("Authorization") != "Bearer "+Token {
		problem(w, 401, "enrollment-token-invalid", "The enrollment token is not valid")
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		problem(w, 400, "invalid-request", "bad csr")
		return
	}
	device := contract.NewID("dev")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: device},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, e.ca, csr.PublicKey, e.caKey)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.ca.Raw}))
	ks := e.KeySet
	resp := cloud.EnrollResponse{DeviceID: device, OrgID: e.OrgID, Region: "in", APIBaseURL: e.URL(), Certificate: chain,
		CertificateExpiresAt: contract.At(tmpl.NotAfter), KeySet: &ks,
		HashKey: cloud.EnrollResponseHashKey{ID: contract.NewID("hk"), Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	out, _ := json.Marshal(resp)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/EnrollResponse", "resp.json", out); err != nil {
		e.t.Errorf("fake EnrollResponse: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = w.Write(out)
}

func (e *Edge) getBundle(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		problem(w, 401, "device-certificate-required", "No device certificate")
		return
	}
	e.mu.Lock()
	e.Fetches++
	raw := e.bundle
	e.mu.Unlock()
	if raw == nil {
		problem(w, 503, "server-error", "no bundle yet")
		return
	}
	var env struct{ Payload string }
	_ = json.Unmarshal(raw, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	var b struct {
		BundleID string `json:"bundle_id"`
	}
	_ = json.Unmarshal(payload, &b)
	if c := r.URL.Query().Get("current"); c != "" && c == b.BundleID {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// FailUploads makes uploads answer status (0 to accept them again).
func (e *Edge) FailUploads(status int) {
	e.mu.Lock()
	e.uploadFail = status
	e.mu.Unlock()
}

// Uploaded returns the uploaded events, in the order they arrived, without duplicates.
func (e *Edge) Uploaded() []json.RawMessage {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]json.RawMessage, 0, len(e.order))
	for _, id := range e.order {
		out = append(out, e.events[id])
	}
	return out
}

// Heartbeats returns the heartbeats received.
func (e *Edge) Heartbeats() []cloud.Heartbeat {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]cloud.Heartbeat(nil), e.beats...)
}

// Command queues a command for the device's next heartbeats.
func (e *Edge) Command(typ cloud.CommandType) string {
	id := contract.NewID("cmd")
	e.mu.Lock()
	e.commands = append(e.commands, cloud.Command{CommandID: id, Type: typ, IssuedAt: contract.At(time.Now())})
	e.mu.Unlock()
	return id
}

func (e *Edge) uploadEvents(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		problem(w, 401, "device-certificate-required", "No device certificate")
		return
	}
	e.mu.Lock()
	fail := e.uploadFail
	e.mu.Unlock()
	if fail != 0 {
		w.Header().Set("Retry-After", "1")
		problem(w, fail, "server-error", "failing on purpose")
		return
	}
	if r.Header.Get("Content-Encoding") != "gzip" {
		problem(w, 400, "invalid-request", "not gzip")
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		problem(w, 400, "invalid-request", "not gzip")
		return
	}
	raw, _ := io.ReadAll(zr)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/EventsBatch", "batch.json", raw); err != nil {
		e.t.Errorf("EventsBatch: %v", err)
	}
	var batch struct {
		Events []json.RawMessage `json:"events"`
	}
	_ = json.Unmarshal(raw, &batch)
	device := r.TLS.PeerCertificates[0].Subject.CommonName
	res := cloud.EventsBatchResult{Rejected: []cloud.EventsBatchResultRejected{}}
	e.mu.Lock()
	for _, ev := range batch.Events {
		var head struct {
			EventID string `json:"event_id"`
			OrgID   string `json:"org_id"`
			Device  struct {
				DeviceID string `json:"device_id"`
			} `json:"device"`
		}
		_ = json.Unmarshal(ev, &head)
		switch {
		case head.OrgID != e.OrgID || head.Device.DeviceID != device:
			res.Rejected = append(res.Rejected, cloud.EventsBatchResultRejected{EventID: head.EventID,
				Type: "https://privometry.dev/problems/event-not-from-device"})
		case e.events[head.EventID] != nil:
			res.Duplicates++
		default:
			e.events[head.EventID] = ev
			e.order = append(e.order, head.EventID)
			res.Accepted++
		}
	}
	e.mu.Unlock()
	e.reply(w, "EventsBatchResult", res)
}

func (e *Edge) heartbeat(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		problem(w, 401, "device-certificate-required", "No device certificate")
		return
	}
	raw, _ := io.ReadAll(r.Body)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/Heartbeat", "heartbeat.json", raw); err != nil {
		e.t.Errorf("Heartbeat: %v", err)
	}
	var hb cloud.Heartbeat
	_ = json.Unmarshal(raw, &hb)
	e.mu.Lock()
	e.beats = append(e.beats, hb)
	pending := []cloud.Command{}
	for _, c := range e.commands {
		acked := false
		for _, a := range hb.AckedCommands {
			acked = acked || a == c.CommandID
		}
		if !acked {
			pending = append(pending, c)
		}
	}
	e.commands = pending
	e.mu.Unlock()
	e.reply(w, "HeartbeatResponse", cloud.HeartbeatResponse{NextHeartbeatSeconds: 60, Commands: pending})
}

// Inventories returns the inventory snapshots received.
func (e *Edge) Inventories() []cloud.InventorySnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]cloud.InventorySnapshot(nil), e.snapshots...)
}

func (e *Edge) inventory(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		problem(w, 401, "device-certificate-required", "No device certificate")
		return
	}
	raw, _ := io.ReadAll(r.Body)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/InventorySnapshot", "inventory.json", raw); err != nil {
		e.t.Errorf("InventorySnapshot: %v", err)
	}
	var snap cloud.InventorySnapshot
	_ = json.Unmarshal(raw, &snap)
	e.mu.Lock()
	e.snapshots = append(e.snapshots, snap)
	e.mu.Unlock()
	out, _ := json.Marshal(cloud.InventoryReceipt{SnapshotID: contract.NewID("inv"), ReceivedAt: contract.At(time.Now())})
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/InventoryReceipt", "receipt.json", out); err != nil {
		e.t.Errorf("fake InventoryReceipt: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(out)
}

// FeedDocument signs a risk feed document with the feed key; the edge serves
// it as the feed's snapshot, or as its delta from base_sequence.
func (e *Edge) FeedDocument(t testing.TB, doc map[string]any) {
	t.Helper()
	raw := mustJSON(t, doc, "riskfeed/v1/riskfeed.schema.json")
	env, _ := json.Marshal(e.Sign("feed", "application/vnd.privometry.riskfeed+json", raw))
	key := doc["feed"].(string) + " snapshot"
	if doc["kind"] == "delta" {
		key = fmt.Sprintf("%s delta %v", doc["feed"], doc["base_sequence"])
	}
	e.mu.Lock()
	if e.feeds == nil {
		e.feeds = map[string][]byte{}
	}
	e.feeds[key] = env
	e.mu.Unlock()
}

func (e *Edge) riskfeed(w http.ResponseWriter, r *http.Request) {
	feed, since := r.URL.Query().Get("feed"), r.URL.Query().Get("since")
	e.mu.Lock()
	env := e.feeds[feed+" delta "+since]
	if since == "" || env == nil {
		env = e.feeds[feed+" snapshot"]
	}
	e.mu.Unlock()
	if env == nil {
		problem(w, 503, "server-error", "no feed")
		return
	}
	var d struct{ Payload string }
	_ = json.Unmarshal(env, &d)
	payload, _ := base64.StdEncoding.DecodeString(d.Payload)
	var doc struct {
		Sequence json.Number `json:"sequence"`
	}
	_ = json.Unmarshal(payload, &doc)
	if since != "" && since == doc.Sequence.String() {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(env)
}

// Approvals returns the approval requests received.
func (e *Edge) Approvals() []cloud.ApprovalCreate {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]cloud.ApprovalCreate(nil), e.asked...)
}

// ApprovalIDs returns the IDs of the approvals created, oldest first.
func (e *Edge) ApprovalIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ids []string
	for id := range e.approvals {
		ids = append(ids, id)
	}
	slices.Sort(ids) // ULIDs sort by time
	return ids
}

// Decide answers a pending approval as a person would.
func (e *Edge) Decide(id string, status cloud.ApprovalStatus, responder string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a := e.approvals[id]; a != nil {
		at := contract.At(time.Now())
		a.Status, a.DecidedAt = status, &at
		a.Responder = &cloud.ApprovalResponder{DisplayName: responder, Channel: cloud.ApprovalResponderChannelSlack}
	}
}

func (e *Edge) createApproval(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		problem(w, 401, "device-certificate-required", "No device certificate")
		return
	}
	raw, _ := io.ReadAll(r.Body)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/ApprovalCreate", "approval.json", raw); err != nil {
		e.t.Errorf("ApprovalCreate: %v", err)
	}
	var req cloud.ApprovalCreate
	_ = json.Unmarshal(raw, &req)
	now := time.Now()
	a := &cloud.Approval{ApprovalID: contract.NewID("apr"), Status: cloud.ApprovalStatusPending, CreatedAt: contract.At(now),
		ExpiresAt: contract.At(now.Add(time.Duration(req.TimeoutSeconds) * time.Second))}
	e.mu.Lock()
	if e.approvals == nil {
		e.approvals = map[string]*cloud.Approval{}
	}
	e.approvals[a.ApprovalID] = a
	e.asked = append(e.asked, req)
	out := *a
	e.mu.Unlock()
	w.Header().Set("Location", "/edge/v1/approvals/"+a.ApprovalID)
	w.WriteHeader(http.StatusCreated)
	e.reply(w, "Approval", out)
}

func (e *Edge) getApproval(w http.ResponseWriter, r *http.Request) {
	wait, _ := time.ParseDuration(r.URL.Query().Get("wait") + "s")
	deadline := time.Now().Add(min(wait, 2*time.Second)) // tests do not wait long
	for {
		e.mu.Lock()
		a := e.approvals[r.PathValue("id")]
		var out cloud.Approval
		if a != nil {
			out = *a
		}
		e.mu.Unlock()
		if a == nil {
			problem(w, 404, "not-found", "No such approval")
			return
		}
		if out.Status != cloud.ApprovalStatusPending || !time.Now().Before(deadline) {
			e.reply(w, "Approval", out)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *Edge) reply(w http.ResponseWriter, message string, v any) {
	out, _ := json.Marshal(v)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/"+message, "resp.json", out); err != nil {
		e.t.Errorf("fake %s: %v", message, err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func problem(w http.ResponseWriter, status int, typ, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"type":"https://privometry.dev/problems/` + typ + `","title":"` + strings.ReplaceAll(title, `"`, "'") + `","status":` +
		big.NewInt(int64(status)).String() + `}`))
}
