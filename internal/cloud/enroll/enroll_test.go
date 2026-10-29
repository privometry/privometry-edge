package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/specs"
)

// edge is a fake edge API: /enroll takes a token, /certs:renew only a client
// certificate its CA issued (mutual TLS), as the platform's do.
type edge struct {
	t      *testing.T
	srv    *httptest.Server
	ca     *x509.Certificate
	caKey  ed25519.PrivateKey
	mu     sync.Mutex
	tokens map[string]bool
	keys   map[string]ed25519.PublicKey // current key per device
}

func newEdge(t *testing.T) *edge {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test device CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	ca, _ := x509.ParseCertificate(der)
	e := &edge{t: t, ca: ca, caKey: caKey, tokens: map[string]bool{"pet_valid-token-0123456789": true}, keys: map[string]ed25519.PublicKey{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /edge/v1/enroll", e.enroll)
	mux.HandleFunc("POST /edge/v1/certs:renew", e.renew)
	e.srv = httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	e.srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	return e
}

func (e *edge) issue(w http.ResponseWriter, csrPEM, device string) ed25519.PublicKey {
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "bad csr", 400)
		return nil
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: device},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, e.ca, csr.PublicKey, e.caKey)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.ca.Raw}))
	w.Header().Set("X-Chain", base64.StdEncoding.EncodeToString([]byte(chain)))
	return csr.PublicKey.(ed25519.PublicKey)
}

func (e *edge) enroll(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/EnrollRequest", "req.json", raw); err != nil {
		e.t.Errorf("EnrollRequest: %v", err)
	}
	var req cloud.EnrollRequest
	json.Unmarshal(raw, &req)
	e.mu.Lock()
	ok := e.tokens[req.EnrollmentToken]
	delete(e.tokens, req.EnrollmentToken)
	e.mu.Unlock()
	if !ok || r.Header.Get("Authorization") != "Bearer "+req.EnrollmentToken {
		w.WriteHeader(401)
		w.Write([]byte(`{"type":"https://privometry.dev/problems/enrollment-token-invalid","title":"The enrollment token is not valid","status":401}`))
		return
	}
	device := contract.NewID("dev")
	pub := e.issue(w, req.CSR, device)
	e.mu.Lock()
	e.keys[device] = pub
	e.mu.Unlock()
	chain, _ := base64.StdEncoding.DecodeString(w.Header().Get("X-Chain"))
	e.reply(w, 201, "EnrollResponse", cloud.EnrollResponse{DeviceID: device, OrgID: contract.NewID("org"), Region: "in", APIBaseURL: e.srv.URL + "/edge/v1",
		Certificate: string(chain), CertificateExpiresAt: contract.At(time.Now().Add(30 * 24 * time.Hour)),
		HashKey: cloud.EnrollResponseHashKey{ID: contract.NewID("hk"), Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}})
}

func (e *edge) renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(401)
		w.Write([]byte(`{"type":"https://privometry.dev/problems/device-certificate-required","title":"No device certificate","status":401}`))
		return
	}
	peer := r.TLS.PeerCertificates[0]
	device := peer.Subject.CommonName
	e.mu.Lock()
	current := e.keys[device]
	e.mu.Unlock()
	if current == nil || !current.Equal(peer.PublicKey) {
		e.t.Errorf("renew presented a certificate for another key")
	}
	raw, _ := io.ReadAll(r.Body)
	var req cloud.RenewRequest
	json.Unmarshal(raw, &req)
	pub := e.issue(w, req.CSR, device)
	e.mu.Lock()
	e.keys[device] = pub
	e.mu.Unlock()
	chain, _ := base64.StdEncoding.DecodeString(w.Header().Get("X-Chain"))
	e.reply(w, 200, "RenewResponse", cloud.RenewResponse{Certificate: string(chain), CertificateExpiresAt: contract.At(time.Now().Add(30 * 24 * time.Hour))})
}

func (e *edge) reply(w http.ResponseWriter, status int, message string, v any) {
	raw, _ := json.Marshal(v)
	if err := specs.Validate("edge-api/v1/messages.schema.json#/$defs/"+message, "resp.json", raw); err != nil {
		e.t.Errorf("fake %s: %v", message, err)
	}
	w.Header().Del("X-Chain")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(raw)
}

func testEnv(t *testing.T) (platform.Env, keystore.Store) {
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	keys, err := keystore.Open(env, "file")
	if err != nil {
		t.Fatal(err)
	}
	return env, keys
}

func TestEnrollThenRenewOverMutualTLS(t *testing.T) {
	e := newEdge(t)
	env, keys := testEnv(t)
	ctx := context.Background()
	if _, err := Enroll(ctx, e.srv.Client(), e.srv.URL+"/edge/v1", "pet_wrong-token-0123456789", env, keys, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "enrollment token is not valid") {
		t.Fatalf("a wrong token: %v", err)
	}
	id, err := Enroll(ctx, e.srv.Client(), e.srv.URL+"/edge/v1", "pet_valid-token-0123456789", env, keys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	firstKey, _ := keys.Get(DeviceKeyName)

	renewed, err := Renew(ctx, e.srv.Client(), env, keys)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.DeviceID != id.DeviceID || renewed.Certificate == id.Certificate {
		t.Errorf("renew: %+v", renewed)
	}
	secondKey, _ := keys.Get(DeviceKeyName)
	if string(firstKey) == string(secondKey) {
		t.Error("renewing rotates the device key")
	}
	if loaded, _ := Load(env); loaded == nil || loaded.Certificate != renewed.Certificate {
		t.Error("device.json keeps the renewed certificate")
	}
	// The renewed certificate works for the next renewal.
	if _, err := Renew(ctx, e.srv.Client(), env, keys); err != nil {
		t.Fatalf("second renewal: %v", err)
	}
}

func TestRenewNeedsAnEnrolledDevice(t *testing.T) {
	e := newEdge(t)
	env, keys := testEnv(t)
	if _, err := Renew(context.Background(), e.srv.Client(), env, keys); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("renew before enrolling: %v", err)
	}
}
