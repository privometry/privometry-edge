// Package enroll enrolls this device with the cloud (POST /edge/v1/enroll,
// specs/edge-api/v1). It generates the device key, which the daemon will use
// unattended for mutual TLS and which therefore has no PIN, sends a
// certificate request with a one-time enrollment token, and keeps the
// certificate and identity the cloud returns. The device key and the
// organization's hash key go in the keystore; the rest in device.json.
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/cloud"
	"github.com/privometry/privometry-oss/internal/cloud/keyset"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/keystore"
	"github.com/privometry/privometry-oss/internal/platform"
)

// Keystore names.
const (
	DeviceKeyName = "device-key"
	HashKeyName   = "org-hash-key"
)

// Identity is what enrollment gave this device, as kept in device.json. It holds
// no secrets.
type Identity struct {
	DeviceID             string    `json:"device_id"`
	OrgID                string    `json:"org_id"`
	UserID               string    `json:"user_id,omitempty"`
	Region               string    `json:"region"`
	APIBaseURL           string    `json:"api_base_url"`
	Certificate          string    `json:"certificate"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	HashKeyID            string    `json:"hash_key_id"`
	Keystore             string    `json:"keystore"`
	EnrolledAt           time.Time `json:"enrolled_at"`
	// KeySetPinned is set when this build has no root keys, so the region's
	// key set was trusted because enrollment delivered it (package keyset).
	KeySetPinned bool `json:"key_set_pinned,omitempty"`
}

// Enroll exchanges a one-time token and a certificate request for a device
// certificate, and keeps the result.
func Enroll(ctx context.Context, client *http.Client, edgeBaseURL, token string, env platform.Env, keys keystore.Store, now time.Time) (*Identity, error) {
	base, err := url.Parse(edgeBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, fmt.Errorf("enroll: %q is not an HTTPS URL", edgeBaseURL)
	}
	priv, csr, err := newKey()
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	body, err := json.Marshal(cloud.EnrollRequest{EnrollmentToken: token, CSR: csr, Device: Device(env)})
	if err != nil {
		return nil, err
	}
	var resp cloud.EnrollResponse
	if err := post(ctx, client, strings.TrimSuffix(edgeBaseURL, "/")+"/enroll", "Bearer "+token, body, http.StatusCreated, &resp); err != nil {
		return nil, err
	}
	cert, err := leaf(resp.Certificate)
	if err != nil {
		return nil, err
	}
	if certPub, ok := cert.PublicKey.(ed25519.PublicKey); !ok || !certPub.Equal(pub) {
		return nil, errors.New("enroll: the certificate is not for this device's key")
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := keys.Put(DeviceKeyName, pkcs8); err != nil {
		return nil, err
	}
	hashKey, err := json.Marshal(resp.HashKey)
	if err != nil {
		return nil, err
	}
	if err := keys.Put(HashKeyName, hashKey); err != nil {
		return nil, err
	}
	id := &Identity{DeviceID: resp.DeviceID, OrgID: resp.OrgID, UserID: resp.UserID, Region: resp.Region, APIBaseURL: resp.APIBaseURL,
		Certificate: resp.Certificate, CertificateExpiresAt: resp.CertificateExpiresAt.Time, HashKeyID: resp.HashKey.ID,
		Keystore: keys.Kind(), EnrolledAt: now.UTC()}
	if resp.KeySet != nil {
		t, err := keyset.Pin(env, *resp.KeySet, now)
		if err != nil {
			return nil, fmt.Errorf("enroll: %w", err)
		}
		id.KeySetPinned = t.Pinned
	}
	return id, save(env, id)
}

// Load reads device.json; nil when this device is not enrolled.
func Load(env platform.Env) (*Identity, error) {
	path, err := identityPath(env)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	return &id, json.Unmarshal(raw, &id)
}

// post sends a JSON body to the edge API and decodes the expected answer.
// authorization is empty for requests authenticated by the client certificate.
func post(ctx context.Context, client *http.Client, endpoint, authorization string, body []byte, want int, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Idempotency-Key", hex.EncodeToString(key))
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if resp.StatusCode != want {
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(raw, &p)
		msg := strings.TrimSpace(p.Title + ": " + p.Detail)
		if p.Title == "" {
			msg = resp.Status
		}
		return fmt.Errorf("enroll: %s answered %d %s", endpoint, resp.StatusCode, strings.TrimSuffix(msg, ":"))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	return nil
}

// newKey makes a device key and a PEM certificate request for it.
func newKey() (ed25519.PrivateKey, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "privometry device"}}, priv)
	if err != nil {
		return nil, "", err
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// Client is an HTTP client that authenticates as this device with its
// certificate (mutual TLS), for the edge API at the identity's api_base_url.
func Client(id *Identity, keys keystore.Store, timeout time.Duration) (*http.Client, error) {
	raw, err := keys.Get(DeviceKeyName)
	if err != nil {
		return nil, fmt.Errorf("enroll: device key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("enroll: device key: %w", err)
	}
	var chain [][]byte
	rest := []byte(id.Certificate)
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("enroll: no device certificate; enroll this device")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}}, nil
}

// MutualTLS is Client with the server roots of base, which tests set to trust
// their own server; production uses the system roots either way.
func MutualTLS(base *http.Client, id *Identity, keys keystore.Store, timeout time.Duration) (*http.Client, error) {
	client, err := Client(id, keys, timeout)
	if err != nil {
		return nil, err
	}
	if t, ok := base.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		client.Transport.(*http.Transport).TLSClientConfig.RootCAs = t.TLSClientConfig.RootCAs
	}
	return client, nil
}

// RenewBefore is how long before expiry a device renews its certificate.
const RenewBefore = 10 * 24 * time.Hour

// Renew asks the edge API, as this device, for a certificate for a new key,
// and keeps both. base is the client to clone (tests pass one that trusts
// their server); its TLS client certificate is replaced by the device's.
func Renew(ctx context.Context, base *http.Client, env platform.Env, keys keystore.Store) (*Identity, error) {
	id, err := Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, errors.New("enroll: this device is not enrolled")
	}
	client, err := MutualTLS(base, id, keys, 30*time.Second)
	if err != nil {
		return nil, err
	}
	priv, csr, err := newKey()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(cloud.RenewRequest{CSR: csr})
	if err != nil {
		return nil, err
	}
	var resp cloud.RenewResponse
	if err := post(ctx, client, strings.TrimSuffix(id.APIBaseURL, "/")+"/certs:renew", "", body, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	cert, err := leaf(resp.Certificate)
	if err != nil {
		return nil, err
	}
	if certPub, ok := cert.PublicKey.(ed25519.PublicKey); !ok || !certPub.Equal(priv.Public()) {
		return nil, errors.New("enroll: the renewed certificate is not for the new key")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := keys.Put(DeviceKeyName, pkcs8); err != nil {
		return nil, err
	}
	id.Certificate, id.CertificateExpiresAt = resp.Certificate, resp.CertificateExpiresAt.Time
	return id, save(env, id)
}

func leaf(chain string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(chain))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("enroll: no certificate in the response")
	}
	return x509.ParseCertificate(block.Bytes)
}

func identityPath(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "device.json"), nil
}

func save(env platform.Env, id *Identity) error {
	path, err := identityPath(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Device describes this machine for enrollment.
func Device(env platform.Env) cloud.EnrollRequestDevice {
	version := strings.TrimPrefix(buildinfo.Version, "v")
	if !semver.MatchString(version) {
		version = "0.0.0-dev" // a development build
	}
	arch := contract.ArchOther
	switch runtime.GOARCH {
	case "amd64":
		arch = contract.ArchAmd64
	case "arm64":
		arch = contract.ArchArm64
	}
	return cloud.EnrollRequestDevice{OS: contract.OS(env.OS()), OSVersion: osVersion(env), Arch: arch, SensorVersion: version}
}

func osVersion(env platform.Env) string {
	switch env.GOOS {
	case "darwin":
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	case "linux":
		if raw, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if v, ok := strings.CutPrefix(line, "VERSION_ID="); ok {
					return strings.Trim(v, `"`)
				}
			}
		}
	}
	return "unknown"
}

// HashKey reads the organization's hash key kept at enrollment, and its ID.
func HashKey(keys keystore.Store) ([]byte, string, error) {
	raw, err := keys.Get(HashKeyName)
	if err != nil {
		return nil, "", fmt.Errorf("enroll: organization hash key: %w", err)
	}
	var hk cloud.EnrollResponseHashKey
	if err := json.Unmarshal(raw, &hk); err != nil {
		return nil, "", fmt.Errorf("enroll: organization hash key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(hk.Key)
	if err != nil || len(key) != 32 {
		return nil, "", errors.New("enroll: organization hash key is not 32 bytes")
	}
	return key, hk.ID, nil
}
