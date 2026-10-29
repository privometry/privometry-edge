package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/account"
	cloudaccount "github.com/privometry/privometry-edge/internal/cloud/account"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

// fakeCloud plays the account API and the edge API's enrollment. It checks
// every request body against account-api/v1 or edge-api/v1, checks its own
// responses too, and verifies each proof the way the platform does: the
// signature over PAE, the keyid, and every bound field.
type fakeCloud struct {
	t   *testing.T
	srv *httptest.Server
	ca  ed25519.PrivateKey

	mu            sync.Mutex
	code          string
	audience      string // what challenges say; normally the API's own URL
	registrations map[string]*fakeRegistration
	keys          map[string]ed25519.PublicKey // by credential ID
	challenges    map[string][]byte            // sign-in challenges by ID
	tokens        map[string]bool              // enrollment tokens not yet used
	enrollDown    bool
	links         []string
	requests      []string
}

type fakeRegistration struct {
	start     cloudaccount.RegistrationStart
	challenge string
	done      bool
}

func newFakeCloud(t *testing.T) *fakeCloud {
	_, ca, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeCloud{t: t, ca: ca, code: "482913", registrations: map[string]*fakeRegistration{}, keys: map[string]ed25519.PublicKey{},
		challenges: map[string][]byte{}, tokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /account/v1/registrations", f.start)
	mux.HandleFunc("POST /account/v1/registrations/{action}", f.registration)
	mux.HandleFunc("POST /account/v1/sign-in/challenges", f.signInChallenge)
	mux.HandleFunc("POST /account/v1/sign-in", f.signIn)
	mux.HandleFunc("POST /edge/v1/enroll", f.enroll)
	f.srv = httptest.NewTLSServer(mux)
	f.audience = f.api()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCloud) api() string { return f.srv.URL + "/account/v1" }

func (f *fakeCloud) read(w http.ResponseWriter, r *http.Request, message, schema string, v any) bool {
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if err := specs.Validate(schema+"#/$defs/"+message, "request.json", raw); err != nil {
		f.t.Errorf("%s %s: request is not a %s: %v", r.Method, r.URL.Path, message, err)
		problem(w, 400, "invalid-request", err.Error())
		return false
	}
	if err := json.Unmarshal(raw, v); err != nil {
		f.t.Errorf("decode %s: %v", message, err)
		return false
	}
	return true
}

func (f *fakeCloud) reply(w http.ResponseWriter, status int, message, schema string, v any) {
	raw, _ := json.Marshal(v)
	if err := specs.Validate(schema+"#/$defs/"+message, "response.json", raw); err != nil {
		f.t.Errorf("the fake's own %s is invalid: %v", message, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(raw)
}

const accountSchema = "account-api/v1/messages.schema.json"
const edgeSchema = "edge-api/v1/messages.schema.json"

func problem(w http.ResponseWriter, status int, kind, detail string, extra ...string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"type":"https://privometry.dev/problems/%s","title":%q,"status":%d,"detail":%q%s}`, kind, kind, status, detail, strings.Join(extra, ""))
}

func (f *fakeCloud) start(w http.ResponseWriter, r *http.Request) {
	var req cloudaccount.RegistrationStart
	if !f.read(w, r, "RegistrationStart", accountSchema, &req) {
		return
	}
	id := contract.NewID("reg")
	f.mu.Lock()
	f.registrations[id] = &fakeRegistration{start: req}
	f.mu.Unlock()
	now := time.Now()
	f.reply(w, 202, "Registration", accountSchema, cloudaccount.Registration{RegistrationID: id, Purpose: req.Purpose,
		Status: cloudaccount.RegistrationStatusAwaitingCode, ExpiresAt: contract.At(now.Add(30 * time.Minute))})
}

func (f *fakeCloud) registration(w http.ResponseWriter, r *http.Request) {
	id, action, _ := strings.Cut(r.PathValue("action"), ":")
	f.mu.Lock()
	reg := f.registrations[id]
	f.mu.Unlock()
	if reg == nil {
		problem(w, 404, "registration-expired", "no such registration")
		return
	}
	switch action {
	case "resend":
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.code = "771135"
		f.mu.Unlock()
		f.reply(w, 202, "Registration", accountSchema, cloudaccount.Registration{RegistrationID: id, Purpose: reg.start.Purpose,
			Status: cloudaccount.RegistrationStatusAwaitingCode, ExpiresAt: contract.At(time.Now().Add(30 * time.Minute))})
	case "verify":
		var req cloudaccount.RegistrationVerify
		if !f.read(w, r, "RegistrationVerify", accountSchema, &req) {
			return
		}
		if req.Code != f.code {
			problem(w, 403, "invalid-code", "That code is not right.", `,"code_attempts_left":4`)
			return
		}
		reg.challenge = base64.RawURLEncoding.EncodeToString(randomBytes(32))
		org := cloudaccount.OrganizationRef{Name: "Acme Payments", Slug: "acme", Region: "in"}
		if reg.start.Organization != nil {
			org.Name, org.Slug = reg.start.Organization.Name, reg.start.Organization.Slug
		}
		f.reply(w, 200, "RegistrationChallenge", accountSchema, cloudaccount.RegistrationChallenge{RegistrationID: id, Challenge: reg.challenge,
			Audience: f.audience, ExpiresAt: contract.At(time.Now().Add(5 * time.Minute)), Organization: org, Role: cloudaccount.RoleOwner})
	case "complete":
		var req cloudaccount.RegistrationComplete
		if !f.read(w, r, "RegistrationComplete", accountSchema, &req) {
			return
		}
		c := req.Credential
		spki, _ := base64.StdEncoding.DecodeString(c.PublicKey)
		parsed, err := x509.ParsePKIXPublicKey(spki)
		pub, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || c.Algorithm != "Ed25519" || c.Protection != "software" {
			problem(w, 403, "proof-rejected", "bad key")
			return
		}
		thumb := account.Thumbprint(spki)
		p := f.verifyProof(c.Proof, pub, thumb)
		if p == nil || p.Purpose != "register" || p.Challenge != reg.challenge || p.RegistrationID != id || p.PublicKeySHA256 != thumb ||
			p.Audience != f.api() || reg.done {
			problem(w, 403, "proof-rejected", "the proof does not verify")
			return
		}
		reg.done = true
		credential, token := contract.NewID("crd"), "pet_"+base64.RawURLEncoding.EncodeToString(randomBytes(32))
		f.mu.Lock()
		f.keys[credential] = pub
		f.tokens[token] = true
		f.mu.Unlock()
		f.reply(w, 201, "RegistrationResult", accountSchema, cloudaccount.RegistrationResult{UserID: contract.NewID("usr"), OrgID: contract.NewID("org"),
			Role: cloudaccount.RoleOwner, CredentialID: credential, Region: "in", Enrollment: &cloudaccount.RegistrationResultEnrollment{
				EnrollmentToken: token, EdgeBaseURL: f.srv.URL + "/edge/v1", ExpiresAt: contract.At(time.Now().Add(10 * time.Minute))}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCloud) verifyProof(proof *cloudaccount.Proof, pub ed25519.PublicKey, keyID string) *cloudaccount.AccountProof {
	if proof == nil || proof.PayloadType != account.ProofPayloadType || len(proof.Signatures) != 1 || proof.Signatures[0].KeyID != keyID {
		return nil
	}
	payload, _ := base64.StdEncoding.DecodeString(proof.Payload)
	sig, _ := base64.StdEncoding.DecodeString(proof.Signatures[0].Sig)
	if !ed25519.Verify(pub, signing.PAE(proof.PayloadType, payload), sig) {
		return nil
	}
	if err := specs.Validate(accountSchema+"#/$defs/AccountProof", "payload.json", payload); err != nil {
		f.t.Errorf("proof payload: %v", err)
		return nil
	}
	var p cloudaccount.AccountProof
	json.Unmarshal(payload, &p)
	if time.Since(p.IssuedAt.Time).Abs() > time.Minute {
		return nil
	}
	return &p
}

func (f *fakeCloud) signInChallenge(w http.ResponseWriter, r *http.Request) {
	var req cloudaccount.SignInChallengeRequest
	if !f.read(w, r, "SignInChallengeRequest", accountSchema, &req) {
		return
	}
	id, challenge := contract.NewID("chl"), randomBytes(32)
	f.mu.Lock()
	f.challenges[id] = challenge
	f.mu.Unlock()
	f.reply(w, 201, "SignInChallenge", accountSchema, cloudaccount.SignInChallenge{ChallengeID: id,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge), Audience: f.audience, ExpiresAt: contract.At(time.Now().Add(5 * time.Minute))})
}

func (f *fakeCloud) signIn(w http.ResponseWriter, r *http.Request) {
	var req cloudaccount.SignInRequest
	if !f.read(w, r, "SignInRequest", accountSchema, &req) {
		return
	}
	f.mu.Lock()
	challenge, pub := f.challenges[req.ChallengeID], f.keys[req.CredentialID]
	delete(f.challenges, req.ChallengeID) // works once
	f.mu.Unlock()
	p := f.verifyProof(req.Proof, pub, req.CredentialID)
	if challenge == nil || pub == nil || p == nil || p.Purpose != "sign_in" || p.ChallengeID != req.ChallengeID || p.CredentialID != req.CredentialID ||
		p.Challenge != base64.RawURLEncoding.EncodeToString(challenge) || p.Audience != f.api() {
		problem(w, 401, "proof-rejected", "Request a new challenge and sign it again.")
		return
	}
	link := "https://console.privometry.dev/sign-in/link#t=plt_" + base64.RawURLEncoding.EncodeToString(randomBytes(32))
	f.mu.Lock()
	f.links = append(f.links, link)
	f.mu.Unlock()
	f.reply(w, 200, "SignInResult", accountSchema, cloudaccount.SignInResult{UserID: contract.NewID("usr"), OrgID: contract.NewID("org"),
		Role: cloudaccount.RoleOwner, SignInLink: &cloudaccount.SignInResultSignInLink{URL: link, ExpiresAt: contract.At(time.Now().Add(time.Minute))}})
}

func (f *fakeCloud) enroll(w http.ResponseWriter, r *http.Request) {
	if f.enrollDown {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(503)
		w.Write([]byte(`{"type":"https://privometry.dev/problems/server-error","title":"Unavailable","status":503}`))
		return
	}
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		CSR             string `json:"csr"`
	}
	if !f.read(w, r, "EnrollRequest", edgeSchema, &req) {
		return
	}
	f.mu.Lock()
	fresh := f.tokens[req.EnrollmentToken]
	delete(f.tokens, req.EnrollmentToken)
	f.mu.Unlock()
	if !fresh || r.Header.Get("Authorization") != "Bearer "+req.EnrollmentToken || len(r.Header.Get("Idempotency-Key")) < 16 {
		problem(w, 401, "unauthorized", "bad enrollment token")
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		problem(w, 400, "invalid-request", "bad CSR")
		return
	}
	expires := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "device"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, f.ca)
	if err != nil {
		f.t.Fatal(err)
	}
	f.reply(w, 201, "EnrollResponse", edgeSchema, map[string]any{"device_id": contract.NewID("dev"), "org_id": contract.NewID("org"),
		"user_id": contract.NewID("usr"), "region": "in", "api_base_url": f.srv.URL + "/edge/v1",
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "certificate_expires_at": contract.At(expires),
		"hash_key": map[string]string{"id": contract.NewID("hk"), "key": base64.StdEncoding.EncodeToString(randomBytes(32))}})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// scripted answers prompts in order and fails the test when it runs out.
type scripted struct {
	t       *testing.T
	lines   []string
	secrets []string
}

func (s *scripted) Line(prompt string) (string, error) {
	if len(s.lines) == 0 {
		s.t.Fatalf("unexpected prompt %q", prompt)
	}
	v := s.lines[0]
	s.lines = s.lines[1:]
	return v, nil
}

func (s *scripted) Secret(prompt string) (string, error) {
	if len(s.secrets) == 0 {
		s.t.Fatalf("unexpected secret prompt %q", prompt)
	}
	v := s.secrets[0]
	s.secrets = s.secrets[1:]
	return v, nil
}

// useCloud points the account commands at the fake, a private data
// directory and file keys, and returns that directory.
func useCloud(t *testing.T, f *fakeCloud, answers *scripted) (string, *[]string) {
	data := t.TempDir()
	env := platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
	opened := &[]string{}
	accountEnv = func() (platform.Env, error) { return env, nil }
	accountHTTP = func() *http.Client { return f.srv.Client() }
	prompter = answers
	openConsole = func(link string) error { *opened = append(*opened, link); return nil }
	t.Cleanup(func() {
		accountEnv, prompter, openConsole = platform.CurrentEnv, ttyPrompter{}, openBrowser
		accountHTTP = func() *http.Client { return &http.Client{Timeout: 30 * time.Second} }
	})
	return data, opened
}

func runCmd(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestLoginThenConsole(t *testing.T) {
	f := newFakeCloud(t)
	answers := &scripted{t: t,
		lines:   []string{"000000", "", "771135", "Meera Nair"}, // a wrong code, a resend, the new code, then the name
		secrets: []string{"12345", "correct horse", "correct horsf", "correct horse", "correct horse"}}
	data, opened := useCloud(t, f, answers)

	code, out, errOut := runCmd("login", "--api", f.api(), "--email", "meera@acme.example", "--create-org", "Acme Payments", "--slug", "acme",
		"--label", "build box")
	if code != 0 {
		t.Fatalf("login: %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"That code is not right (4 attempts left).", "A new code is on its way.", "Email confirmed: Acme Payments (acme), role owner.",
		"A PIN needs at least 6 characters.", "The PINs differ.", "Signed up as meera@acme.example in Acme Payments", "a file only you can read",
		"Enrolled this device (dev_"} {
		if !strings.Contains(out, want) {
			t.Errorf("login output lacks %q:\n%s", want, out)
		}
	}
	if len(answers.lines)+len(answers.secrets) != 0 {
		t.Errorf("unused answers: %v %v", answers.lines, answers.secrets)
	}

	state, err := account.LoadState(env(data))
	if err != nil || state.OrgSlug != "acme" || !strings.HasPrefix(state.CredentialID, "crd_") || state.Keystore != keystore.KindFile ||
		state.APIBaseURL != f.api() {
		t.Fatalf("state %+v, %v", state, err)
	}
	for _, name := range []string{"cli-key", "device-key", "org-hash-key"} {
		if fi, err := os.Stat(filepath.Join(data, "keys", name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("keys/%s: %v %v", name, fi, err)
		}
	}
	sealed, _ := os.ReadFile(filepath.Join(data, "keys", "cli-key"))
	if _, err := account.Open(sealed, "correct horse"); err != nil {
		t.Errorf("the stored key does not open with the PIN: %v", err)
	}
	device, _ := os.ReadFile(filepath.Join(data, "device.json"))
	if !bytes.Contains(device, []byte(`"device_id": "dev_`)) || !bytes.Contains(device, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("device.json:\n%s", device)
	}

	// A wrong PIN, then the right one; the browser opens the link the API returned.
	answers.secrets = []string{"wrong pin", "correct horse"}
	code, out, errOut = runCmd("console")
	if code != 0 {
		t.Fatalf("console: %d\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "Wrong PIN.") || len(*opened) != 1 || (*opened)[0] != f.links[0] {
		t.Errorf("console opened %v (links %v):\n%s", *opened, f.links, out)
	}
	answers.secrets = []string{"correct horse"}
	if code, out, _ = runCmd("console", "--print"); code != 0 || strings.TrimSpace(out) != f.links[1] {
		t.Errorf("console --print: %d %q", code, out)
	}
	answers.secrets = []string{"no", "nope!!", "still no"}
	if code, _, errOut = runCmd("console"); code != 2 || !strings.Contains(errOut, "wrong PIN") {
		t.Errorf("three wrong PINs: %d %s", code, errOut)
	}

	// Signing up again needs --replace.
	if code, _, errOut = runCmd("login", "--api", f.api(), "--email", "meera@acme.example", "--org", "acme"); code != 2 ||
		!strings.Contains(errOut, "--replace") {
		t.Errorf("second login: %d %s", code, errOut)
	}
}

func TestLoginWithAnInvitationWhenEnrollmentFails(t *testing.T) {
	f := newFakeCloud(t)
	f.enrollDown = true
	answers := &scripted{t: t, lines: []string{"482913", "Ravi Iyer"}, secrets: []string{"tulip-river-9", "tulip-river-9"}}
	data, _ := useCloud(t, f, answers)
	link := "https://console.privometry.dev/join#t=pit_" + strings.Repeat("a", 43)
	code, out, errOut := runCmd("login", "--api", f.api(), "--email", "ravi@acme.example", "--invite", link)
	if code != 1 || !strings.Contains(errOut, "This device is not enrolled") || !strings.Contains(out, "Signed up as ravi@acme.example") {
		t.Fatalf("login: %d\n%s%s", code, out, errOut)
	}
	if f.registrations[firstKey(f.registrations)].start.InvitationToken != "pit_"+strings.Repeat("a", 43) {
		t.Error("the token is taken from the invitation link")
	}
	if _, err := account.LoadState(env(data)); err != nil {
		t.Errorf("the account is kept when enrollment fails: %v", err)
	}
}

func TestLoginChecksWhereItTalks(t *testing.T) {
	f := newFakeCloud(t)
	f.audience = "https://eu.api.privometry.dev/account/v1" // answers as another region
	answers := &scripted{t: t, lines: []string{"482913"}}
	useCloud(t, f, answers)
	code, _, errOut := runCmd("login", "--api", f.api(), "--email", "meera@acme.example", "--org", "acme")
	if code != 2 || !strings.Contains(errOut, "answered for https://eu.api.privometry.dev") {
		t.Fatalf("login: %d %s", code, errOut)
	}
	for _, args := range [][]string{
		{"login"},
		{"login", "--email", "a@b.example"},
		{"login", "--email", "a@b.example", "--org", "acme", "--invite", "pit_x"},
		{"login", "--email", "a@b.example", "--create-org", "Acme"},
		{"console", "extra"},
	} {
		if code, _, _ := runCmd(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, errOut := runCmd("console"); code != 2 || !strings.Contains(errOut, "privometry login") {
		t.Errorf("console before login: %d %s", code, errOut)
	}
}

func env(data string) platform.Env {
	return platform.Env{GOOS: "linux", Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}
}

func firstKey[V any](m map[string]V) string {
	for k := range m {
		return k
	}
	return ""
}

func TestEnrollWithAnAdminToken(t *testing.T) {
	f := newFakeCloud(t)
	token := "pet_" + strings.Repeat("m", 43)
	f.tokens[token] = true
	useCloud(t, f, &scripted{t: t})
	if code, out, _ := runCmd("device", "status"); code != 1 || !strings.Contains(out, "not enrolled") {
		t.Fatalf("status before enrolling: %d %s", code, out)
	}
	code, out, errOut := runCmd("enroll", "--edge", f.srv.URL+"/edge/v1", "--token", token)
	if code != 0 || !strings.Contains(out, "Enrolled this device (dev_") {
		t.Fatalf("enroll: %d\n%s%s", code, out, errOut)
	}
	if code, out, _ = runCmd("device", "status"); code != 0 || !strings.Contains(out, "Device:      dev_") {
		t.Errorf("status: %d\n%s", code, out)
	}
	if code, _, errOut = runCmd("enroll", "--edge", f.srv.URL+"/edge/v1", "--token", token); code != 2 || !strings.Contains(errOut, "401") {
		t.Errorf("a used token: %d %s", code, errOut)
	}
	for _, args := range [][]string{{"enroll"}, {"device"}, {"device", "explode"}} {
		if code, _, _ := runCmd(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}
