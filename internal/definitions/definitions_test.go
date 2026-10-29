package definitions_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/detectorpacks"
	"github.com/privometry/privometry-edge/internal/definitions"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/internal/trust"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// next is the lowest adapter set version newer than the built-in one.
const next = adapterdefs.SetVersion + 1

type signer struct {
	id   string
	priv ed25519.PrivateKey
}

func newSigner(role, name string) signer {
	seed := sha256.Sum256([]byte("definitions-test:" + role + ":" + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return signer{signing.KeyID(role, name, priv.Public().(ed25519.PublicKey)), priv}
}

var (
	release = newSigner("release", "test")
	policy  = newSigner("policy", "test")
	keys    = &signing.KeySet{Version: 1, Keys: []signing.Key{
		{KeyID: release.id, Role: "release", Public: release.priv.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour)},
		{KeyID: policy.id, Role: "policy", Public: policy.priv.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour)},
	}}
)

func (s signer) sign(t *testing.T, payloadType string, payload []byte) []byte {
	t.Helper()
	b, err := json.Marshal(signing.Sign(payloadType, payload, s.id, s.priv))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func opts(t *testing.T) definitions.Options {
	return definitions.Options{Dir: t.TempDir(), Keys: keys, SensorVersion: "0.9.0", Now: func() time.Time { return now }}
}

// adapterSet builds a signed adapter set from the built-in definitions,
// with edit applied to the decoded payload.
func adapterSet(t *testing.T, s signer, version int64, edit func(map[string]any)) []byte {
	t.Helper()
	payload, err := definitions.BuildAdapterSet(version, now.Add(-time.Hour), "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return s.sign(t, definitions.AdaptersPayloadType, edited(t, payload, edit))
}

func detectorSet(t *testing.T, s signer, version int64, edit func(map[string]any)) []byte {
	t.Helper()
	payload, err := definitions.BuildDetectorSet(version, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return s.sign(t, definitions.DetectorsPayloadType, edited(t, payload, edit))
}

func edited(t *testing.T, payload []byte, edit func(map[string]any)) []byte {
	t.Helper()
	if edit == nil {
		return payload
	}
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func install(t *testing.T, o definitions.Options, k definitions.Kind, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Dir, k.File()), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func renameClaude(v map[string]any) {
	for _, a := range v["adapters"].([]any) {
		if m := a.(map[string]any); m["agent"] == "claude_code" {
			m["display_name"] = "Claude Code (signed)"
		}
	}
}

func TestBuiltInWhenNothingInstalled(t *testing.T) {
	for _, o := range []definitions.Options{{}, opts(t)} {
		for _, st := range definitions.Statuses(o) {
			if st.Source != "built-in" || st.Problem != "" || st.SetVersion != st.Kind.BuiltIn() {
				t.Errorf("%+v", st)
			}
		}
	}
}

func TestSignedAdapterSet(t *testing.T) {
	o := opts(t)
	install(t, o, definitions.Adapters, adapterSet(t, release, next, renameClaude))
	reg, st, err := definitions.LoadAdapters(o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "signed" || st.SetVersion != next || st.Problem != "" || st.PublishedAt == "" {
		t.Fatalf("status %+v", st)
	}
	a, ok := reg.Get("claude_code")
	if !ok || a.DisplayName != "Claude Code (signed)" {
		t.Errorf("signed definition not used: %q", a.DisplayName)
	}
}

func TestRejectedAdapterSets(t *testing.T) {
	cases := []struct {
		name    string
		raw     func(t *testing.T) []byte
		sensor  string
		noKeys  bool
		problem string
	}{
		{"not newer than built-in", func(t *testing.T) []byte { return adapterSet(t, release, adapterdefs.SetVersion, renameClaude) }, "", false, "not newer than the built-in set"},
		{"signed with the policy key", func(t *testing.T) []byte { return adapterSet(t, policy, next, renameClaude) }, "", false, "no valid signature"},
		{"no release keys in this build", func(t *testing.T) []byte { return adapterSet(t, release, next, renameClaude) }, "", true, "no release signing keys"},
		{"needs a newer sensor", func(t *testing.T) []byte {
			return adapterSet(t, release, next, func(v map[string]any) { v["min_sensor_version"] = "1.4.0" })
		}, "", false, "needs Privometry 1.4.0"},
		{"invalid adapter inside", func(t *testing.T) []byte {
			return adapterSet(t, release, next, func(v map[string]any) { v["adapters"].([]any)[0].(map[string]any)["agent"] = "notepad" })
		}, "", false, "agent"},
		{"tampered payload", func(t *testing.T) []byte {
			raw := adapterSet(t, release, next, nil)
			var env signing.Envelope
			json.Unmarshal(raw, &env)
			env.Payload = strings.Replace(env.Payload, "A", "B", 1)
			b, _ := json.Marshal(env)
			return b
		}, "", false, "signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := opts(t)
			if c.noKeys {
				o.Keys = nil // fall back to the release keys built in, as a build with none
				trust.WithoutReleaseKeys(t)
			}
			raw := c.raw(t)
			install(t, o, definitions.Adapters, raw)
			reg, st, err := definitions.LoadAdapters(o)
			if err != nil {
				t.Fatal(err)
			}
			if st.Source != "built-in" || !strings.Contains(st.Problem, c.problem) {
				t.Errorf("status %+v, want problem containing %q", st, c.problem)
			}
			if a, _ := reg.Get("claude_code"); a.DisplayName != "Claude Code" {
				t.Errorf("built-in definitions not used: %q", a.DisplayName)
			}
			if _, err := definitions.Install(opts(t), raw); err == nil && !c.noKeys {
				t.Error("Install accepted a set that loading rejects")
			}
		})
	}
}

func TestDevelopmentBuildAcceptsAnyMinimum(t *testing.T) {
	o := opts(t)
	o.SensorVersion = "dev"
	install(t, o, definitions.Adapters, adapterSet(t, release, next, func(v map[string]any) { v["min_sensor_version"] = "9.0.0" }))
	if _, st, _ := definitions.LoadAdapters(o); st.Source != "signed" {
		t.Errorf("status %+v", st)
	}
}

func setPack(v map[string]any, id string, edit func(manifest map[string]any, detectors []any)) {
	for _, p := range v["packs"].([]any) {
		p := p.(map[string]any)
		if m := p["manifest"].(map[string]any); m["id"] == id {
			edit(m, p["detectors"].([]any))
		}
	}
}

func TestSignedDetectorSet(t *testing.T) {
	o := opts(t)
	install(t, o, definitions.Detectors, detectorSet(t, release, detectorpacks.SetVersion+1, func(v map[string]any) {
		setPack(v, "privometry/credentials", func(m map[string]any, _ []any) { m["version"] = "9.9.0" })
		setPack(v, "privometry/injection", func(m map[string]any, _ []any) {
			m["version"], m["min_sensor_version"] = "2.0.0", "3.0.0"
		})
	}))
	packs, st, err := definitions.LoadDetectors(o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "signed" || st.SetVersion != detectorpacks.SetVersion+1 || st.Problem != "" {
		t.Fatalf("status %+v", st)
	}
	versions := map[string]string{}
	for _, p := range packs {
		versions[p.Manifest.ID] = p.Manifest.Version
	}
	if versions["privometry/credentials"] != "9.9.0" {
		t.Errorf("signed pack not used: %v", versions)
	}
	if v := versions["privometry/injection"]; v == "2.0.0" || v == "" {
		t.Errorf("pack needing a newer sensor should stay built in: %v", versions)
	}
	if len(st.Kept) != 1 || !strings.Contains(st.Kept[0], "privometry/injection") {
		t.Errorf("kept %v", st.Kept)
	}
}

func TestDetectorSetFailingSamplesIsRejected(t *testing.T) {
	o := opts(t)
	raw := detectorSet(t, release, 2, func(v map[string]any) {
		setPack(v, "privometry/credentials", func(_ map[string]any, docs []any) {
			d := docs[0].(map[string]any)["detectors"].([]any)[0].(map[string]any)
			d["samples"].(map[string]any)["match"] = []any{"nothing secret here"}
		})
	})
	install(t, o, definitions.Detectors, raw)
	packs, st, err := definitions.LoadDetectors(o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "built-in" || !strings.Contains(st.Problem, "fails its own samples") || len(packs) != 3 {
		t.Errorf("status %+v, %d packs", st, len(packs))
	}
	if _, err := definitions.Install(opts(t), raw); err == nil {
		t.Error("Install accepted a pack that fails its samples")
	}
}

func TestInstall(t *testing.T) {
	o := opts(t)
	st, err := definitions.Install(o, adapterSet(t, release, next+1, renameClaude))
	if err != nil || st.SetVersion != next+1 {
		t.Fatalf("install: %+v %v", st, err)
	}
	platformtest.Private(t, filepath.Join(o.Dir, "adapters.json"))
	if _, err := definitions.Install(o, adapterSet(t, release, next+1, nil)); !errors.Is(err, definitions.ErrNotNewer) {
		t.Errorf("reinstall: %v", err)
	}
	if _, err := definitions.Install(o, adapterSet(t, release, next, nil)); !errors.Is(err, definitions.ErrNotNewer) {
		t.Errorf("rollback: %v", err)
	}
	if _, st, _ := definitions.LoadAdapters(o); st.SetVersion != next+1 {
		t.Errorf("a refused install changed the set in use: %+v", st)
	}
	if _, err := definitions.Install(o, detectorSet(t, release, detectorpacks.SetVersion+1, nil)); err != nil {
		t.Errorf("detector set: %v", err)
	}
	if _, err := definitions.Install(o, []byte(`{"payloadType":"application/vnd.privometry.bundle+json"}`)); err == nil {
		t.Error("a policy bundle was installed as definitions")
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapters.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	if b, err := definitions.Fetch(ctx, srv.Client(), srv.URL+"/adapters.json"); err != nil || string(b) != `{"ok":true}` {
		t.Errorf("fetch: %q %v", b, err)
	}
	if _, err := definitions.Fetch(ctx, srv.Client(), srv.URL+"/missing.json"); err == nil {
		t.Error("404 accepted")
	}
	if _, err := definitions.Fetch(ctx, http.DefaultClient, "http://example.com/adapters.json"); err == nil {
		t.Error("plain HTTP accepted")
	}
}

// builtInDigests pins the content of each built-in set version. When
// adapter-defs/ or detectorpacks/ change, bump SetVersion in its embed.go and
// record the new digest here: an installed signed set is used only when it is
// newer than the built-in set, so an unbumped change could be overridden by a
// set built from the old files.
var builtInDigests = map[string]string{
	"adapters 1":      "sha256:aa1b25ac7b76702411b707d9556df0a8485b0525e9a44dca56e8a5ff83c156d0",
	"adapters 2":      "sha256:f9b8b211cea1a0805035045087cfce32a8ec0311553c6eb36b79f2cffa6feaf1", // Codex verified against 0.164.0
	"adapters 3":      "sha256:21c959122a3b90834506f89e7f8bc51497f63c8c0d1d4065432dd2a6fa81c018", // Gemini CLI and Copilot CLI
	"adapters 4":      "sha256:9ab141f9406295f29e4b0185c4dd1e12c9bc0d390597a4805bbfc649012c633d", // Antigravity, bypass flags
	"adapters 5":      "sha256:51f543b4c59231ab28d693af62b509f8da73c31113bc1ba8137201f22dc42d89", // disable settings, process patterns, no-session args
	"detectorpacks 1": "sha256:67d93563fd3d144e907d1876fc7e8c315e9940df94fe109e11e2b1ff63425c85",
	"detectorpacks 2": "sha256:0f489f0e56f3d87283af25a57dc4610f9c317237a3707b3055a20a518732b01c", // SCAN-13 exfiltration detectors
	"detectorpacks 3": "sha256:11231588848668b267435ce73074732c68769cae18e46c22f701a5112517433b", // maintainers URL on GitHub
}

func TestBuiltInSetVersionsArePinned(t *testing.T) {
	for _, c := range []struct {
		kind    definitions.Kind
		fsys    fs.FS
		version int64
	}{{definitions.Adapters, adapterdefs.FS, adapterdefs.SetVersion}, {definitions.Detectors, detectorpacks.FS, detectorpacks.SetVersion}} {
		key := string(c.kind) + " " + strconv.FormatInt(c.version, 10)
		got := digest(t, c.fsys)
		if want, ok := builtInDigests[key]; !ok || want != got {
			t.Errorf("%s: content digest is %s; bump %s SetVersion if it changed, and pin %q: %q", c.kind, got, c.kind, key, got)
		}
	}
}

func digest(t *testing.T, fsys fs.FS) string {
	t.Helper()
	var files []string
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	})
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte(f + "\x00"))
		h.Write(b)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
