package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/signing"
	"github.com/privometry/privometry-oss/internal/trust"
)

// testKey derives a key like scripts/gen-conformance: a TEST KEY with a
// published seed.
func testKey(role, name string) (string, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("privometry-test-key:" + role + ":" + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return signing.KeyID(role, name, priv.Public().(ed25519.PublicKey)), priv
}

var now = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

type fixture struct {
	t        *testing.T
	srv      *httptest.Server
	keys     *signing.KeySet
	manifest []byte // the signed envelope served at /release.json
	archive  []byte // served at /privometry.tar.gz
	release  Release
}

// script is a fake binary: a shell script that prints a version.
func script(v string) []byte {
	return []byte("#!/bin/sh\necho \"privometry " + v + " (commit test, built test)\"\n")
}

func tarGz(t *testing.T, files map[string][]byte, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range extra {
		tw.WriteHeader(h)
	}
	for _, name := range []string{"LICENSE", "privometry", "privometryd", "privometry-hook"} {
		body, ok := files[name]
		if !ok {
			continue
		}
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func newFixture(t *testing.T, version string) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binaries are shell scripts")
	}
	f := &fixture{t: t}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release.json":
			w.Write(f.manifest)
		case "/privometry.tar.gz":
			w.Write(f.archive)
		case "/redirect-to-http":
			http.Redirect(w, r, "http://example.com/privometry.tar.gz", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	id, priv := testKey("release", "test")
	f.keys = &signing.KeySet{Version: 1, Keys: []signing.Key{{KeyID: id, Role: "release", Public: priv.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour)}}}
	f.archive = tarGz(t, map[string][]byte{"LICENSE": []byte("Apache-2.0"), "privometry": script(version), "privometryd": script(version), "privometry-hook": script(version)})
	f.release = Release{Schema: ReleaseSchema, Version: version, Channel: ReleaseChannelStable,
		ReleasedAt: contract.At(now.Add(-time.Hour)), ExpiresAt: contract.At(now.Add(30 * 24 * time.Hour)),
		Artifacts: []Artifact{{OS: map[string]ArtifactOS{"darwin": ArtifactOSMacos, "linux": ArtifactOSLinux}[runtime.GOOS], Arch: ArtifactArch(runtime.GOARCH),
			URL: f.srv.URL + "/privometry.tar.gz", Format: ArtifactFormatTarGz, Binaries: []ArtifactBinary{"privometry", "privometryd", "privometry-hook"}}}}
	f.sign("release", "test")
	return f
}

// sign re-signs the manifest after changes to release or archive.
func (f *fixture) sign(role, name string) {
	sum := sha256.Sum256(f.archive)
	f.release.Artifacts[0].SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	f.release.Artifacts[0].Size = int64(len(f.archive))
	payload, _ := json.Marshal(f.release)
	id, priv := testKey(role, name)
	f.manifest, _ = json.Marshal(signing.Sign(PayloadType, payload, id, priv))
}

func (f *fixture) opts(current string) Options {
	return Options{ManifestURL: f.srv.URL + "/release.json", Keys: f.keys, Client: f.srv.Client(), Current: current,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: func() time.Time { return now }}
}

func installed(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"privometry", "privometryd", "privometry-hook"} {
		os.WriteFile(filepath.Join(dir, n), script(version), 0o755)
	}
	return dir
}

func TestUpdateInstallsVerifiedRelease(t *testing.T) {
	f := newFixture(t, "0.5.0")
	ctx := context.Background()
	rel, art, err := Check(ctx, f.opts("0.4.2"))
	if err != nil {
		t.Fatal(err)
	}
	dir := installed(t, "0.4.2")
	staged, err := Stage(ctx, f.opts("0.4.2"), art, dir, rel.Version)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.Files) != 3 {
		t.Errorf("staged %v; LICENSE must not be extracted", staged.Files)
	}
	if err := staged.Install(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Errorf("leftover files after install: %v", entries)
	}
	for _, n := range []string{"privometry", "privometryd", "privometry-hook"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		info, _ := os.Stat(filepath.Join(dir, n))
		if !bytes.Contains(b, []byte("0.5.0")) || info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s not replaced with an executable 0.5.0", n)
		}
	}
}

func TestUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		current string
		edit    func(f *fixture, o *Options)
		want    error
		msg     string
	}{
		{"same version", "0.5.0", nil, ErrUpToDate, ""},
		{"downgrade", "0.6.0", nil, ErrDowngrade, ""},
		{"release older than a prerelease", "0.5.1-beta.1", nil, ErrDowngrade, ""},
		{"dev build", "dev", nil, ErrDevBuild, ""},
		{"expired manifest", "0.4.2", func(_ *fixture, o *Options) {
			o.Now = func() time.Time { return now.Add(31 * 24 * time.Hour) }
		}, ErrExpired, ""},
		{"signed by a policy key", "0.4.2", func(f *fixture, _ *Options) { f.sign("policy", "test-in") }, signing.ErrNoValidSignature, ""},
		{"signed by an unknown release key", "0.4.2", func(f *fixture, _ *Options) { f.sign("release", "attacker") }, signing.ErrNoValidSignature, ""},
		{"payload changed after signing", "0.4.2", func(f *fixture, _ *Options) {
			f.manifest = bytes.Replace(f.manifest, []byte(`"payload":"`), []byte(`"payload":"A`), 1)
		}, nil, "manifest signature"},
		{"invalid manifest", "0.4.2", func(f *fixture, _ *Options) {
			f.release.Artifacts[0].Binaries = append(f.release.Artifacts[0].Binaries, "install.sh")
			f.sign("release", "test")
		}, nil, "binaries/3"},
		{"no download for this platform", "0.4.2", func(_ *fixture, o *Options) { o.GOARCH = "riscv64" }, ErrNoArtifact, ""},
		{"manifest over plain HTTP", "0.4.2", func(_ *fixture, o *Options) { o.ManifestURL = "http://example.com/release.json" }, nil, "not an HTTPS URL"},
		{"no release keys built in", "0.4.2", func(_ *fixture, o *Options) { o.Keys = nil; trust.WithoutReleaseKeys(t) }, ErrNoReleaseKeys, ""},
	}
	for _, c := range cases {
		f := newFixture(t, "0.5.0")
		o := f.opts(c.current)
		if c.edit != nil {
			c.edit(f, &o)
		}
		_, _, err := Check(ctx, o)
		switch {
		case err == nil:
			t.Errorf("%s: accepted", c.name)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		case c.msg != "" && !strings.Contains(err.Error(), c.msg):
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.msg)
		}
	}
}

func TestStageRejectsBadDownloads(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		edit func(f *fixture, art *Artifact)
		msg  string
	}{
		{"digest mismatch", func(_ *fixture, art *Artifact) { art.SHA256 = "sha256:" + strings.Repeat("0", 64) }, "digest"},
		{"bigger than declared", func(_ *fixture, art *Artifact) { art.Size-- }, "larger than"},
		{"smaller than declared", func(_ *fixture, art *Artifact) { art.Size++ }, "bytes, the manifest says"},
		{"redirect to plain HTTP", func(f *fixture, art *Artifact) { art.URL = f.srv.URL + "/redirect-to-http" }, "redirect off HTTPS"},
		{"binary missing", func(f *fixture, art *Artifact) {
			f.archive = tarGz(f.t, map[string][]byte{"privometry": script("0.5.0"), "privometryd": script("0.5.0")})
			f.sign("release", "test")
			*art = f.release.Artifacts[0]
		}, "no privometry-hook"},
		{"path traversal only", func(f *fixture, art *Artifact) {
			f.archive = tarGz(f.t, map[string][]byte{"privometry": script("0.5.0"), "privometryd": script("0.5.0")},
				&tar.Header{Name: "../privometry-hook", Mode: 0o755, Size: 0, Typeflag: tar.TypeReg},
				&tar.Header{Name: "bin/privometry-hook", Mode: 0o755, Size: 0, Typeflag: tar.TypeReg},
				&tar.Header{Name: "privometry-hook", Linkname: "/bin/sh", Typeflag: tar.TypeSymlink})
			f.sign("release", "test")
			*art = f.release.Artifacts[0]
		}, "no privometry-hook"},
		{"binary reports another version", func(f *fixture, art *Artifact) {
			f.archive = tarGz(f.t, map[string][]byte{"privometry": script("0.4.9"), "privometryd": script("0.5.0"), "privometry-hook": script("0.5.0")})
			f.sign("release", "test")
			*art = f.release.Artifacts[0]
		}, "reports"},
	}
	for _, c := range cases {
		f := newFixture(t, "0.5.0")
		art := f.release.Artifacts[0]
		c.edit(f, &art)
		dir := installed(t, "0.4.2")
		_, err := Stage(ctx, f.opts("0.4.2"), &art, dir, "0.5.0")
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v, want %q", c.name, err, c.msg)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 3 {
			t.Errorf("%s: staged files left behind: %v", c.name, entries)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "privometry")); !bytes.Contains(b, []byte("0.4.2")) {
			t.Errorf("%s: installed privometry changed", c.name)
		}
	}
}

func TestInstallRollsBack(t *testing.T) {
	f := newFixture(t, "0.5.0")
	dir := installed(t, "0.4.2")
	staged, err := Stage(context.Background(), f.opts("0.4.2"), &f.release.Artifacts[0], dir, "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	// privometryd sorts between privometry and privometry-hook: make its swap fail after
	// privometry is already replaced.
	os.Remove(staged.Files["privometryd"])
	if err := staged.Install(); err == nil {
		t.Fatal("install with a missing staged file succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Errorf("files after rollback: %v", entries)
	}
	for _, n := range []string{"privometry", "privometryd", "privometry-hook"} {
		if b, _ := os.ReadFile(filepath.Join(dir, n)); !bytes.Contains(b, []byte("0.4.2")) {
			t.Errorf("%s not restored", n)
		}
	}
}

func TestVersionOrder(t *testing.T) {
	order := []string{"0.4.2", "0.5.0-alpha", "0.5.0-alpha.1", "0.5.0-alpha.beta", "0.5.0-beta", "0.5.0-beta.2", "0.5.0-beta.11", "0.5.0-rc.1", "0.5.0", "0.5.1", "1.0.0"}
	for i := 1; i < len(order); i++ {
		a, _ := parseVersion(order[i-1])
		b, err := parseVersion(order[i])
		if err != nil || a.compare(b) >= 0 || b.compare(a) <= 0 {
			t.Errorf("%s must sort before %s (%v)", order[i-1], order[i], err)
		}
	}
	if a, _ := parseVersion("1.2.3+build.5"); a.compare(version{core: [3]int{1, 2, 3}}) != 0 {
		t.Error("build metadata must not affect order")
	}
	for _, bad := range []string{"dev", "1.2", "01.2.3", "1.2.x", ""} {
		if _, err := parseVersion(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestConformanceReleaseVector(t *testing.T) {
	raw, err := os.ReadFile("../../specs/conformance/signatures/envelopes/release-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	ks, err := os.ReadFile("../../specs/conformance/signatures/keyset-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signing.ParseKeySet(ks)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, "0.5.0")
	f.manifest = raw
	o := f.opts("0.4.2")
	o.Keys = keys
	o.Now = func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC) }
	o.GOOS, o.GOARCH = "darwin", "arm64"
	rel, art, err := Check(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "0.5.0" || art.OS != ArtifactOSMacos || art.Arch != ArtifactArchArm64 {
		t.Errorf("picked %s %s/%s", rel.Version, art.OS, art.Arch)
	}
}

// A Windows release is a zip of .exe files; they are installed under their
// .exe names, and binaries an earlier update could not delete (Windows keeps
// a running binary) are cleaned up by the next one.
func TestStageWindowsZip(t *testing.T) {
	f := newFixture(t, "0.5.0")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"privometry.exe", "privometryd.exe", "privometry-hook.exe", "README.md"} {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate}
		h.SetMode(0o755)
		w, _ := zw.CreateHeader(h)
		w.Write(script("0.5.0"))
	}
	zw.Close()
	f.archive = buf.Bytes()
	f.release.Artifacts[0].Format = ArtifactFormatZip
	f.sign("release", "test")

	dir := t.TempDir()
	for _, n := range []string{"privometry.exe", "privometryd.exe", "privometry-hook.exe"} {
		os.WriteFile(filepath.Join(dir, n), script("0.4.2"), 0o755)
	}
	leftover := filepath.Join(dir, "privometryd.exe.privometry-old-abc")
	os.WriteFile(leftover, script("0.4.1"), 0o755)

	opts := f.opts("0.4.2")
	opts.GOOS = "windows"
	staged, err := Stage(context.Background(), opts, &f.release.Artifacts[0], dir, "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Error("the leftover from an earlier update was not removed")
	}
	if err := staged.Install(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"privometry.exe", "privometryd.exe", "privometry-hook.exe"} {
		if got, _ := os.ReadFile(filepath.Join(dir, n)); !bytes.Equal(got, script("0.5.0")) {
			t.Errorf("%s not replaced", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "privometry")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a binary without .exe was written on Windows")
	}
}
