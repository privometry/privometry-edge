// Package update installs signed Privometry releases in place.
//
// A release is a privometry.release/v1 manifest in a DSSE envelope signed by a
// release key. privometry update installs one only when all of these hold:
//
//   - the signature verifies against the release keys built into this
//     binary (none ship yet, so every update is refused; see
//     internal/trust/keys/README.md);
//   - the manifest validates against its schema and has not expired;
//   - its version is newer than the running one (no downgrades, no
//     reinstalls, and development builds never update themselves);
//   - the download for this OS and architecture has exactly the declared
//     size and SHA-256, every URL is HTTPS, and the archive holds the
//     declared binaries at its top level (nothing else is extracted);
//   - the new privometry binary runs and reports the manifest's version.
//
// Binaries are staged next to the installed ones and swapped in with
// renames, restoring the old ones if any swap fails.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/signing"
	"github.com/privometry/privometry-oss/internal/trust"
	"github.com/privometry/privometry-oss/specs"
)

// PayloadType is the DSSE payload type of a signed release manifest.
const PayloadType = "application/vnd.privometry.release+json"

// DefaultManifestURL is where privometry update looks for the latest stable
// release. PRIVOMETRY_UPDATE_URL or --manifest override it.
const DefaultManifestURL = "https://github.com/privometry/privometry-oss/releases/latest/download/release.json"

// Limits on what is downloaded.
const (
	maxManifest = 1 << 20
	maxBinary   = 256 << 20
)

// Errors callers can match with errors.Is.
var (
	ErrNoReleaseKeys = trust.ErrNoReleaseKeys
	ErrDevBuild      = errors.New("update: development builds do not update themselves")
	ErrUpToDate      = errors.New("update: already up to date")
	ErrDowngrade     = errors.New("update: the published release is older than this one; downgrades are refused")
	ErrExpired       = errors.New("update: the release manifest has expired")
	ErrNoArtifact    = errors.New("update: the release has no download for this platform")
	ErrManaged       = errors.New("update: Privometry was installed by a package manager")
)

// TrustedKeys returns the release key set built into this binary.
func TrustedKeys() (*signing.KeySet, error) { return trust.ReleaseKeys() }

// Options configure a check or an install.
type Options struct {
	ManifestURL string
	Keys        *signing.KeySet // nil means TrustedKeys
	Client      *http.Client    // nil means a client with timeouts
	Current     string          // the running version
	GOOS        string          // runtime.GOOS
	GOARCH      string
	Now         func() time.Time
}

func (o *Options) defaults() error {
	if o.ManifestURL == "" {
		o.ManifestURL = DefaultManifestURL
	}
	if o.Keys == nil {
		ks, err := TrustedKeys()
		if err != nil {
			return err
		}
		o.Keys = ks
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 5 * time.Minute}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return nil
}

// Check fetches and verifies the manifest and picks this platform's
// download. It returns ErrUpToDate or ErrDowngrade, with the release, when
// there is nothing to install.
func Check(ctx context.Context, opts Options) (*Release, *Artifact, error) {
	if err := opts.defaults(); err != nil {
		return nil, nil, err
	}
	cur, err := parseVersion(opts.Current)
	if err != nil {
		return nil, nil, ErrDevBuild
	}
	raw, err := get(ctx, opts.Client, opts.ManifestURL, maxManifest)
	if err != nil {
		return nil, nil, fmt.Errorf("update: manifest: %w", err)
	}
	payload, err := signing.Verify(raw, opts.Keys, "release", PayloadType, opts.Now())
	if err != nil {
		return nil, nil, fmt.Errorf("update: manifest signature: %w", err)
	}
	var rel Release
	if err := specs.DecodeInto("release/v1/release.schema.json", "release.json", payload, &rel); err != nil {
		return nil, nil, fmt.Errorf("update: manifest: %w", err)
	}
	if opts.Now().After(rel.ExpiresAt.Time) {
		return &rel, nil, fmt.Errorf("%w (%s)", ErrExpired, rel.ExpiresAt)
	}
	next, err := parseVersion(rel.Version)
	if err != nil {
		return &rel, nil, err
	}
	switch c := next.compare(cur); {
	case c == 0:
		return &rel, nil, ErrUpToDate
	case c < 0:
		return &rel, nil, ErrDowngrade
	}
	osName := map[string]ArtifactOS{"darwin": ArtifactOSMacos, "linux": ArtifactOSLinux, "windows": ArtifactOSWindows}[opts.GOOS]
	for i, a := range rel.Artifacts {
		if a.OS == osName && string(a.Arch) == opts.GOARCH {
			return &rel, &rel.Artifacts[i], nil
		}
	}
	return &rel, nil, fmt.Errorf("%w (%s/%s)", ErrNoArtifact, opts.GOOS, opts.GOARCH)
}

// get downloads an HTTPS URL, refusing redirects off HTTPS and bodies over
// limit bytes.
func get(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("%q is not an HTTPS URL", rawURL)
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("redirect off HTTPS")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", rawURL, limit)
	}
	return body, nil
}

// InstallDir is the folder holding the running binaries, with symlinks
// resolved. It refuses folders a package manager owns.
func InstallDir() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return "", err
	}
	dir := filepath.Dir(self)
	switch {
	case strings.Contains(dir, "/Cellar/") || strings.Contains(dir, "/homebrew/") || strings.Contains(dir, "/linuxbrew/"):
		return "", fmt.Errorf("%w (Homebrew): run brew upgrade privometry", ErrManaged)
	case strings.Contains(strings.ToLower(dir), `\scoop\`):
		return "", fmt.Errorf("%w (Scoop): run scoop update privometry", ErrManaged)
	}
	return dir, nil
}

// Staged is a downloaded, verified release waiting next to the installed
// binaries.
type Staged struct {
	Dir   string
	Files map[string]string // binary name -> staged path
	Ext   string            // ".exe" on Windows
}

// Stage downloads the artifact, checks its size and digest, extracts the
// declared binaries next to the installed ones under temporary names, and
// checks that the new privometry runs and reports want.
func Stage(ctx context.Context, opts Options, art *Artifact, dir, want string) (*Staged, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	body, err := get(ctx, opts.Client, art.URL, art.Size)
	if err != nil {
		return nil, fmt.Errorf("update: download: %w", err)
	}
	if int64(len(body)) != art.Size {
		return nil, fmt.Errorf("update: download is %d bytes, the manifest says %d", len(body), art.Size)
	}
	sum := sha256.Sum256(body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != art.SHA256 {
		return nil, fmt.Errorf("update: download digest %s does not match the manifest's %s", got, art.SHA256)
	}
	wanted := map[string]bool{}
	for _, b := range art.Binaries {
		wanted[string(b)] = true
	}
	s := &Staged{Dir: dir, Files: map[string]string{}}
	if opts.GOOS == "windows" {
		s.Ext = ".exe"
	}
	removeOld(dir)
	write := func(name string, r io.Reader) error {
		if !wanted[name] || s.Files[name] != "" {
			return nil // not a declared binary, or a duplicate entry: ignore
		}
		tmp, err := tempPath(dir, name)
		if err != nil {
			return err
		}
		tmp += s.Ext
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // installed binaries must be executable
		if err != nil {
			return err
		}
		s.Files[name] = tmp
		n, err := io.Copy(f, io.LimitReader(r, maxBinary+1))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > maxBinary {
			err = fmt.Errorf("%s is larger than %d bytes", name, maxBinary)
		}
		return err
	}
	switch art.Format {
	case ArtifactFormatTarGz:
		err = extractTarGz(body, write)
	case ArtifactFormatZip:
		err = extractZip(body, write)
	default:
		err = fmt.Errorf("unknown archive format %q", art.Format)
	}
	if err == nil {
		for _, b := range art.Binaries {
			if s.Files[string(b)] == "" {
				err = fmt.Errorf("the archive has no %s", b)
				break
			}
		}
	}
	if err == nil {
		err = checkRuns(ctx, s.Files["privometry"], want)
	}
	if err != nil {
		s.Discard()
		return nil, fmt.Errorf("update: %w", err)
	}
	return s, nil
}

// topLevel returns an archive entry's name when it is a plain file at the
// archive's top level ("privometry" or "./privometry"), else "".
func topLevel(name string) string {
	name = strings.TrimPrefix(name, "./")
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return ""
	}
	return name
}

func extractTarGz(body []byte, write func(string, io.Reader) error) error {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue // links, folders and devices are never extracted
		}
		if name := topLevel(h.Name); name != "" {
			if err := write(name, tr); err != nil {
				return err
			}
		}
	}
}

func extractZip(body []byte, write func(string, io.Reader) error) error {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if !f.Mode().IsRegular() {
			continue
		}
		name := strings.TrimSuffix(topLevel(f.Name), ".exe")
		if name == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = write(name, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// checkRuns runs the staged privometry and checks the version it reports, which
// also proves it was built for this machine.
func checkRuns(ctx context.Context, path, want string) error {
	if path == "" {
		return nil // a release without privometry itself: nothing to run
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return fmt.Errorf("the new privometry does not run here: %w", err)
	}
	if f := strings.Fields(string(out)); len(f) < 2 || f[1] != want {
		return fmt.Errorf("the new privometry reports %q, the manifest says %s", strings.TrimSpace(string(out)), want)
	}
	return nil
}

func tempPath(dir, name string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return filepath.Join(dir, ".privometry-update-"+name+"-"+hex.EncodeToString(b)), nil
}

// Discard removes the staged files.
func (s *Staged) Discard() {
	for _, p := range s.Files {
		os.Remove(p)
	}
}

// Install swaps the staged binaries in. Each swap is a rename, so an agent's
// hook sees the old or the new privometry-hook, never a partial file. If a swap
// fails, the binaries already replaced are restored.
func (s *Staged) Install() error {
	names := make([]string, 0, len(s.Files))
	for n := range s.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	type swapped struct{ target, old string }
	var done []swapped
	rollback := func() {
		for i := len(done) - 1; i >= 0; i-- {
			if done[i].old != "" {
				_ = os.Rename(done[i].old, done[i].target) // best effort: already failing
			} else {
				os.Remove(done[i].target)
			}
		}
	}
	for _, n := range names {
		target := filepath.Join(s.Dir, n+s.Ext)
		sw := swapped{target: target}
		if _, err := os.Lstat(target); err == nil {
			sw.old = target + ".privometry-old-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			if err := os.Rename(target, sw.old); err != nil {
				rollback()
				s.Discard()
				return fmt.Errorf("update: %w", err)
			}
		}
		if err := os.Rename(s.Files[n], target); err != nil {
			if sw.old != "" {
				_ = os.Rename(sw.old, target) // best effort: already failing
			}
			rollback()
			s.Discard()
			return fmt.Errorf("update: %w", err)
		}
		done = append(done, sw)
	}
	for _, d := range done {
		if d.old != "" {
			os.Remove(d.old) // Windows keeps a running binary; the next update removes it
		}
	}
	return nil
}

// removeOld deletes binaries an earlier update replaced but could not
// remove because they were running (Windows renames a running binary but
// does not delete it).
func removeOld(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, "*.privometry-old-*"))
	for _, p := range old {
		os.Remove(p)
	}
}

// version is a parsed semantic version.
type version struct {
	core [3]int
	pre  []string
}

func parseVersion(s string) (version, error) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata does not order
	}
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	var v version
	if len(parts) != 3 {
		return v, fmt.Errorf("update: %q is not a version", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return v, fmt.Errorf("update: %q is not a version", s)
		}
		v.core[i] = n
	}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
	}
	return v, nil
}

// compare orders versions by semver precedence.
func (v version) compare(o version) int {
	for i := range 3 {
		if v.core[i] != o.core[i] {
			return cmpInt(v.core[i], o.core[i])
		}
	}
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1 // a release is newer than its prereleases
	case len(o.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		a, b := v.pre[i], o.pre[i]
		an, aerr := strconv.Atoi(a)
		bn, berr := strconv.Atoi(b)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return cmpInt(an, bn)
			}
		case aerr == nil:
			return -1 // numeric identifiers sort before alphanumeric ones
		case berr == nil:
			return 1
		case a != b:
			return strings.Compare(a, b)
		}
	}
	return cmpInt(len(v.pre), len(o.pre))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
