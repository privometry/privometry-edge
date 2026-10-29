// Package definitions supplies the adapter definitions and detector packs the
// sensor runs on (PRD EDGE-04 and SCAN-09). Both ship inside the binary, and
// each can be replaced at run time by a newer set signed with the release
// key, so agent config paths, hook formats and detectors change without a
// binary release.
//
// A signed set is a DSSE envelope kept in <data dir>/definitions. It is used
// only when all of these hold:
//
//   - the signature verifies against the release keys built into this binary
//     (none ship yet, so every installed set is ignored; see
//     internal/trust/keys/README.md);
//   - the payload validates against its schema (privometry.adapter_set/v1 or
//     privometry.detectorpack_set/v1);
//   - its set_version is higher than the set built into this binary, so a
//     set made for an older release never overrides a newer binary;
//   - this sensor is at least the set's min_sensor_version (adapters);
//   - every definition loads and every detector passes its own samples.
//
// Otherwise the built-in set is used and Status says why. Detector packs that
// need a newer sensor are kept at their built-in version, one by one.
package definitions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	adapterdefs "github.com/privometry/privometry-edge/adapter-defs"
	"github.com/privometry/privometry-edge/detectorpacks"
	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/internal/trust"
	"github.com/privometry/privometry-edge/specs"
)

// Kind is one of the two signed sets.
type Kind string

// The signed sets.
const (
	Adapters  Kind = "adapters"
	Detectors Kind = "detectorpacks"
)

// Kinds lists the sets in display order.
var Kinds = []Kind{Adapters, Detectors}

// DSSE payload types of the signed sets.
const (
	AdaptersPayloadType  = "application/vnd.privometry.adapters+json"
	DetectorsPayloadType = "application/vnd.privometry.detectorpacks+json"
)

// DirName is the folder under the data directory holding installed sets.
const DirName = "definitions"

// DefaultBaseURL is where privometry definitions update downloads
// adapters.json and detectorpacks.json: the latest release's direct assets.
// PRIVOMETRY_DEFINITIONS_URL or --url override it.
const DefaultBaseURL = "https://github.com/privometry/privometry-edge/releases/latest/download"

// maxSet bounds a downloaded or installed set.
const maxSet = 8 << 20

// ErrNotNewer means a set is not newer than the one in use.
var ErrNotNewer = errors.New("definitions: the set is not newer than the one in use")

type kindInfo struct {
	payloadType, schema, label string
	builtIn                    int64
}

var kinds = map[Kind]kindInfo{
	Adapters:  {AdaptersPayloadType, "adapter/v1/adapter-set.schema.json", "Adapter definitions", adapterdefs.SetVersion},
	Detectors: {DetectorsPayloadType, "detectorpack/v1/pack-set.schema.json", "Detector packs", detectorpacks.SetVersion},
}

// File is the installed set's file name in the definitions folder.
func (k Kind) File() string { return string(k) + ".json" }

// Label names the set for people.
func (k Kind) Label() string { return kinds[k].label }

// BuiltIn is the version of the set built into this binary.
func (k Kind) BuiltIn() int64 { return kinds[k].builtIn }

// Options configure loading and installing.
type Options struct {
	// Dir holds installed sets; empty means built-in sets only.
	Dir string
	// Keys verify signed sets; nil means the release keys built into this
	// binary.
	Keys *signing.KeySet
	// SensorVersion is this sensor's version, checked against each set's
	// min_sensor_version. A development build accepts any.
	SensorVersion string
	Now           func() time.Time
}

// Dir is the definitions folder under env's data directory.
func Dir(env platform.Env) (string, error) {
	data, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(data, DirName), nil
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

func (o Options) keys() (*signing.KeySet, error) {
	if o.Keys != nil {
		return o.Keys, nil
	}
	return trust.ReleaseKeys()
}

// Status describes the set in use for one kind.
type Status struct {
	Kind        Kind   `json:"kind"`
	Source      string `json:"source"` // built-in or signed
	SetVersion  int64  `json:"set_version"`
	BuiltIn     int64  `json:"built_in_version"`
	PublishedAt string `json:"published_at,omitempty"`
	// Problem says why an installed set is not used.
	Problem string `json:"problem,omitempty"`
	// Kept lists detector packs kept at their built-in version because the
	// signed version needs a newer sensor.
	Kept []string `json:"kept_built_in,omitempty"`
}

func builtInStatus(k Kind) Status {
	return Status{Kind: k, Source: "built-in", SetVersion: k.BuiltIn(), BuiltIn: k.BuiltIn()}
}

// LoadAdapters returns the adapter definitions to run on.
func LoadAdapters(opts Options) (*registry.Registry, Status, error) {
	builtIn, err := registry.Load(adapterdefs.FS)
	if err != nil {
		return nil, Status{}, err
	}
	raw, err := readInstalled(opts, Adapters)
	if raw == nil && err == nil {
		return builtIn, builtInStatus(Adapters), nil
	}
	var reg *registry.Registry
	var st Status
	if err == nil {
		reg, st, err = verifyAdapters(opts, raw)
	}
	if err == nil {
		err = newerThanBuiltIn(st)
	}
	if err != nil {
		st = builtInStatus(Adapters)
		st.Problem = problem(err)
		return builtIn, st, nil
	}
	return reg, st, nil
}

func verifyAdapters(opts Options, raw []byte) (*registry.Registry, Status, error) {
	var set registry.AdapterSet
	if err := verify(opts, Adapters, raw, &set); err != nil {
		return nil, Status{}, err
	}
	st := Status{Kind: Adapters, Source: "signed", SetVersion: set.SetVersion, BuiltIn: Adapters.BuiltIn(), PublishedAt: set.PublishedAt.String()}
	if !atLeast(opts.SensorVersion, set.MinSensorVersion) {
		return nil, st, fmt.Errorf("definitions: adapter set %d needs Privometry %s or later", set.SetVersion, set.MinSensorVersion)
	}
	reg, err := registry.New(set.Adapters)
	if err != nil {
		return nil, st, err
	}
	return reg, st, nil
}

// LoadDetectors returns the detector packs to run.
func LoadDetectors(opts Options) ([]*content.Pack, Status, error) {
	builtIn, err := content.Load(detectorpacks.FS)
	if err != nil {
		return nil, Status{}, err
	}
	raw, err := readInstalled(opts, Detectors)
	if raw == nil && err == nil {
		return builtIn, builtInStatus(Detectors), nil
	}
	var packs []*content.Pack
	var st Status
	if err == nil {
		packs, st, err = verifyDetectors(opts, raw, builtIn)
	}
	if err == nil {
		err = newerThanBuiltIn(st)
	}
	if err != nil {
		st = builtInStatus(Detectors)
		st.Problem = problem(err)
		return builtIn, st, nil
	}
	return packs, st, nil
}

func verifyDetectors(opts Options, raw []byte, builtIn []*content.Pack) ([]*content.Pack, Status, error) {
	var set content.PackSet
	if err := verify(opts, Detectors, raw, &set); err != nil {
		return nil, Status{}, err
	}
	st := Status{Kind: Detectors, Source: "signed", SetVersion: set.SetVersion, BuiltIn: Detectors.BuiltIn(), PublishedAt: set.PublishedAt.String()}
	byID := map[string]*content.Pack{}
	for _, p := range builtIn {
		byID[p.Manifest.ID] = p
	}
	var packs []*content.Pack
	seen := map[string]bool{}
	for _, sp := range set.Packs {
		id := sp.Manifest.ID
		if seen[id] {
			return nil, st, fmt.Errorf("definitions: detector pack %s is in the set twice", id)
		}
		seen[id] = true
		if !atLeast(opts.SensorVersion, sp.Manifest.MinSensorVersion) {
			if p, ok := byID[id]; ok {
				packs = append(packs, p)
				st.Kept = append(st.Kept, fmt.Sprintf("%s %s (set has %s, which needs Privometry %s)", id, p.Manifest.Version, sp.Manifest.Version, sp.Manifest.MinSensorVersion))
			}
			continue
		}
		p, err := content.NewPack(sp.Manifest, sp.Detectors)
		if err != nil {
			return nil, st, err
		}
		if errs := content.Check(p); len(errs) > 0 {
			return nil, st, fmt.Errorf("definitions: %s %s fails its own samples: %w", id, sp.Manifest.Version, errors.Join(errs...))
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Manifest.ID < packs[j].Manifest.ID })
	return packs, st, nil
}

// newerThanBuiltIn refuses a set made for an older release.
func newerThanBuiltIn(st Status) error {
	if st.SetVersion <= st.Kind.BuiltIn() {
		return fmt.Errorf("%w: set %d is not newer than the built-in set %d", ErrNotNewer, st.SetVersion, st.Kind.BuiltIn())
	}
	return nil
}

// Check verifies a signed set completely, as loading does, except that it
// does not compare its version with the sets built in or installed: a
// publisher checks a set built from the same sources as its own binary.
func Check(opts Options, raw []byte) (Status, error) {
	k, err := KindOf(raw)
	if err != nil {
		return Status{}, err
	}
	var st Status
	switch k {
	case Adapters:
		_, st, err = verifyAdapters(opts, raw)
	case Detectors:
		var builtIn []*content.Pack
		if builtIn, err = content.Load(detectorpacks.FS); err == nil {
			_, st, err = verifyDetectors(opts, raw, builtIn)
		}
	}
	return st, err
}

// verify checks a set's signature and schema and decodes it into v.
func verify(opts Options, k Kind, raw []byte, v any) error {
	ks, err := opts.keys()
	if err != nil {
		return err
	}
	payload, err := signing.Verify(raw, ks, "release", kinds[k].payloadType, opts.now())
	if err != nil {
		return err
	}
	return specs.DecodeInto(kinds[k].schema, k.File(), payload, v)
}

// readInstalled returns nil, nil when no set of this kind is installed.
func readInstalled(opts Options, k Kind) ([]byte, error) {
	if opts.Dir == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Join(opts.Dir, k.File()))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSet+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSet {
		return nil, fmt.Errorf("definitions: %s is larger than %d bytes", k.File(), maxSet)
	}
	return raw, nil
}

func problem(err error) string {
	if errors.Is(err, trust.ErrNoReleaseKeys) {
		return "installed set ignored: " + err.Error() + " to verify it with"
	}
	return "installed set ignored: " + strings.TrimPrefix(err.Error(), "definitions: ")
}

// Statuses reports the set in use for each kind.
func Statuses(opts Options) []Status {
	_, a, errA := LoadAdapters(opts)
	_, d, errD := LoadDetectors(opts)
	if errA != nil {
		a = Status{Kind: Adapters, Problem: errA.Error()}
	}
	if errD != nil {
		d = Status{Kind: Detectors, Problem: errD.Error()}
	}
	return []Status{a, d}
}

// KindOf returns the kind of a signed set from its envelope's payload type.
func KindOf(raw []byte) (Kind, error) {
	var env struct {
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("definitions: not a signed set: %w", err)
	}
	for _, k := range Kinds {
		if kinds[k].payloadType == env.PayloadType {
			return k, nil
		}
	}
	return "", fmt.Errorf("definitions: payload type %q is not an adapter set or a detector pack set", env.PayloadType)
}

// Install verifies a signed set and saves it in opts.Dir. The set must be
// newer than the built-in set and than the set already installed, and must
// load completely; nothing is written otherwise.
func Install(opts Options, raw []byte) (Status, error) {
	if opts.Dir == "" {
		return Status{}, errors.New("definitions: no definitions folder")
	}
	if len(raw) > maxSet {
		return Status{}, fmt.Errorf("definitions: set is larger than %d bytes", maxSet)
	}
	st, err := Check(opts, raw)
	if err == nil {
		err = newerThanBuiltIn(st)
	}
	if err != nil {
		return st, err
	}
	k := st.Kind
	if current := installedVersion(opts, k); st.SetVersion <= current {
		return st, fmt.Errorf("%w: set %d is not newer than the installed set %d", ErrNotNewer, st.SetVersion, current)
	}
	if err := platform.EnsurePrivateDir(opts.Dir); err != nil {
		return st, err
	}
	tmp := filepath.Join(opts.Dir, "."+k.File()+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return st, err
	}
	if err := os.Rename(tmp, filepath.Join(opts.Dir, k.File())); err != nil {
		os.Remove(tmp)
		return st, err
	}
	return st, nil
}

// installedVersion is the version of the valid installed set, or 0.
func installedVersion(opts Options, k Kind) int64 {
	var st Status
	switch k {
	case Adapters:
		_, st, _ = LoadAdapters(opts)
	case Detectors:
		_, st, _ = LoadDetectors(opts)
	}
	if st.Source != "signed" {
		return 0
	}
	return st.SetVersion
}

// Fetch downloads a signed set over HTTPS.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("definitions: %q is not an HTTPS URL", rawURL)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSet+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSet {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", rawURL, maxSet)
	}
	return body, nil
}

// atLeast reports whether version satisfies a minimum. An empty minimum and
// a version that is not x.y.z (a development build) always do.
func atLeast(version, minimum string) bool {
	v, ok := triple(version)
	m, okMin := triple(minimum)
	if !ok || !okMin {
		return true
	}
	for i := range v {
		if v[i] != m[i] {
			return v[i] > m[i]
		}
	}
	return true
}

func triple(s string) ([3]int, bool) {
	var t [3]int
	core, _, _ := strings.Cut(strings.TrimPrefix(s, "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return t, false
		}
		t[i] = n
	}
	return t, true
}

// BuildAdapterSet returns the unsigned adapter set payload for the
// definitions built into this binary, for scripts/sign-definitions.
func BuildAdapterSet(setVersion int64, publishedAt time.Time, minSensor string) ([]byte, error) {
	files, err := fs.Glob(adapterdefs.FS, "*.yaml")
	if err != nil {
		return nil, err
	}
	var adapters []any
	for _, f := range files {
		v, err := decodeFile(adapterdefs.FS, f)
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, v)
	}
	set := map[string]any{"schema": "privometry.adapter_set/v1", "set_version": setVersion,
		"published_at": contract.At(publishedAt), "adapters": adapters}
	if minSensor != "" {
		set["min_sensor_version"] = minSensor
	}
	return marshalValid(Adapters, set)
}

// BuildDetectorSet returns the unsigned detector pack set payload for the
// packs built into this binary, for scripts/sign-definitions.
func BuildDetectorSet(setVersion int64, publishedAt time.Time) ([]byte, error) {
	manifests, err := fs.Glob(detectorpacks.FS, "*/pack.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(manifests)
	var packs []any
	for _, m := range manifests {
		manifest, err := decodeFile(detectorpacks.FS, m)
		if err != nil {
			return nil, err
		}
		files, _ := fs.Glob(detectorpacks.FS, path.Join(path.Dir(m), "detectors", "*.yaml"))
		sort.Strings(files)
		var docs []any
		for _, f := range files {
			v, err := decodeFile(detectorpacks.FS, f)
			if err != nil {
				return nil, err
			}
			docs = append(docs, v)
		}
		packs = append(packs, map[string]any{"manifest": manifest, "detectors": docs})
	}
	set := map[string]any{"schema": "privometry.detectorpack_set/v1", "set_version": setVersion,
		"published_at": contract.At(publishedAt), "packs": packs}
	return marshalValid(Detectors, set)
}

func decodeFile(fsys fs.FS, name string) (any, error) {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return specs.Decode(name, raw)
}

func marshalValid(k Kind, set any) ([]byte, error) {
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := specs.Validate(kinds[k].schema, k.File(), b); err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
