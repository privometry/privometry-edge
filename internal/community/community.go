package community

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing/fstest"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy/packtest"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/specs"
)

const (
	// PayloadType is the DSSE payload type of a signed community pack.
	PayloadType = "application/vnd.privometry.communitypack+json"
	// Role is the key role that signs community packs.
	Role = "publisher"
	// Reserved is the publisher only Privometry's release key speaks for.
	Reserved = "privometry"
)

var (
	// ErrUntrusted means no trusted key may sign for the pack's publisher.
	ErrUntrusted = errors.New("no trusted key for this publisher")
	// ErrNotNewer means the same or a newer version is already installed.
	ErrNotNewer = errors.New("not newer than the installed version")
	// ErrNotInstalled means no pack or key matched.
	ErrNotInstalled = errors.New("not installed")
)

var nameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Store keeps the publisher keys the user trusts and the packs they
// installed, in <data dir>/community.
type Store struct{ dir string }

// Open returns the store for env's data folder.
func Open(env platform.Env) (*Store, error) {
	data, err := env.DataDir()
	if err != nil {
		return nil, err
	}
	return &Store{dir: filepath.Join(data, "community")}, nil
}

// Dir is where the store keeps its files.
func (s *Store) Dir() string { return s.dir }

// ---- trusted publisher keys

// Key is one publisher key the user trusts.
type Key struct {
	Publisher string         `json:"publisher"`
	KeyID     string         `json:"keyid"`
	PublicKey string         `json:"public_key"`
	NotBefore contract.Time  `json:"not_before"`
	NotAfter  *contract.Time `json:"not_after,omitempty"`
	AddedAt   contract.Time  `json:"added_at"`
}

// Fingerprint is the full SHA-256 of the public key, for comparing with what
// the publisher announces.
func (k Key) Fingerprint() string {
	raw, _ := base64.StdEncoding.DecodeString(k.PublicKey)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type trustFile struct {
	Keys []Key `json:"keys"`
}

// PublisherKeys reads a publisher's key set (privometry.keyset/v1 holding
// publisher keys). Keys for other roles, and keys claiming the reserved
// publisher, are refused.
func PublisherKeys(raw []byte, now time.Time) ([]Key, error) {
	if err := specs.Validate("common/v1/keyset.schema.json", "keyset.json", raw); err != nil {
		return nil, err
	}
	ks, err := signing.ParseKeySet(raw)
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, k := range ks.Keys {
		if k.Role != Role {
			return nil, fmt.Errorf("key %s has role %s; only publisher keys sign community packs", k.KeyID, k.Role)
		}
		name := strings.Split(k.KeyID, ":")[1]
		if name == Reserved {
			return nil, fmt.Errorf("key %s claims the publisher %q, which only Privometry's release key speaks for", k.KeyID, Reserved)
		}
		key := Key{Publisher: name, KeyID: k.KeyID, PublicKey: base64.StdEncoding.EncodeToString(k.Public),
			NotBefore: contract.At(k.NotBefore), AddedAt: contract.At(now)}
		if !k.NotAfter.IsZero() {
			t := contract.At(k.NotAfter)
			key.NotAfter = &t
		}
		out = append(out, key)
	}
	return out, nil
}

// Trusted returns the keys the user trusts, by publisher and key ID.
func (s *Store) Trusted() ([]Key, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "trust.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f trustFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("community: %s: %w", filepath.Join(s.dir, "trust.json"), err)
	}
	return f.Keys, nil
}

// Trust adds keys, replacing any with the same key ID.
func (s *Store) Trust(keys []Key) error {
	have, err := s.Trusted()
	if err != nil {
		return err
	}
	byID := map[string]Key{}
	for _, k := range have {
		byID[k.KeyID] = k
	}
	for _, k := range keys {
		byID[k.KeyID] = k
	}
	return s.saveTrust(byID)
}

// Untrust removes the key with that ID, or every key of that publisher, and
// returns how many it removed. Packs those keys signed stop loading.
func (s *Store) Untrust(publisherOrKeyID string) (int, error) {
	have, err := s.Trusted()
	if err != nil {
		return 0, err
	}
	byID := map[string]Key{}
	removed := 0
	for _, k := range have {
		if k.KeyID == publisherOrKeyID || k.Publisher == publisherOrKeyID {
			removed++
			continue
		}
		byID[k.KeyID] = k
	}
	if removed == 0 {
		return 0, ErrNotInstalled
	}
	return removed, s.saveTrust(byID)
}

func (s *Store) saveTrust(byID map[string]Key) error {
	keys := make([]Key, 0, len(byID))
	for _, k := range byID {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	raw, err := json.MarshalIndent(trustFile{Keys: keys}, "", "  ")
	if err != nil {
		return err
	}
	return s.write(filepath.Join(s.dir, "trust.json"), append(raw, '\n'))
}

// keySet holds the trusted keys of one publisher.
func (s *Store) keySet(publisher string) (*signing.KeySet, error) {
	keys, err := s.Trusted()
	if err != nil {
		return nil, err
	}
	ks := &signing.KeySet{Version: 1}
	for _, k := range keys {
		if k.Publisher != publisher {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("community: trusted key %s is malformed", k.KeyID)
		}
		sk := signing.Key{KeyID: k.KeyID, Role: Role, Public: ed25519.PublicKey(pub), NotBefore: k.NotBefore.Time}
		if k.NotAfter != nil {
			sk.NotAfter = k.NotAfter.Time
		}
		ks.Keys = append(ks.Keys, sk)
	}
	if len(ks.Keys) == 0 {
		return nil, fmt.Errorf("%w %q (privometry trust add)", ErrUntrusted, publisher)
	}
	return ks, nil
}

// ---- signed packs

// Pack is a verified community pack.
type Pack struct {
	Document
	Publisher string
	SignedBy  string // key IDs in the envelope
	files     map[string]string
}

// Open verifies a signed pack: the envelope must be signed by a trusted key of
// the pack's own publisher and the payload must be a valid
// privometry.communitypack/v1 document with unique file paths.
func (s *Store) Open(raw []byte, now time.Time) (*Pack, error) {
	var env signing.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("community: not a DSSE envelope: %w", err)
	}
	unverified, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("community: payload: %w", err)
	}
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(unverified, &head); err != nil {
		return nil, fmt.Errorf("community: payload: %w", err)
	}
	publisher, _, ok := strings.Cut(head.ID, "/")
	if !ok || !nameRE.MatchString(publisher) {
		return nil, fmt.Errorf("community: pack ID %q has no publisher", head.ID)
	}
	if publisher == Reserved {
		return nil, fmt.Errorf("community: %s: the publisher %q is reserved for Privometry's own packs", head.ID, Reserved)
	}
	// Only this publisher's keys are offered, so another publisher's key
	// cannot sign for it.
	ks, err := s.keySet(publisher)
	if err != nil {
		return nil, fmt.Errorf("community: %s: %w", head.ID, err)
	}
	payload, err := signing.Verify(raw, ks, Role, PayloadType, now)
	if err != nil {
		return nil, fmt.Errorf("community: %s: %w", head.ID, err)
	}
	p := &Pack{Publisher: publisher, files: map[string]string{}}
	if err := specs.DecodeInto("communitypack/v1/communitypack.schema.json", "pack.json", payload, &p.Document); err != nil {
		return nil, fmt.Errorf("community: %w", err)
	}
	for _, f := range p.Files {
		if _, dup := p.files[f.Path]; dup {
			return nil, fmt.Errorf("community: %s holds %s twice", p.ID, f.Path)
		}
		p.files[f.Path] = f.Content
	}
	var ids []string
	for _, sig := range env.Signatures {
		ids = append(ids, sig.KeyID)
	}
	p.SignedBy = strings.Join(ids, ", ")
	return p, nil
}

// fsys lays the pack out as <name>/<path>, the layout the pack loaders read.
func (p *Pack) fsys() fstest.MapFS {
	name := strings.SplitN(p.ID, "/", 2)[1]
	m := fstest.MapFS{}
	for f, c := range p.files {
		m[path.Join(name, f)] = &fstest.MapFile{Data: []byte(c), Mode: 0o600}
	}
	return m
}

// manifest reads pack.yaml's id, version and min_sensor_version.
func (p *Pack) manifest() (id, version, minSensor string, err error) {
	var m struct {
		ID               string `yaml:"id"`
		Version          string `yaml:"version"`
		MinSensorVersion string `yaml:"min_sensor_version"`
	}
	if err := yaml.Unmarshal([]byte(p.files["pack.yaml"]), &m); err != nil {
		return "", "", "", fmt.Errorf("community: %s pack.yaml: %w", p.ID, err)
	}
	if m.ID != p.ID || m.Version != p.Version {
		return "", "", "", fmt.Errorf("community: pack.yaml is %s %s, the signed pack says %s %s", m.ID, m.Version, p.ID, p.Version)
	}
	return m.ID, m.Version, m.MinSensorVersion, nil
}

// RulePack loads a verified rule pack.
func (p *Pack) RulePack(sensorVersion string) (rulepack.Pack, error) {
	if p.Kind != DocumentKindRules {
		return rulepack.Pack{}, fmt.Errorf("community: %s is a %s pack", p.ID, p.Kind)
	}
	_, _, minSensor, err := p.manifest()
	if err != nil {
		return rulepack.Pack{}, err
	}
	if !AtLeast(sensorVersion, minSensor) {
		return rulepack.Pack{}, fmt.Errorf("community: %s %s needs Privometry %s", p.ID, p.Version, minSensor)
	}
	packs, err := rulepack.Load(p.fsys())
	if err != nil {
		return rulepack.Pack{}, err
	}
	return packs[0], nil
}

// DetectorPack loads a verified detector pack.
func (p *Pack) DetectorPack(sensorVersion string) (*content.Pack, error) {
	if p.Kind != DocumentKindDetectors {
		return nil, fmt.Errorf("community: %s is a %s pack", p.ID, p.Kind)
	}
	_, _, minSensor, err := p.manifest()
	if err != nil {
		return nil, err
	}
	if !AtLeast(sensorVersion, minSensor) {
		return nil, fmt.Errorf("community: %s %s needs Privometry %s", p.ID, p.Version, minSensor)
	}
	packs, err := content.Load(p.fsys())
	if err != nil {
		return nil, err
	}
	return packs[0], nil
}

// Check runs the pack's own release gate: a rule pack's tests (with the
// checks of privometry policy test) or a detector pack's samples.
func (p *Pack) Check(sensorVersion string) error {
	switch p.Kind {
	case DocumentKindRules:
		if _, err := p.RulePack(sensorVersion); err != nil {
			return err
		}
		dir, err := os.MkdirTemp("", "privometry-pack-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if err := os.CopyFS(dir, p.fsys()); err != nil {
			return err
		}
		r := packtest.Pack(filepath.Join(dir, strings.SplitN(p.ID, "/", 2)[1]))
		if !r.OK() {
			return fmt.Errorf("community: %s %s fails its own tests: %s", p.ID, p.Version, strings.Join(append(r.Problems, r.Failures...), "; "))
		}
	case DocumentKindDetectors:
		dp, err := p.DetectorPack(sensorVersion)
		if err != nil {
			return err
		}
		if errs := content.Check(dp); len(errs) > 0 {
			return fmt.Errorf("community: %s %s fails its own samples: %w", p.ID, p.Version, errors.Join(errs...))
		}
	}
	return nil
}

// Installed describes one installed pack.
type Installed struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Version     string `json:"version"`
	PublishedAt string `json:"published_at,omitempty"`
	SignedBy    string `json:"signed_by,omitempty"`
	// Problem is why the pack does not load now, such as a key no longer trusted.
	Problem string `json:"problem,omitempty"`
}

// InstallOptions say what an install accepts.
type InstallOptions struct {
	Now           time.Time
	SensorVersion string
}

func (s *Store) packPath(id string) string {
	publisher, name, _ := strings.Cut(id, "/")
	return filepath.Join(s.dir, "packs", publisher, name+".json")
}

// Install verifies a signed pack, runs its own tests or samples, and keeps
// it. A version that is not newer than the installed one is refused; remove
// the installed pack first to go back.
func (s *Store) Install(raw []byte, opts InstallOptions) (Installed, error) {
	p, err := s.Open(raw, opts.Now)
	if err != nil {
		return Installed{}, err
	}
	if err := p.Check(opts.SensorVersion); err != nil {
		return Installed{}, err
	}
	if old, err := os.ReadFile(s.packPath(p.ID)); err == nil {
		if v := storedVersion(old); v != "" && !newer(p.Version, v) {
			return Installed{}, fmt.Errorf("community: %s %s: %w (%s); run privometry packs remove %s first to go back", p.ID, p.Version, ErrNotNewer, v, p.ID)
		}
	}
	if err := s.write(s.packPath(p.ID), raw); err != nil {
		return Installed{}, err
	}
	return describe(p), nil
}

func describe(p *Pack) Installed {
	return Installed{ID: p.ID, Kind: string(p.Kind), Version: p.Version, PublishedAt: p.PublishedAt.String(), SignedBy: p.SignedBy}
}

// storedVersion reads the version of a kept envelope without verifying it,
// so a pack whose key is no longer trusted still blocks a downgrade.
func storedVersion(raw []byte) string {
	var env signing.Envelope
	if json.Unmarshal(raw, &env) != nil {
		return ""
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}
	var head struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return ""
	}
	return head.Version
}

// Remove deletes an installed pack.
func (s *Store) Remove(id string) error {
	err := os.Remove(s.packPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotInstalled
	}
	return err
}

// stored lists the kept envelopes by pack ID.
func (s *Store) stored() (map[string][]byte, error) {
	files, err := filepath.Glob(filepath.Join(s.dir, "packs", "*", "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		id := filepath.Base(filepath.Dir(f)) + "/" + strings.TrimSuffix(filepath.Base(f), ".json")
		out[id] = raw
	}
	return out, nil
}

// List verifies every installed pack again and reports it.
func (s *Store) List(now time.Time, sensorVersion string) ([]Installed, error) {
	stored, err := s.stored()
	if err != nil {
		return nil, err
	}
	var out []Installed
	for id, raw := range stored {
		p, err := s.Open(raw, now)
		if err == nil && p.ID != id {
			err = fmt.Errorf("community: the file for %s holds %s", id, p.ID)
		}
		if err != nil {
			out = append(out, Installed{ID: id, Version: storedVersion(raw), Problem: err.Error()})
			continue
		}
		in := describe(p)
		switch p.Kind {
		case DocumentKindRules:
			_, err = p.RulePack(sensorVersion)
		case DocumentKindDetectors:
			_, err = p.DetectorPack(sensorVersion)
		}
		if err != nil {
			in.Problem = err.Error()
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// verified returns the installed packs of one kind that verify now.
func (s *Store) verified(kind DocumentKind, now time.Time) ([]*Pack, []error) {
	stored, err := s.stored()
	if err != nil {
		return nil, []error{err}
	}
	var out []*Pack
	var errs []error
	for id, raw := range stored {
		p, err := s.Open(raw, now)
		if err == nil && p.ID != id {
			err = fmt.Errorf("community: the file for %s holds %s", id, p.ID)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, errs
}

// RulePacks loads every installed rule pack that verifies now. Problems are
// returned, not fatal: a pack that fails is left out.
func (s *Store) RulePacks(now time.Time, sensorVersion string) ([]rulepack.Pack, []error) {
	packs, errs := s.verified(DocumentKindRules, now)
	var out []rulepack.Pack
	for _, p := range packs {
		rp, err := p.RulePack(sensorVersion)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, rp)
	}
	return out, errs
}

// DetectorPacks loads every installed detector pack that verifies now.
func (s *Store) DetectorPacks(now time.Time, sensorVersion string) ([]*content.Pack, []error) {
	packs, errs := s.verified(DocumentKindDetectors, now)
	var out []*content.Pack
	for _, p := range packs {
		dp, err := p.DetectorPack(sensorVersion)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, dp)
	}
	return out, errs
}

// write replaces a file atomically, private to the user.
func (s *Store) write(dst string, raw []byte) error {
	if err := platform.EnsurePrivateDir(s.dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// ---- building and signing (publishers)

// allowedPath matches the files a pack folder may contribute.
var allowedPath = regexp.MustCompile(`^(pack\.yaml|README\.md|(rules|tests|detectors)/[A-Za-z0-9][A-Za-z0-9_-]{0,63}(\.test)?\.yaml)$`)

// Build reads a pack folder into an unsigned privometry.communitypack/v1
// document. kind is rules or detectors.
func Build(dir string, kind DocumentKind, publishedAt time.Time) ([]byte, error) {
	var m struct {
		ID      string `yaml:"id"`
		Version string `yaml:"version"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("community: pack.yaml: %w", err)
	}
	doc := Document{Schema: DocumentSchema, Kind: kind, ID: m.ID, Version: m.Version, PublishedAt: contract.At(publishedAt)}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if !allowedPath.MatchString(rel) {
			return nil // not part of a pack (editor files, notes)
		}
		body, err := os.ReadFile(p) //nolint:gosec // walks the user's own pack folder, as the user
		if err != nil {
			return err
		}
		doc.Files = append(doc.Files, DocumentFile{Path: rel, Content: string(body)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(doc.Files, func(i, j int) bool { return doc.Files[i].Path < doc.Files[j].Path })
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := specs.Validate("communitypack/v1/communitypack.schema.json", "pack.json", out); err != nil {
		return nil, err
	}
	return out, nil
}

// SignedFile is how a signed pack is named: <publisher>-<name>-<version>.pack.json.
func SignedFile(id, version string) string {
	return strings.ReplaceAll(id, "/", "-") + "-" + version + ".pack.json"
}

// Seed files hold a publisher's private key as the hex of its 32-byte seed.

// NewSeed makes a new key for a publisher and returns its seed file, its
// key set and the key.
func NewSeed(publisher string, notBefore time.Time) (seedFile, keySet []byte, key Key, err error) {
	if !nameRE.MatchString(publisher) || publisher == Reserved {
		return nil, nil, Key{}, fmt.Errorf("community: %q is not a publisher name you can use (lower case, digits and dashes; not %q)", publisher, Reserved)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, Key{}, err
	}
	id := signing.KeyID(Role, publisher, pub)
	ksDoc := map[string]any{"schema": "privometry.keyset/v1", "version": 1, "issued_at": contract.At(notBefore),
		"keys": []map[string]any{{"keyid": id, "role": Role, "public_key": base64.StdEncoding.EncodeToString(pub), "not_before": contract.At(notBefore)}}}
	keySet, err = json.MarshalIndent(ksDoc, "", "  ")
	if err != nil {
		return nil, nil, Key{}, err
	}
	key = Key{Publisher: publisher, KeyID: id, PublicKey: base64.StdEncoding.EncodeToString(pub), NotBefore: contract.At(notBefore)}
	return []byte(hex.EncodeToString(priv.Seed()) + "\n"), append(keySet, '\n'), key, nil
}

// SeedKey is the public key of a seed file, as a trusted key of publisher.
func SeedKey(seedFile []byte, publisher string, notBefore time.Time) (Key, error) {
	priv, err := privateKey(seedFile)
	if err != nil {
		return Key{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return Key{Publisher: publisher, KeyID: signing.KeyID(Role, publisher, pub), PublicKey: base64.StdEncoding.EncodeToString(pub),
		NotBefore: contract.At(notBefore), AddedAt: contract.At(notBefore)}, nil
}

func privateKey(seedFile []byte) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedFile)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("community: the key file must hold the 32-byte seed in hex")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs a pack document with a seed file for the publisher's key.
func Sign(doc, seedFile []byte) ([]byte, error) {
	priv, err := privateKey(seedFile)
	if err != nil {
		return nil, err
	}
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(doc, &head); err != nil {
		return nil, err
	}
	publisher, _, _ := strings.Cut(head.ID, "/")
	env := signing.Sign(PayloadType, doc, signing.KeyID(Role, publisher, priv.Public().(ed25519.PublicKey)), priv)
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ---- versions

// AtLeast reports whether version is at least minimum. A version that is not
// x.y.z (a development build) counts as new enough.
func AtLeast(version, minimum string) bool {
	if minimum == "" {
		return true
	}
	v, ok := triple(version)
	if !ok {
		return true
	}
	m, ok := triple(minimum)
	return !ok || compare(v, m) >= 0
}

func newer(a, b string) bool {
	x, okA := triple(a)
	y, okB := triple(b)
	return okA && okB && compare(x, y) > 0
}

func triple(s string) ([3]int, bool) {
	var t [3]int
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return t, false
		}
		t[i] = n
	}
	return t, true
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
