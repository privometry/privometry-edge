// Command release-manifest writes release.json, the signed manifest that
// privometry update installs from (specs/release/v1), from what goreleaser
// left in dist/: one artifact per archive listed in checksums.txt, with its
// exact size and SHA-256 and its download URL on the GitHub release.
//
//	go run ./scripts/release-manifest -version 0.5.0 -dist dist -key release.seed -name gh-2026
//	go run ./scripts/release-manifest -version 0.5.0 -dist dist    # unsigned payload for an external signer
//
// The connected build (privometry-connect) runs it too, with -base-url and
// -notes-url for its own download host.
//
// The manifest expires after -valid (60 days by default): devices refuse an
// expired one, so a release is re-signed before then (the release workflow's
// manual "resign" run). The signed envelope is checked the way a sensor
// checks it before it is written.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/signing"
	"github.com/privometry/privometry-edge/internal/update"
	"github.com/privometry/privometry-edge/specs"
)

// archiveRE matches goreleaser's archive names (.goreleaser.yaml name_template).
var archiveRE = regexp.MustCompile(`^privometry_(.+)_(darwin|linux|windows)_(amd64|arm64)\.(tar\.gz|zip)$`)

var binaries = []update.ArtifactBinary{"privometry", "privometryd", "privometry-hook", "privometry-mcp-shim"}

func main() {
	log.SetFlags(0)
	version := flag.String("version", "", "release version without the v, for example 0.5.0")
	dist := flag.String("dist", "dist", "goreleaser output folder with checksums.txt and the archives")
	base := flag.String("base-url", "", "download folder; default https://github.com/privometry/privometry-edge/releases/download/v<version>")
	notes := flag.String("notes-url", "", "release notes; default the GitHub release page")
	channel := flag.String("channel", "stable", "stable or beta")
	valid := flag.Duration("valid", 60*24*time.Hour, "how long devices accept the manifest")
	released := flag.String("released-at", "", "release time (RFC 3339); default now, and kept when re-signing")
	keyFile := flag.String("key", "", "file with the base64 release key seed; empty writes the unsigned payload")
	name := flag.String("name", "", "release key name, as in its key ID release:<name>:<hash>")
	out := flag.String("out", "", "output file; default <dist>/release.json, or release.payload.json unsigned")
	flag.Parse()
	if *version == "" {
		log.Fatal("-version is required")
	}
	*version = strings.TrimPrefix(*version, "v")
	if *base == "" {
		*base = "https://github.com/privometry/privometry-edge/releases/download/v" + *version
	}
	now := time.Now().UTC()
	releasedAt := now
	if *released != "" {
		t, err := time.Parse(time.RFC3339Nano, *released)
		if err != nil {
			log.Fatalf("-released-at: %v", err)
		}
		releasedAt = t
	}
	rel := update.Release{Schema: "privometry.release/v1", Version: *version, Channel: update.ReleaseChannel(*channel),
		ReleasedAt: contract.At(releasedAt), ExpiresAt: contract.At(now.Add(*valid)),
		NotesURL: orDefault(*notes, "https://github.com/privometry/privometry-edge/releases/tag/v"+*version)}
	arts, err := artifacts(*dist, *version, strings.TrimSuffix(*base, "/"))
	if err != nil {
		log.Fatal(err)
	}
	rel.Artifacts = arts
	payload, err := json.MarshalIndent(rel, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	var check update.Release
	if err := specs.DecodeInto("release/v1/release.schema.json", "release.json", payload, &check); err != nil {
		log.Fatal(err)
	}
	if *keyFile == "" {
		path := orDefault(*out, filepath.Join(*dist, "release.payload.json"))
		write(path, append(payload, '\n'))
		fmt.Printf("wrote %s (unsigned; sign as DSSE with payload type %s)\n", path, update.PayloadType)
		return
	}
	if *name == "" {
		log.Fatal("-name is required with -key")
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := signing.ParsePrivateKey(raw)
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := signing.KeyID("release", *name, pub)
	env, err := json.MarshalIndent(signing.Sign(update.PayloadType, payload, id, priv), "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	ks := &signing.KeySet{Version: 1, Keys: []signing.Key{{KeyID: id, Role: "release", Public: pub, NotBefore: now.Add(-time.Minute)}}}
	if _, err := signing.Verify(env, ks, "release", update.PayloadType, now); err != nil {
		log.Fatalf("the signed manifest does not verify: %v", err)
	}
	path := orDefault(*out, filepath.Join(*dist, "release.json"))
	write(path, append(env, '\n'))
	fmt.Printf("wrote %s (%s, %d artifacts, expires %s, signed by %s)\n", path, *version, len(arts), rel.ExpiresAt, id)
}

// artifacts lists the archives in checksums.txt for this version.
func artifacts(dist, version, base string) ([]update.Artifact, error) {
	f, err := os.Open(filepath.Join(dist, "checksums.txt"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	osName := map[string]update.ArtifactOS{"darwin": "macos", "linux": "linux", "windows": "windows"}
	var out []update.Artifact
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		sum, file := fields[0], fields[1]
		m := archiveRE.FindStringSubmatch(file)
		if m == nil || m[1] != version {
			continue
		}
		info, err := os.Stat(filepath.Join(dist, file))
		if err != nil {
			return nil, fmt.Errorf("%s is in checksums.txt but not in %s: %w", file, dist, err)
		}
		out = append(out, update.Artifact{OS: osName[m[2]], Arch: update.ArtifactArch(m[3]), URL: base + "/" + file,
			SHA256: "sha256:" + sum, Size: info.Size(), Format: update.ArtifactFormat(m[4]), Binaries: binaries})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no privometry_%s_* archives in %s/checksums.txt", version, dist)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
}
