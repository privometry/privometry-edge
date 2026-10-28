// Command sign-definitions builds the adapter set and the detector pack set
// from adapter-defs/ and detectorpacks/ and signs them with a release key,
// for publishing next to a release as adapters.json and detectorpacks.json
// (see internal/definitions).
//
//	go run ./scripts/sign-definitions -key release.seed -name prod -out dist/
//	go run ./scripts/sign-definitions -out dist/    # unsigned payloads for an external signer
//
// The key file holds the base64 Ed25519 seed (32 bytes) or private key (64
// bytes). Each set's version is the SetVersion of its source folder, so bump
// it before signing changed definitions. Never commit a key file.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/detectorpacks"
	"github.com/privometry/privometry-oss/internal/definitions"
	"github.com/privometry/privometry-oss/internal/signing"
)

func main() {
	log.SetFlags(0)
	keyFile := flag.String("key", "", "file with the base64 release key seed; empty writes unsigned payloads")
	name := flag.String("name", "", "release key name, as in its key ID release:<name>:<hash>")
	out := flag.String("out", "dist", "output folder")
	minSensor := flag.String("min-sensor", "", "oldest sensor version that understands the adapter set")
	flag.Parse()

	now := time.Now()
	adapters, err := definitions.BuildAdapterSet(adapterdefs.SetVersion, now, *minSensor)
	if err != nil {
		log.Fatal(err)
	}
	detectors, err := definitions.BuildDetectorSet(detectorpacks.SetVersion, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	sets := []struct {
		kind    definitions.Kind
		ptype   string
		payload []byte
	}{
		{definitions.Adapters, definitions.AdaptersPayloadType, adapters},
		{definitions.Detectors, definitions.DetectorsPayloadType, detectors},
	}
	if *keyFile == "" {
		for _, s := range sets {
			path := filepath.Join(*out, string(s.kind)+".payload.json")
			write(path, s.payload)
			fmt.Printf("wrote %s (unsigned; sign as DSSE with payload type %s)\n", path, s.ptype)
		}
		return
	}
	if *name == "" {
		log.Fatal("-name is required with -key")
	}
	priv := readKey(*keyFile)
	pub := priv.Public().(ed25519.PublicKey)
	id := signing.KeyID("release", *name, pub)
	ks := &signing.KeySet{Version: 1, Keys: []signing.Key{{KeyID: id, Role: "release", Public: pub, NotBefore: now.Add(-time.Minute)}}}
	for _, s := range sets {
		env, err := json.MarshalIndent(signing.Sign(s.ptype, s.payload, id, priv), "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		// Check the signed set the way a sensor will before publishing it.
		if _, err := definitions.Check(definitions.Options{Keys: ks, SensorVersion: *minSensor}, env); err != nil {
			log.Fatalf("%s: %v", s.kind, err)
		}
		path := filepath.Join(*out, s.kind.File())
		write(path, append(env, '\n'))
		fmt.Printf("wrote %s (set %d, signed by %s)\n", path, s.kind.BuiltIn(), id)
	}
}

func readKey(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := signing.ParsePrivateKey(raw)
	if err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return priv
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
}
