// Command release-keygen makes a release or root signing key: the secret
// seed, and the key set that goes into internal/trust/keys so sensors trust
// it (see internal/trust/keys/README.md).
//
//	go run ./scripts/release-keygen -role release -name gh-2026 -out ~/keys
//	go run ./scripts/release-keygen -role root -name offline-a -out /Volumes/KEYS
//
// It writes <name>.<role>.seed (base64, mode 0600: the GitHub release secret,
// or the offline root key; never commit it) and <role>-keys.json (public; a
// release key set is committed as internal/trust/keys/release-keys.json).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/privometry/privometry-edge/internal/signing"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func main() {
	log.SetFlags(0)
	role := flag.String("role", "release", "release or root")
	name := flag.String("name", "", "key name, as in its key ID <role>:<name>:<hash>, for example gh-2026")
	out := flag.String("out", ".", "folder to write the seed and the key set to")
	flag.Parse()
	if *role != "release" && *role != "root" {
		log.Fatal("-role must be release or root")
	}
	if !nameRE.MatchString(*name) {
		log.Fatal("-name is required: lower case letters, digits and dashes")
	}
	seedPath := filepath.Join(*out, *name+"."+*role+".seed")
	setPath := filepath.Join(*out, *role+"-keys.json")
	for _, p := range []string{seedPath, setPath} {
		if _, err := os.Stat(p); err == nil {
			log.Fatalf("%s exists; choose another -out or -name", p)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	set, id, err := signing.KeySetDocument(*role, *name, pub, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(seedPath, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(setPath, set, 0o644); err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	fmt.Printf("Key %s\nFingerprint %s\n", id, hex.EncodeToString(sum[:]))
	fmt.Printf("Wrote %s (secret: never commit it) and %s (public).\n", seedPath, setPath)
	if *role == "release" {
		fmt.Printf("Next: store the seed as the PRIVOMETRY_RELEASE_KEY secret of the GitHub \"release\" environment, set PRIVOMETRY_RELEASE_KEY_NAME=%s there, and commit %s as internal/trust/keys/release-keys.json.\n", *name, setPath)
	} else {
		fmt.Println("Next: keep the seed offline, in two places held by two people; commit the key set as internal/trust/keys/root-keys.json.")
	}
}
