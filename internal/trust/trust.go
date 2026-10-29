// Package trust holds the key sets built into this binary. Release keys sign
// self-update manifests, adapter definition sets and Privometry's detector
// pack sets; root keys sign each region's key set, which names the policy and
// license keys enrolled devices verify bundles with. See keys/README.md.
package trust

import (
	"embed"
	"errors"
	"io/fs"

	"github.com/privometry/privometry-edge/internal/signing"
)

// ErrNoReleaseKeys means this build carries no release keys, so it cannot
// verify anything signed with one.
var ErrNoReleaseKeys = errors.New("this build has no release signing keys")

//go:embed keys
var keysFS embed.FS

// ErrNoRootKeys means this build carries no root keys, so an enrolled device
// pins the key set it gets at enrollment instead of verifying it.
var ErrNoRootKeys = errors.New("this build has no root keys")

// RootKeys returns the root key set built into this binary.
func RootKeys() (*signing.KeySet, error) {
	raw, err := keysFS.ReadFile("keys/root-keys.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoRootKeys
	}
	if err != nil {
		return nil, err
	}
	return signing.ParseKeySet(raw)
}

// ReleaseKeys returns the release key set built into this binary.
func ReleaseKeys() (*signing.KeySet, error) {
	if noReleaseKeys {
		return nil, ErrNoReleaseKeys
	}
	raw, err := keysFS.ReadFile("keys/release-keys.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoReleaseKeys
	}
	if err != nil {
		return nil, err
	}
	return signing.ParseKeySet(raw)
}

// noReleaseKeys makes ReleaseKeys answer as a build that carries none.
var noReleaseKeys bool

// WithoutReleaseKeys makes ReleaseKeys answer as a build that carries no
// release keys until the test ends, for tests of that refusal. Tests that use
// it must not run in parallel with tests that need the built-in keys.
func WithoutReleaseKeys(t interface{ Cleanup(func()) }) {
	noReleaseKeys = true
	t.Cleanup(func() { noReleaseKeys = false })
}
