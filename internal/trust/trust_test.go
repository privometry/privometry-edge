package trust_test

import (
	"errors"
	"testing"

	"github.com/privometry/privometry-oss/internal/trust"
)

// The key sets that ship must parse and hold only keys of their own role: a
// test key or a key of another role here would be trusted by every binary.
func TestShippedKeySets(t *testing.T) {
	release, err := trust.ReleaseKeys()
	if err != nil {
		t.Fatalf("release keys: %v", err)
	}
	if len(release.Keys) == 0 {
		t.Fatal("release-keys.json holds no keys")
	}
	for _, k := range release.Keys {
		if k.Role != "release" {
			t.Errorf("release-keys.json holds %s, role %s", k.KeyID, k.Role)
		}
	}
	root, err := trust.RootKeys()
	if errors.Is(err, trust.ErrNoRootKeys) {
		return
	}
	if err != nil {
		t.Fatalf("root keys: %v", err)
	}
	for _, k := range root.Keys {
		if k.Role != "root" {
			t.Errorf("root-keys.json holds %s, role %s", k.KeyID, k.Role)
		}
	}
}

func TestWithoutReleaseKeys(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		trust.WithoutReleaseKeys(t)
		if _, err := trust.ReleaseKeys(); !errors.Is(err, trust.ErrNoReleaseKeys) {
			t.Errorf("err %v, want ErrNoReleaseKeys", err)
		}
	})
	if _, err := trust.ReleaseKeys(); err != nil {
		t.Errorf("after the test ended: %v", err)
	}
}
