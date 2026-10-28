package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/privometry/privometry-oss/internal/platform"
)

func fileEnv(t *testing.T) (platform.Env, string) {
	data := t.TempDir()
	return platform.Env{GOOS: "linux", Home: t.TempDir(), Getenv: func(k string) string {
		if k == "PRIVOMETRY_HOME" {
			return data
		}
		return ""
	}}, data
}

func TestFileStore(t *testing.T) {
	env, data := fileEnv(t)
	s, err := Open(env, "auto") // no D-Bus session: falls back to files
	if err != nil || s.Kind() != KindFile {
		t.Fatalf("store %v, %v", s, err)
	}
	if _, err := s.Get("cli-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	secret := []byte{0, 1, 2, 0xff}
	if err := s.Put("cli-key", secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("cli-key")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("got %x, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{filepath.Join(data, "keys"): 0o700, filepath.Join(data, "keys", "cli-key"): 0o600} {
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s: mode %v, want %v", path, fi.Mode().Perm(), want)
			}
		}
	}
	if err := s.Delete("cli-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("cli-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.Put("../escape", secret); err == nil {
		t.Error("names must not be paths")
	}
	if _, err := Open(env, "keychain"); err == nil {
		t.Error("keychain must fail where there is none")
	}
}

// TestMacOSKeychain writes to the real login keychain under a test service name
// and removes the item again. Run with PRIVOMETRY_KEYCHAIN_TEST=1 on a Mac.
func TestMacOSKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("PRIVOMETRY_KEYCHAIN_TEST") != "1" {
		t.Skip("set PRIVOMETRY_KEYCHAIN_TEST=1 on macOS to use the real keychain")
	}
	s := &macOS{service: Service + ".test", tool: "/usr/bin/security"}
	defer s.Delete("roundtrip")
	secret := []byte("sealed key \x00 bytes")
	if err := s.Put("roundtrip", secret); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("roundtrip", append(secret, '!')); err != nil {
		t.Fatal("updating an item:", err)
	}
	got, err := s.Get("roundtrip")
	if err != nil || !bytes.Equal(got, append(secret, '!')) {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := s.Delete("roundtrip"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("roundtrip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
