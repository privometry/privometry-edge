//go:build windows

package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/privometry/privometry-edge/internal/platform"
)

func TestDPAPIStore(t *testing.T) {
	dir := t.TempDir()
	env := platform.Env{GOOS: "windows", Home: dir, Getenv: func(k string) string {
		return map[string]string{"PRIVOMETRY_HOME": dir}[k]
	}}
	s, err := Open(env, "auto")
	if err != nil || s.Kind() != KindDPAPI {
		t.Fatalf("auto on Windows: %v %v", s, err)
	}
	secret := []byte("device-key-bytes")
	if err := s.Put("device-key", secret); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "keys", "device-key"))
	if bytes.Contains(raw, secret) {
		t.Error("the file holds the secret in the clear")
	}
	if got, err := s.Get("device-key"); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("get: %q %v", got, err)
	}
	// A sealed file copied under another name does not open: the name is entropy.
	os.WriteFile(filepath.Join(dir, "keys", "hash-key"), raw, 0o600)
	if _, err := s.Get("hash-key"); err == nil {
		t.Error("a sealed file must only open under its own name")
	}
	if err := s.Delete("device-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("device-key"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}
