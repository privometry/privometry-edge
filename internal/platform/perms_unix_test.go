//go:build unix

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePrivateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", ".privometry")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); !errors.Is(err, ErrInsecure) {
		t.Fatalf("0755 dir: got %v, want ErrInsecure", err)
	}
}

func TestEnsurePrivateDirTightensOwnDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".privometry")
	if err := os.Mkdir(dir, 0o744); err != nil { // as launchd creates it for a log file
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("own 0744 dir should be tightened, got %v", err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("mode %v, want 0700", info.Mode().Perm())
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if err := EnsurePrivateDir(link); !errors.Is(err, ErrInsecure) {
		t.Errorf("a symlinked data dir must still be refused: %v", err)
	}
}

func TestCheckPrivateRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(link); !errors.Is(err, ErrInsecure) {
		t.Fatalf("symlink: got %v, want ErrInsecure", err)
	}
}

func TestWritableByOthers(t *testing.T) {
	dir := t.TempDir()
	for mode, want := range map[os.FileMode]bool{0o755: false, 0o775: true, 0o757: true} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		got, err := WritableByOthers(dir)
		if err != nil || got != want {
			t.Errorf("mode %#o: got %v, %v; want %v", mode, got, err, want)
		}
	}
}

// Agents may run hooks without HOME; the home folder then comes from the
// account database.
func TestCurrentEnvWithoutHome(t *testing.T) {
	want, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home folder here")
	}
	t.Setenv("HOME", "")
	env, err := CurrentEnv()
	if err != nil || env.Home != want {
		t.Errorf("CurrentEnv without HOME: %q, %v; want %q", env.Home, err, want)
	}
}
