// Package keystore keeps Privometry's secrets (the CLI sign-in key sealed with
// the person's PIN, the device key, the organization hash key) in the OS
// keychain: the macOS login keychain through /usr/bin/security, the Secret
// Service on Linux through secret-tool, or on Windows files sealed with DPAPI
// under the user's logon. Where none is available they go in files only the
// user can read.
//
// Secrets never appear on a command line: they are written to the keychain
// tools' standard input.
package keystore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/privometry/privometry-edge/internal/platform"
)

// Service names Privometry's items in the OS keychain.
const Service = "dev.privometry"

// Kinds of store.
const (
	KindMacOS         = "macos-keychain"
	KindSecretService = "secret-service"
	KindDPAPI         = "windows-dpapi"
	KindFile          = "file"
)

// ErrNotFound means the store holds no secret of that name.
var ErrNotFound = errors.New("keystore: not found")

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Store keeps named secrets.
type Store interface {
	Kind() string
	Put(name string, secret []byte) error
	Get(name string) ([]byte, error)
	Delete(name string) error
}

// Open returns the store of the given kind: "auto" (or "") picks the OS
// keychain when there is one, "keychain" requires it, and "file" or one of the
// Kind values names a store.
func Open(env platform.Env, kind string) (Store, error) {
	switch kind {
	case "", "auto":
		if s := osKeychain(env); s != nil {
			return s, nil
		}
		return fileStore(env)
	case "keychain":
		if s := osKeychain(env); s != nil {
			return s, nil
		}
		return nil, errors.New("keystore: no OS keychain here (macOS keychain, secret-tool with a Secret Service on Linux, or DPAPI on Windows)")
	case KindMacOS:
		return &macOS{service: Service, tool: "/usr/bin/security"}, nil
	case KindSecretService:
		return &secretService{service: Service}, nil
	case KindDPAPI:
		if s := dpapiStore(env); s != nil {
			return s, nil
		}
		return nil, errors.New("keystore: DPAPI is only available on Windows")
	case KindFile:
		return fileStore(env)
	}
	return nil, fmt.Errorf("keystore: unknown kind %q (auto, keychain or file)", kind)
}

func osKeychain(env platform.Env) Store {
	switch env.GOOS {
	case "darwin":
		if _, err := os.Stat("/usr/bin/security"); err == nil {
			return &macOS{service: Service, tool: "/usr/bin/security"}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil && env.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return &secretService{service: Service}
		}
	case "windows":
		return dpapiStore(env)
	}
	return nil
}

func checkName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("keystore: bad secret name %q", name)
	}
	return nil
}

// ---- macOS login keychain

type macOS struct {
	service string
	tool    string
}

func (m *macOS) Kind() string { return KindMacOS }

func (m *macOS) Put(name string, secret []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	// "security -i" reads commands from standard input, so the secret stays off the command line. Hex keeps it to
	// characters the command parser takes as one word.
	cmd := exec.Command(m.tool, "-i") //nolint:gosec // fixed tool; the secret goes on standard input, not the command line
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %s -a %s -l privometry-%s -w %s\n",
		m.service, name, name, hex.EncodeToString(secret)))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keystore: macOS keychain: %w: %s", err, strings.TrimSpace(out.String()))
	}
	// Interactive mode exits 0 even when a command fails, so read the item back.
	got, err := m.Get(name)
	if err != nil || !bytes.Equal(got, secret) {
		return fmt.Errorf("keystore: macOS keychain did not keep %s: %s", name, strings.TrimSpace(out.String()))
	}
	return nil
}

func (m *macOS) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	out, err := exec.Command(m.tool, "find-generic-password", "-s", m.service, "-a", name, "-w").Output() //nolint:gosec // fixed tool and arguments: our service and key names
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 { // errSecItemNotFound
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: macOS keychain: %w", err)
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func (m *macOS) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := exec.Command(m.tool, "delete-generic-password", "-s", m.service, "-a", name).Run() //nolint:gosec // fixed tool and arguments: our service and key names
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return nil
	}
	return err
}

// ---- Secret Service (GNOME Keyring, KWallet) through secret-tool

type secretService struct{ service string }

func (s *secretService) Kind() string { return KindSecretService }

func (s *secretService) Put(name string, secret []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	cmd := exec.Command("secret-tool", "store", "--label=privometry-"+name, "service", s.service, "account", name) //nolint:gosec // fixed tool; the secret goes on standard input
	cmd.Stdin = strings.NewReader(hex.EncodeToString(secret))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keystore: secret-tool: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *secretService) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	out, err := exec.Command("secret-tool", "lookup", "service", s.service, "account", name).Output() //nolint:gosec // fixed tool and arguments: our service and key names
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: secret-tool: %w", err)
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func (s *secretService) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return exec.Command("secret-tool", "clear", "service", s.service, "account", name).Run() //nolint:gosec // fixed tool and arguments: our service and key names
}

// ---- files only the user can read

type files struct{ dir string }

func fileStore(env platform.Env) (Store, error) {
	data, err := env.DataDir()
	if err != nil {
		return nil, err
	}
	return &files{dir: filepath.Join(data, "keys")}, nil
}

func (f *files) Kind() string { return KindFile }

func (f *files) Put(name string, secret []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(f.dir, 0o700); err != nil { //nolint:gosec // a folder: 0700 is owner-only
		return err
	}
	tmp, err := os.CreateTemp(f.dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(secret); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(f.dir, name))
}

func (f *files) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (f *files) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(f.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
