package account

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privometry/privometry-edge/internal/platform"
)

// KeyName is the keystore name of the sealed CLI key.
const KeyName = "cli-key"

// ErrNotSignedUp means this machine has no account yet.
var ErrNotSignedUp = errors.New("this machine is not signed up; run privometry login")

// State is the account this machine is signed up with, kept in account.json in
// the data directory. It holds no secrets: the sealed key is in the keystore.
type State struct {
	APIBaseURL   string    `json:"api_base_url"`
	Region       string    `json:"region"`
	OrgID        string    `json:"org_id"`
	OrgName      string    `json:"org_name"`
	OrgSlug      string    `json:"org_slug"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	CredentialID string    `json:"credential_id"`
	Keystore     string    `json:"keystore"` // the store kind that holds the sealed key
	RegisteredAt time.Time `json:"registered_at"`
}

func statePath(env platform.Env) (string, error) {
	dir, err := env.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "account.json"), nil
}

// LoadState reads account.json.
func LoadState(env platform.Env) (*State, error) {
	path, err := statePath(env)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotSignedUp
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("account: %s: %w", path, err)
	}
	return &s, nil
}

// SaveState writes account.json, readable only by the user.
func SaveState(env platform.Env, s *State) error {
	path, err := statePath(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
