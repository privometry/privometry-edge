// Package accountclient is the CLI side of the account API (specs/account-api/v1):
// the person's sign-in key, the proofs it signs, the API client, and the
// account this machine is signed up with.
package accountclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// The CLI key is the person's sign-in key (credential type cli_key). This build
// keeps it in software: an Ed25519 key sealed with a key derived from the
// person's PIN, stored in the OS keychain. Anyone who copies the sealed key can
// try PINs offline, which is why the account API is told its protection is
// "software"; keys held by the Secure Enclave or a TPM come later.

// PINMinLength is the shortest PIN accepted. Longer passphrases are better.
const PINMinLength = 6

// PBKDF2Iterations is the PIN stretching cost (PBKDF2-HMAC-SHA256).
const PBKDF2Iterations = 600_000

// ErrWrongPIN means the PIN does not open the sealed key.
var ErrWrongPIN = errors.New("account: wrong PIN")

// SealedKey is the CLI key as stored: the private key encrypted with
// AES-256-GCM under PBKDF2(PIN), bound to its public key.
type SealedKey struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	PublicKey  []byte `json:"public_key"` // DER SubjectPublicKeyInfo
}

// CheckPIN reports why a PIN is not acceptable, or nil.
func CheckPIN(pin string) error {
	if utf8.RuneCountInString(pin) < PINMinLength {
		return fmt.Errorf("a PIN needs at least %d characters", PINMinLength)
	}
	return nil
}

// NewCLIKey generates an Ed25519 key.
func NewCLIKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// Seal encrypts the key with the PIN.
func Seal(priv ed25519.PrivateKey, pin string) ([]byte, error) {
	if err := CheckPIN(pin); err != nil {
		return nil, err
	}
	spki, err := SPKI(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	s := SealedKey{Version: 1, KDF: "pbkdf2-sha256", Iterations: PBKDF2Iterations, Salt: make([]byte, 16), Nonce: make([]byte, 12), PublicKey: spki}
	if _, err := rand.Read(s.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(s.Nonce); err != nil {
		return nil, err
	}
	gcm, err := s.cipher(pin)
	if err != nil {
		return nil, err
	}
	s.Ciphertext = gcm.Seal(nil, s.Nonce, priv.Seed(), s.aad())
	return json.Marshal(s)
}

// Open decrypts a sealed key with the PIN.
func Open(sealed []byte, pin string) (ed25519.PrivateKey, error) {
	var s SealedKey
	if err := json.Unmarshal(sealed, &s); err != nil {
		return nil, fmt.Errorf("account: sealed key: %w", err)
	}
	if s.Version != 1 || s.KDF != "pbkdf2-sha256" || s.Iterations < 100_000 {
		return nil, fmt.Errorf("account: sealed key version %d (%s) is not supported", s.Version, s.KDF)
	}
	gcm, err := s.cipher(pin)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, s.Nonce, s.Ciphertext, s.aad())
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrWrongPIN
	}
	priv := ed25519.NewKeyFromSeed(seed)
	spki, err := SPKI(priv.Public().(ed25519.PublicKey))
	if err != nil || string(spki) != string(s.PublicKey) {
		return nil, errors.New("account: sealed key does not match its public key")
	}
	return priv, nil
}

func (s SealedKey) cipher(pin string) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, pin, s.Salt, s.Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s SealedKey) aad() []byte {
	return append([]byte("privometry-cli-key-v1:"), s.PublicKey...)
}

// SPKI is the DER SubjectPublicKeyInfo of a public key.
func SPKI(pub ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// Thumbprint is "sha256:" and the hex SHA-256 of a DER SubjectPublicKeyInfo:
// the keyid of a registration proof and its public_key_sha256.
func Thumbprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])
}
