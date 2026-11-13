package hostfs

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Signer signs audit chain anchors and access attestations.
//
// ed25519 rather than an HMAC because the point of a signature here is that
// somebody OTHER than the writer can check it: an export handed to a tenant, or
// an anchor replicated to the backup store, must be verifiable without holding
// the key that produced it. A shared secret would mean the verifier could also
// forge.
type Signer struct {
	priv ed25519.PrivateKey
}

// EnsureSigner loads the signing key, generating it on first use.
//
// The key is generated once and never rotated in place: rotating it would
// invalidate every anchor and attestation ever written, which is the opposite
// of what those records are for. A rotation story means keeping the old public
// key alongside the new one, and that is not built.
func (f *FS) EnsureSigner() (*Signer, error) {

	path := f.cfg.SigningKeyPath()
	b, err := os.ReadFile(path)
	switch {

	case err == nil:
		raw, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if decErr != nil {

			return nil, fmt.Errorf("hostfs: signing key at %s is not base64: %w", path, decErr)
		}
		if len(raw) != ed25519.PrivateKeySize {

			return nil, fmt.Errorf("hostfs: signing key at %s is %d bytes, want %d",
				path, len(raw), ed25519.PrivateKeySize)
		}
		return &Signer{priv: ed25519.PrivateKey(raw)}, nil

	case os.IsNotExist(err):
		// fall through to generation

	default:
		return nil, fmt.Errorf("hostfs: read signing key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {

		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {

		return nil, fmt.Errorf("hostfs: generate signing key: %w", err)
	}
	// Temp-file + rename with the final mode set at creation, so the key is
	// never briefly world-readable.
	tmp := path + ".tmp"
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(tmp, []byte(enc+"\n"), 0o600); err != nil {

		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {

		_ = os.Remove(tmp)
		return nil, err
	}
	return &Signer{priv: priv}, nil
}

// NewSignerFromSeed builds a Signer from a deterministic seed. Tests only: it
// keeps signature assertions reproducible without writing a key to disk.
func NewSignerFromSeed(seed []byte) *Signer {

	s := make([]byte, ed25519.SeedSize)
	copy(s, seed)
	return &Signer{priv: ed25519.NewKeyFromSeed(s)}
}

// Sign returns a base64 signature over payload.
func (s *Signer) Sign(payload []byte) string {

	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, payload))
}

// PublicKey is the base64 verifying key, published alongside exports so a
// recipient can check a signature without the control plane's cooperation.
func (s *Signer) PublicKey() string {

	return base64.StdEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

// Verify checks a signature against a published public key.
func Verify(pubB64, sig string, payload []byte) bool {

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {

		return false
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {

		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, raw)
}
