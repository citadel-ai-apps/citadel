package hostfs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// encKeyHexBytes is 16, giving a 32-character hex key.
//
// PocketBase's --encryptionEnv requires exactly 32 characters. This is not a
// security parameter to tune upward; a longer key is rejected at startup.
const encKeyHexBytes = 16

// EncKeyRef is the filename under control/keys that holds a tenant's key. The
// tenant row stores this reference, never the key itself.
func EncKeyRef(tenantID string) string { return tenantID + ".key" }

// legacySuCredRef is where a superuser password used to be stored. Nothing
// writes it any more: the control plane signs PocketBase tokens from pb_data
// instead (internal/pbauth). Old files are removed by
// RemoveLegacySuperuserCredential.
func legacySuCredRef(tenantID string) string { return tenantID + ".su" }

func (f *FS) keyPath(ref string) string { return filepath.Join(f.cfg.KeysDir(), ref) }

// EnsureKeys generates a tenant's encryption key if it does not exist.
// Idempotent: regenerating the encryption key would make the existing pb_data
// settings undecryptable.
func (f *FS) EnsureKeys(tenantID string) error {

	if err := os.MkdirAll(f.cfg.KeysDir(), 0o700); err != nil {

		return err
	}
	return f.ensureSecret(EncKeyRef(tenantID), func() (string, error) {

		return randomHex(encKeyHexBytes)
	})
}

func (f *FS) ensureSecret(ref string, gen func() (string, error)) error {

	path := f.keyPath(ref)
	if _, err := os.Stat(path); err == nil {

		return nil

	} else if !os.IsNotExist(err) {

		return err
	}
	val, err := gen()
	if err != nil {

		return err
	}
	// Temp-file + rename with the final mode set at creation, so the secret is
	// never briefly world-readable.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(val+"\n"), 0o600); err != nil {

		return err
	}
	if err := os.Rename(tmp, path); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// EncryptionKey reads a tenant's PB_ENCRYPTION_KEY.
func (f *FS) EncryptionKey(tenantID string) (string, error) {

	b, err := os.ReadFile(f.keyPath(EncKeyRef(tenantID)))
	if err != nil {

		return "", fmt.Errorf("hostfs: read encryption key for %s: %w", tenantID, err)
	}
	key := strings.TrimSpace(string(b))
	if len(key) != encKeyHexBytes*2 {

		return "", fmt.Errorf("hostfs: encryption key for %s is %d chars, PocketBase requires %d",
			tenantID, len(key), encKeyHexBytes*2)
	}
	return key, nil
}

// RemoveLegacySuperuserCredential deletes a superuser password stored by an
// earlier control plane. Idempotent. No superuser password is handed out or
// kept: the owner opens /_/ through the portal, and the health check signs its
// own token.
func (f *FS) RemoveLegacySuperuserCredential(tenantID string) error {

	err := os.Remove(f.keyPath(legacySuCredRef(tenantID)))
	if err != nil && !os.IsNotExist(err) {

		return err
	}
	return nil
}

// RemoveKeys deletes a tenant's secrets. Called on purge, never on a plain
// stop: the encryption key is the only way to read the tenant's settings back.
func (f *FS) RemoveKeys(tenantID string) error {

	for _, ref := range []string{EncKeyRef(tenantID), legacySuCredRef(tenantID)} {

		if err := os.Remove(f.keyPath(ref)); err != nil && !os.IsNotExist(err) {

			return err
		}
	}
	return nil
}

func randomHex(n int) (string, error) {

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {

		return "", err
	}
	return hex.EncodeToString(b), nil
}
