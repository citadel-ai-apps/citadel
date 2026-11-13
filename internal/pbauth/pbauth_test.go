package pbauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const testEncKey = "0123456789abcdef0123456789abcdef"

// The shapes below are the ones observed on pb-hardened 0.22.55 and 0.40.4 in
// the development VM, reduced to the columns this package reads.

func modernDB(t *testing.T, dir string) {

	t.Helper()
	exec(t, dir,
		`CREATE TABLE _collections (id TEXT PRIMARY KEY, name TEXT, options JSON)`,
		`INSERT INTO _collections VALUES ('pbc_3142635823', '_superusers',
			'{"authToken":{"secret":"collsecret","duration":86400}}')`,
		`CREATE TABLE _superusers (id TEXT PRIMARY KEY, email TEXT, tokenKey TEXT, created TEXT)`,
		`INSERT INTO _superusers VALUES ('seat1', 'admin-t1@example.invalid', 'seatkey', '2026-02-01')`,
		`INSERT INTO _superusers VALUES ('first', 'alice@example.com', 'alicekey', '2026-01-01')`,
	)
}

func legacyDB(t *testing.T, dir, settings string) {

	t.Helper()
	exec(t, dir,
		`CREATE TABLE _params (id TEXT PRIMARY KEY, key TEXT, value JSON)`,
		`CREATE TABLE _admins (id TEXT PRIMARY KEY, email TEXT, tokenKey TEXT, created TEXT)`,
		`INSERT INTO _admins VALUES ('seat1', 'admin-t1@example.invalid', 'seatkey', '2026-01-01')`,
	)
	db := open(t, dir)
	if _, err := db.Exec(`INSERT INTO _params VALUES ('p1', 'settings', ?)`, settings); err != nil {

		t.Fatal(err)
	}
}

func open(t *testing.T, dir string) *sql.DB {

	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "data.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func exec(t *testing.T, dir string, stmts ...string) {

	t.Helper()
	db := open(t, dir)
	for _, s := range stmts {

		if _, err := db.Exec(s); err != nil {

			t.Fatalf("%s: %v", s, err)
		}
	}
}

// verify checks the signature with the key PocketBase would use and returns the
// claims.
func verify(t *testing.T, tok, key string) map[string]any {

	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {

		t.Fatalf("token %q is not a JWT", tok)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {

		t.Fatalf("signature does not verify with key %q", key)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {

		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {

		t.Fatal(err)
	}
	return claims
}

func encrypt(t *testing.T, plain string) string {

	t.Helper()
	block, err := aes.NewCipher([]byte(testEncKey))
	if err != nil {

		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {

		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {

		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil))
}

func TestMintModernSeat(t *testing.T) {

	dir := t.TempDir()
	modernDB(t, dir)
	tok, err := Mint(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"},
		BySeatEmail(SeatEmail("t1")), time.Minute)
	if err != nil {

		t.Fatal(err)
	}
	if tok.RecordID != "seat1" || tok.CollectionID != "pbc_3142635823" || tok.Legacy {

		t.Fatalf("token = %+v", tok)
	}
	c := verify(t, tok.Token, "seatkey"+"collsecret")
	if c["type"] != "auth" || c["id"] != "seat1" || c["collectionId"] != "pbc_3142635823" || c["refreshable"] != true {

		t.Fatalf("claims = %v", c)
	}
	exp := int64(c["exp"].(float64))
	if d := time.Until(time.Unix(exp, 0)); d <= 0 || d > time.Minute {

		t.Fatalf("exp is %v away, want within a minute", d)
	}
}

func TestMintAnySuperuserIsNotTiedToTheSeat(t *testing.T) {

	dir := t.TempDir()
	modernDB(t, dir)
	exec(t, dir, `DELETE FROM _superusers WHERE id = 'seat1'`)

	tok, err := Mint(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0)
	if err != nil {

		t.Fatal(err)
	}
	if tok.RecordID != "first" {

		t.Fatalf("record = %q, want the oldest remaining superuser", tok.RecordID)
	}
	verify(t, tok.Token, "alicekey"+"collsecret")

	_, err = Mint(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"}, BySeatEmail(SeatEmail("t1")), 0)
	if !errors.Is(err, ErrNoSuperuser) {

		t.Fatalf("seat lookup after delete: err = %v, want ErrNoSuperuser", err)
	}
}

func TestMintLegacyPlainAndEncryptedSettings(t *testing.T) {

	settings := `{"meta":{"appName":"Acme"},"adminAuthToken":{"secret":"adminsecret","duration":1209600}}`
	for name, stored := range map[string]string{
		"plain":     settings,
		"encrypted": encrypt(t, settings),
	} {

		t.Run(name, func(t *testing.T) {

			dir := t.TempDir()
			legacyDB(t, dir, stored)
			tok, err := Mint(context.Background(),
				Source{DataDir: dir, PBVersion: "0.22.55", EncryptionKey: testEncKey}, AnySuperuser(), 0)
			if err != nil {

				t.Fatal(err)
			}
			c := verify(t, tok.Token, "seatkey"+"adminsecret")
			if c["type"] != "admin" || c["id"] != "seat1" || !tok.Legacy {

				t.Fatalf("claims = %v, token = %+v", c, tok)
			}
			if _, ok := c["collectionId"]; ok {

				t.Fatalf("legacy claims carry a collectionId: %v", c)
			}
		})
	}
}

// Rehearsal signs for the TARGET version from data the old binary wrote. The
// 0.23 migration keeps the admin's id and tokenKey and carries the admin token
// secret into _superusers, so the same key verifies.
func TestMintModernClaimsFromLegacyData(t *testing.T) {

	dir := t.TempDir()
	legacyDB(t, dir, encrypt(t, `{"adminAuthToken":{"secret":"adminsecret"}}`))
	tok, err := Mint(context.Background(),
		Source{DataDir: dir, PBVersion: "0.38.2", EncryptionKey: testEncKey}, AnySuperuser(), 0)
	if err != nil {

		t.Fatal(err)
	}
	c := verify(t, tok.Token, "seatkey"+"adminsecret")
	if c["type"] != "auth" || c["collectionId"] != SuperusersCollectionID {

		t.Fatalf("claims = %v", c)
	}
}

func TestMintRefuses(t *testing.T) {

	ctx := context.Background()

	t.Run("empty signing key", func(t *testing.T) {

		dir := t.TempDir()
		modernDB(t, dir)
		exec(t, dir,
			`UPDATE _collections SET options = '{"authToken":{"secret":""}}'`,
			`UPDATE _superusers SET tokenKey = ''`)
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); !errors.Is(err, ErrNoSigningKey) {

			t.Fatalf("err = %v, want ErrNoSigningKey", err)
		}
	})

	t.Run("encrypted settings without a key", func(t *testing.T) {

		dir := t.TempDir()
		legacyDB(t, dir, encrypt(t, `{"adminAuthToken":{"secret":"s"}}`))
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.22.55"}, AnySuperuser(), 0); err == nil {

			t.Fatal("minted without the encryption key")
		}
	})

	t.Run("oversized value", func(t *testing.T) {

		dir := t.TempDir()
		modernDB(t, dir)
		exec(t, dir, `UPDATE _superusers SET tokenKey = '`+strings.Repeat("k", maxValueLen+1)+`'`)
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); err == nil {

			t.Fatal("accepted an oversized value from pb_data")
		}
	})

	// pb_data is tenant-writable: a data.db that points elsewhere must not be
	// followed.
	t.Run("symlinked database", func(t *testing.T) {

		real := t.TempDir()
		modernDB(t, real)
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(real, "data.db"), filepath.Join(dir, "data.db")); err != nil {

			t.Fatal(err)
		}
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); err == nil {

			t.Fatal("followed a symlinked data.db")
		}
	})

	// The data directory itself reached through a symlinked parent is the
	// same attack one level up.
	t.Run("database outside the data directory", func(t *testing.T) {

		real := t.TempDir()
		modernDB(t, real)
		dir := t.TempDir()
		if err := os.Symlink(real, filepath.Join(dir, "sub")); err != nil {

			t.Fatal(err)
		}
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); err == nil {

			t.Fatal("minted with no data.db of its own")
		}
	})

	// A view is tenant-written SQL that would execute on the host.
	t.Run("collection table replaced by a view", func(t *testing.T) {

		dir := t.TempDir()
		modernDB(t, dir)
		exec(t, dir,
			`ALTER TABLE _collections RENAME TO real_collections`,
			`CREATE VIEW _collections AS SELECT * FROM real_collections`)
		if _, err := Mint(ctx, Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); err == nil {

			t.Fatal("read the signing secret through a tenant-defined view")
		}
	})

	t.Run("no database", func(t *testing.T) {

		if _, err := Mint(ctx, Source{DataDir: t.TempDir(), PBVersion: "0.40.4"}, AnySuperuser(), 0); err == nil {

			t.Fatal("minted from an empty pb_data")
		}
	})
}

func TestIsLegacy(t *testing.T) {

	for v, want := range map[string]bool{"0.22.55": true, "0.23.0": false, "0.40.4": false, "1.0.0": false, "junk": false} {

		if got := IsLegacy(v); got != want {

			t.Errorf("IsLegacy(%q) = %v, want %v", v, got, want)
		}
	}
}
