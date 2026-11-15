// Package pbauth signs PocketBase superuser tokens from a tenant's pb_data, read
// on the host.
//
// This is how the control plane gets into an instance without ever holding a
// PocketBase password and without managing the instance through its own API
// (design.md INV-5): the signing secrets are rows in pb_data, so producing a
// token PocketBase will accept is a filesystem read, not an API call.
//
// Two callers, two selectors:
//
//   - the portal's admin handoff signs for the tenant's owner seat
//     (BySeatEmail), so an owner opens /_/ with their portal login alone;
//   - the data-plane health check signs for any superuser (AnySuperuser), so
//     the owner renaming, re-passwording or deleting the seat never makes a
//     healthy instance look broken.
//
// pb_data is tenant-writable and its contents are hostile input (INV-1). Every
// value read here only ever keys an HMAC over a token that goes back to the
// same tenant, the database is read through a handle opened beneath pb_data and
// never by path, and nothing is written: not a row, and not a -wal or -shm
// sidecar either (see readOnce).
package pbauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite" // the same pure-Go driver internal/store uses
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/safesqlite"
)

// Errors callers branch on.
var (
	// ErrNoSuperuser means the selector matched no account: the seat was
	// removed from inside the instance, or the instance has no superuser yet.
	ErrNoSuperuser = errors.New("pbauth: no matching superuser in pb_data")
	// ErrNoSigningKey mirrors PocketBase's own ErrMissingSigningKey.
	ErrNoSigningKey = errors.New("pbauth: signing key is empty")
)

// SuperusersCollectionID is the id PocketBase 0.23+ gives `_superusers`. It is
// read from the database whenever the collection exists; the constant is only
// used when signing 0.23+ claims from pre-0.23 data, which the 0.23 migration
// turns into that collection (rehearsal signs from the copy before it boots).
const SuperusersCollectionID = "pbc_3142635823"

// DefaultTTL is deliberately short. The token only has to survive the trip to
// the admin UI or one health request; the admin UI refreshes it into a normal
// session straight away.
const DefaultTTL = 2 * time.Minute

// maxValueLen bounds every value read from pb_data. PocketBase's own token
// keys and secrets are 50 characters.
const maxValueLen = 4096

// SeatEmail is the owner seat: the superuser created for the tenant's owner by
// the one-shot before first boot. Its address is in .invalid so it can never
// receive mail, and its password is discarded at creation.
func SeatEmail(tenantID string) string { return "admin-" + tenantID + "@example.invalid" }

// IsLegacy reports whether a PocketBase version predates the 0.23 rework:
// `_admins` instead of `_superusers`, `admin create` instead of
// `superuser upsert`, and a different token shape.
func IsLegacy(version string) bool {

	var major, minor int
	if n, _ := fmt.Sscanf(version, "%d.%d", &major, &minor); n < 2 {

		return false
	}
	return major == 0 && minor < 23
}

// Source is where to sign from.
type Source struct {
	// DataDir is the host path of pb_data.
	DataDir string
	// PBVersion selects the claim shape PocketBase will check: the version
	// that will SERVE the token, which during rehearsal is the target.
	PBVersion string
	// EncryptionKey decrypts pre-0.23 settings, where the admin token secret
	// lives. Unused from 0.23 on.
	EncryptionKey string
}

// Selector picks the superuser to sign for.
type Selector struct {
	email string
}

// BySeatEmail selects one account by email.
func BySeatEmail(email string) Selector { return Selector{email: email} }

// AnySuperuser selects the oldest superuser. PocketBase refuses to delete the
// last one, so a running instance always has one.
func AnySuperuser() Selector { return Selector{} }

// Token is a signed superuser token and the record it was signed for.
type Token struct {
	Token        string `json:"token"`
	RecordID     string `json:"id"`
	CollectionID string `json:"collectionId,omitempty"`
	Email        string `json:"email"`
	// Legacy is true when the claims are pre-0.23 admin claims.
	Legacy bool `json:"-"`
}

// account is what is read from pb_data.
type account struct {
	id, email, tokenKey string
	collectionID        string
	secret              string
}

// ErrNotTimeBoxable is MintStatic on a pre-0.23 runtime, whose admin tokens
// carry no refreshable claim: the admin UI would renew one for as long as the
// tab stays open, so no expiry the caller sets would hold.
var ErrNotTimeBoxable = errors.New("pbauth: this PocketBase version cannot issue a token that stops at a set time")

// Mint signs a superuser token valid for ttl. The admin UI refreshes it into an
// ordinary session.
func Mint(ctx context.Context, src Source, sel Selector, ttl time.Duration) (Token, error) {

	return mint(ctx, src, sel, ttl, true)
}

// MintStatic signs a superuser token that dies at ttl: refreshable is false, so
// PocketBase's auth-refresh hands the same token back instead of a new one, and
// the admin UI session ends when it does. This is what break-glass hands an
// operator — PocketBase's own impersonation tokens work the same way.
//
// 0.23+ only; ErrNotTimeBoxable otherwise.
func MintStatic(ctx context.Context, src Source, sel Selector, ttl time.Duration) (Token, error) {

	if IsLegacy(src.PBVersion) {

		return Token{}, ErrNotTimeBoxable
	}
	return mint(ctx, src, sel, ttl, false)
}

func mint(ctx context.Context, src Source, sel Selector, ttl time.Duration, refreshable bool) (Token, error) {

	if ttl <= 0 {

		ttl = DefaultTTL
	}
	acc, err := read(ctx, src, sel)
	if err != nil {

		return Token{}, err
	}
	key := acc.tokenKey + acc.secret
	if key == "" {

		return Token{}, ErrNoSigningKey
	}
	legacy := IsLegacy(src.PBVersion)
	exp := time.Now().Add(ttl).Unix()
	var claims map[string]any
	if legacy {

		claims = map[string]any{"id": acc.id, "type": "admin", "exp": exp}

	} else {

		if acc.collectionID == "" {

			acc.collectionID = SuperusersCollectionID
		}
		claims = map[string]any{
			"id": acc.id, "type": "auth", "collectionId": acc.collectionID,
			"refreshable": refreshable, "exp": exp,
		}
	}
	tok, err := signHS256(claims, key)
	if err != nil {

		return Token{}, err
	}
	return Token{Token: tok, RecordID: acc.id, CollectionID: acc.collectionID, Email: acc.email, Legacy: legacy}, nil
}

// Exists reports whether the selector matches an account in pb_data.
func Exists(ctx context.Context, src Source, sel Selector) (bool, error) {

	_, err := read(ctx, src, sel)
	if errors.Is(err, ErrNoSuperuser) {

		return false, nil
	}
	return err == nil, err
}

// read loads the selected account and the collection-level secret, following
// whichever schema the database actually has rather than the version label:
// rehearsal signs 0.23+ claims from data a 0.22 binary last wrote.
func read(ctx context.Context, src Source, sel Selector) (account, error) {

	acc, err := readOnce(ctx, src, sel)
	if isTornRead(err) {

		// immutable=1 promises SQLite the file does not change, and PocketBase
		// checkpointing into it mid-read breaks that promise. The read is a
		// handful of pages, so one retry clears a collision with a checkpoint.
		// The retry opens the file afresh, with every check, rather than
		// trusting a path that was only checked the first time.
		acc, err = readOnce(ctx, src, sel)
	}
	return acc, err
}

// readOnce opens data.db WITHOUT SQLite's locking and reads the account.
//
// The file is opened once, beneath DataDir, through hostfs.OpenRegularUnder,
// and SQLite reads that handle through safesqlite rather than a path. A check
// on the path followed by an open of the path is a race: the health check runs
// this every 500ms and sends the token it signs to the tenant's own hostname,
// so a tenant that swapped data.db for a symlink to another tenant's database
// between the two would be handed a superuser token for that tenant.
//
// immutable=1 is the other half. The pb_data being read is normally open in a
// running PocketBase under gVisor, and gVisor keeps fcntl locks inside the
// sandbox. A normal host-side connection therefore believes it is alone:
// it rebuilds -shm on open and, as the "last" connection, checkpoints and
// unlinks -wal and -shm on close, underneath the live instance, which then
// fails every query with SQLITE_IOERR_SHORT_READ (design.md INV-20). With
// immutable SQLite takes no locks and never creates, reads or removes a
// sidecar.
//
// The price is that only checkpointed pages are visible, not the WAL. That is
// acceptable for what is read here: the owner seat is created by the one-shot
// with the instance stopped (so it is checkpointed when that process exits),
// superusers and the collection secret change rarely, and PocketBase
// auto-checkpoints every ~1000 pages.
func readOnce(ctx context.Context, src Source, sel Selector) (account, error) {

	f, _, err := hostfs.OpenRegularUnder(src.DataDir, "data.db")
	if err != nil {

		return account{}, fmt.Errorf("pbauth: %w", err)
	}
	defer f.Close()
	sdb, err := safesqlite.Open(f, "")
	if err != nil {

		return account{}, err
	}
	defer sdb.Close()
	db := sdb.DB

	modern, err := hasTable(ctx, db, "_superusers")
	if err != nil {

		return account{}, err
	}
	// Every table read below must be a table. A view is tenant-written SQL,
	// and it would run here, on the host.
	need := []string{"_params", "_admins"}
	if modern {

		need = []string{"_collections", "_superusers"}
	}
	for _, name := range need {

		ok, err := hasTable(ctx, db, name)
		if err != nil {

			return account{}, err
		}
		if !ok {

			return account{}, fmt.Errorf("pbauth: %s is missing or is not a table", name)
		}
	}
	var acc account
	if modern {

		acc, err = readModern(ctx, db, sel)

	} else {

		acc, err = readLegacy(ctx, db, sel, src.EncryptionKey)
	}
	if err != nil {

		return account{}, err
	}
	for _, v := range []string{acc.id, acc.email, acc.tokenKey, acc.collectionID, acc.secret} {

		if len(v) > maxValueLen {

			return account{}, fmt.Errorf("pbauth: a value in pb_data exceeds %d bytes", maxValueLen)
		}
	}
	return acc, nil
}

// isTornRead reports whether err looks like an immutable read that raced a
// PocketBase checkpoint writing into the same file.
func isTornRead(err error) bool {

	var se *sqlite.Error
	if !errors.As(err, &se) {

		return false
	}
	switch se.Code() & 0xff {

	case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
		return true
	}
	return se.Code() == sqlite3.SQLITE_IOERR_SHORT_READ
}

func hasTable(ctx context.Context, db *sql.DB, name string) (bool, error) {

	var n int
	err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&n)
	return n > 0, err
}

func readModern(ctx context.Context, db *sql.DB, sel Selector) (account, error) {

	var acc account
	var secret sql.NullString
	err := db.QueryRowContext(ctx,
		"SELECT id, json_extract(options, '$.authToken.secret') FROM _collections WHERE name = '_superusers'").
		Scan(&acc.collectionID, &secret)
	if err != nil {

		return account{}, fmt.Errorf("pbauth: read _superusers collection: %w", err)
	}
	acc.secret = secret.String
	if err := selectAccount(ctx, db, "_superusers", sel, &acc); err != nil {

		return account{}, err
	}
	return acc, nil
}

func readLegacy(ctx context.Context, db *sql.DB, sel Selector, encKey string) (account, error) {

	var acc account
	var raw string
	if err := db.QueryRowContext(ctx, "SELECT value FROM _params WHERE key = 'settings'").Scan(&raw); err != nil {

		return account{}, fmt.Errorf("pbauth: read settings: %w", err)
	}
	settings, err := decodeSettings(raw, encKey)
	if err != nil {

		return account{}, err
	}
	var s struct {
		AdminAuthToken struct {
			Secret string `json:"secret"`
		} `json:"adminAuthToken"`
	}
	if err := json.Unmarshal(settings, &s); err != nil {

		return account{}, fmt.Errorf("pbauth: parse settings: %w", err)
	}
	acc.secret = s.AdminAuthToken.Secret
	if err := selectAccount(ctx, db, "_admins", sel, &acc); err != nil {

		return account{}, err
	}
	return acc, nil
}

// selectAccount fills id, email and tokenKey. table is one of two constants,
// never caller input.
func selectAccount(ctx context.Context, db *sql.DB, table string, sel Selector, acc *account) error {

	q := "SELECT id, email, tokenKey FROM " + table
	var args []any
	if sel.email != "" {

		q += " WHERE email = ?"
		args = append(args, sel.email)
	}
	q += " ORDER BY created, id LIMIT 1"
	err := db.QueryRowContext(ctx, q, args...).Scan(&acc.id, &acc.email, &acc.tokenKey)
	if errors.Is(err, sql.ErrNoRows) {

		return ErrNoSuperuser
	}
	if err != nil {

		return fmt.Errorf("pbauth: read %s: %w", table, err)
	}
	return nil
}

// decodeSettings returns pre-0.23 settings JSON. PocketBase writes the row in
// plain JSON until settings are first saved, and encrypted after that when it
// runs with an encryption key, so both spellings occur on one instance's life.
// The encrypted form is base64(nonce || AES-256-GCM ciphertext).
func decodeSettings(raw, encKey string) ([]byte, error) {

	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {

		return []byte(raw), nil
	}
	if encKey == "" {

		return nil, errors.New("pbauth: settings are encrypted and no encryption key was given")
	}
	ct, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {

		return nil, fmt.Errorf("pbauth: settings are neither JSON nor base64: %w", err)
	}
	block, err := aes.NewCipher([]byte(encKey))
	if err != nil {

		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {

		return nil, err
	}
	if len(ct) < gcm.NonceSize() {

		return nil, errors.New("pbauth: encrypted settings are truncated")
	}
	plain, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
	if err != nil {

		return nil, fmt.Errorf("pbauth: decrypt settings: %w", err)
	}
	return plain, nil
}

func signHS256(claims map[string]any, key string) (string, error) {

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {

		return "", err
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// AdminUIEntry is the localStorage entry the PocketBase admin UI reads its
// session from, for a token minted for that UI. Version-specific, read from
// the shipped ui/dist bundles:
//
//   - 0.23+: key `__pb_superusers__` + the UI's path without its trailing
//     slash, so `__pb_superusers__/_` at /_/; value {token, record}.
//   - 0.22: key `pb_admin_auth`; value {token, model}.
//
// The UI refreshes the token on load, which is what turns this short-lived
// token into an ordinary session.
func AdminUIEntry(tok Token) (key, value string, err error) {

	var v any
	if tok.Legacy {

		key = "pb_admin_auth"
		v = map[string]any{"token": tok.Token, "model": map[string]any{"id": tok.RecordID, "email": tok.Email}}

	} else {

		key = "__pb_superusers__/_"
		v = map[string]any{"token": tok.Token, "record": map[string]any{
			"id": tok.RecordID, "email": tok.Email,
			"collectionId": tok.CollectionID, "collectionName": "_superusers",
		}}
	}
	b, err := json.Marshal(v)
	if err != nil {

		return "", "", err
	}
	return key, string(b), nil
}
