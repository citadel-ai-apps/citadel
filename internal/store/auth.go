package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ErrCredentialNotFound is returned when a principal has no portal password set.
var ErrCredentialNotFound = errors.New("store: principal has no credential")

// ErrTokenNotFound is returned for an unknown, revoked or expired API token.
var ErrTokenNotFound = errors.New("store: api token not found")

// PrincipalCredential is a portal login secret.
//
// Only the encoded hash is stored, and nothing in the control plane can recover
// the password from it. Under SSO (D16) this table simply stops being written.
type PrincipalCredential struct {
	bun.BaseModel `bun:"table:principal_credential,alias:principal_credential" json:"-"`

	PrincipalID string    `bun:"principal_id,pk" json:"principal_id"`
	Algo        string    `bun:"algo" json:"algo"`
	Hash        string    `bun:"hash" json:"-"`
	UpdatedAt   time.Time `bun:"updated_at" json:"updated_at"`
	// SessionEpoch is stamped into every portal cookie issued for this
	// principal; a cookie from an earlier epoch is refused.
	SessionEpoch int64 `bun:"session_epoch" json:"-"`
}

// APIToken is a CLI or CI credential bound to a principal.
//
// Hash is sha256 of the secret half of the token; the secret itself is returned
// once, at creation, and never stored. A leaked database therefore yields no
// usable token.
type APIToken struct {
	bun.BaseModel `bun:"table:api_token,alias:api_token" json:"-"`

	ID          string     `bun:"id,pk" json:"id"`
	PrincipalID string     `bun:"principal_id" json:"principal_id"`
	Name        string     `bun:"name" json:"name"`
	Hash        string     `bun:"hash" json:"-"`
	CreatedBy   string     `bun:"created_by" json:"created_by"`
	CreatedAt   time.Time  `bun:"created_at" json:"created_at"`
	ExpiresAt   time.Time  `bun:"expires_at" json:"expires_at"`
	LastUsedAt  *time.Time `bun:"last_used_at,nullzero" json:"last_used_at,omitempty"`
	RevokedBy   string     `bun:"revoked_by,nullzero" json:"revoked_by,omitempty"`
	RevokedAt   *time.Time `bun:"revoked_at,nullzero" json:"revoked_at,omitempty"`
}

// SetCredential stores or replaces a principal's portal password hash.
func SetCredential(ctx context.Context, tx bun.Tx, c PrincipalCredential) error {

	c.UpdatedAt = time.Now().UTC()
	_, err := tx.NewInsert().Model(&c).
		On("CONFLICT (principal_id) DO UPDATE").
		Set("algo = EXCLUDED.algo").
		Set("hash = EXCLUDED.hash").
		Set("updated_at = EXCLUDED.updated_at").
		// A new password ends every session the old one opened.
		Set("session_epoch = principal_credential.session_epoch + 1").
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: set credential for %s: %w", c.PrincipalID, err)
	}
	return nil
}

// BumpSessionEpoch ends every portal session issued for a principal so far.
func BumpSessionEpoch(ctx context.Context, tx bun.Tx, principalID string) error {

	_, err := tx.NewUpdate().Model((*PrincipalCredential)(nil)).
		Set("session_epoch = session_epoch + 1").
		Where("principal_id = ?", principalID).
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: end sessions for %s: %w", principalID, err)
	}
	return nil
}

// GetCredential reads a principal's portal password hash.
func GetCredential(ctx context.Context, db bun.IDB, principalID string) (PrincipalCredential, error) {

	var c PrincipalCredential
	err := db.NewSelect().Model(&c).Where("principal_id = ?", principalID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return PrincipalCredential{}, fmt.Errorf("%w: %s", ErrCredentialNotFound, principalID)
	}
	if err != nil {

		return PrincipalCredential{}, err
	}
	return c, nil
}

// InsertToken writes an API token row inside tx.
func InsertToken(ctx context.Context, tx bun.Tx, t APIToken) error {

	if t.CreatedAt.IsZero() {

		t.CreatedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&t).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert token %s: %w", t.ID, err)
	}
	return nil
}

// TokenByID returns a token regardless of its state, for revocation and listing.
func TokenByID(ctx context.Context, db bun.IDB, id string) (APIToken, error) {

	var t APIToken
	err := db.NewSelect().Model(&t).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return APIToken{}, fmt.Errorf("%w: %s", ErrTokenNotFound, id)
	}
	if err != nil {

		return APIToken{}, err
	}
	return t, nil
}

// ListTokens returns every token, newest first. Secrets are not stored, so this
// is safe to render.
func ListTokens(ctx context.Context, db bun.IDB, principalID string) ([]APIToken, error) {

	q := db.NewSelect().Model((*APIToken)(nil)).Order("created_at DESC", "id DESC")
	if principalID != "" {

		q = q.Where("principal_id = ?", principalID)
	}
	var out []APIToken
	err := q.Scan(ctx, &out)
	return out, err
}

// RevokeToken withdraws a token. Like a grant, the row stays: the record of
// what existed is the point.
func RevokeToken(ctx context.Context, tx bun.Tx, id, revokedBy string) error {

	res, err := tx.NewUpdate().Model((*APIToken)(nil)).
		Set("revoked_by = ?", revokedBy).
		Set("revoked_at = ?", time.Now().UTC()).
		Where("id = ?", id).
		Where("revoked_at IS NULL").
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s is already revoked", ErrTokenNotFound, id)
	}
	return nil
}

// TouchToken records a token's last use.
//
// Deliberately not an audit event: the audit log records what the principal
// did, and a row per authenticated request would bury that under traffic. This
// write also goes through the read pool's sibling — it is the one mutation in
// the control plane with no state change to be atomic with.
func TouchToken(ctx context.Context, db *DB, id string) error {

	_, err := db.w.NewUpdate().Model((*APIToken)(nil)).
		Set("last_used_at = ?", time.Now().UTC()).
		Where("id = ?", id).
		Exec(ctx)
	return err
}
