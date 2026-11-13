package store

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ReaffirmWindow is how long a new owner has to look at the grants they
// inherited before those grants stop being enforced (§14.7).
const ReaffirmWindow = 30 * 24 * time.Hour

// Reaffirmation is a Tier-2 grant inherited through an ownership transfer,
// awaiting the new owner's confirmation that it should still be in effect.
//
// A transfer must not silently carry grants. The person newly accountable for
// an instance should have to look at what it can reach — so an unaffirmed row
// past due_at stops the grant being an input to the next ACL regeneration.
// That is the same "stops being an input" mechanism expiry uses, deliberately:
// a second revocation path could disagree with the first.
type Reaffirmation struct {
	bun.BaseModel `bun:"table:grant_reaffirmation,alias:grant_reaffirmation" json:"-"`

	GrantID    string     `bun:"grant_id,pk" json:"grant_id"`
	TransferID string     `bun:"transfer_id" json:"transfer_id"`
	DueAt      time.Time  `bun:"due_at" json:"due_at"`
	AffirmedBy string     `bun:"affirmed_by,nullzero" json:"affirmed_by,omitempty"`
	AffirmedAt *time.Time `bun:"affirmed_at,nullzero" json:"affirmed_at,omitempty"`
}

// Lapsed reports whether this grant has fallen out of enforcement for want of a
// re-affirmation.
func (r Reaffirmation) Lapsed(now time.Time) bool {

	return r.AffirmedAt == nil && !now.Before(r.DueAt)
}

// InsertReaffirmation records one inherited grant inside tx.
func InsertReaffirmation(ctx context.Context, tx bun.Tx, r Reaffirmation) error {

	if r.DueAt.IsZero() {

		r.DueAt = time.Now().UTC().Add(ReaffirmWindow)
	}
	_, err := tx.NewInsert().Model(&r).
		On("CONFLICT (grant_id) DO UPDATE").
		Set("transfer_id = EXCLUDED.transfer_id").
		Set("due_at = EXCLUDED.due_at").
		Set("affirmed_by = NULL").
		Set("affirmed_at = NULL").
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: insert reaffirmation for %s: %w", r.GrantID, err)
	}
	return nil
}

// Affirm marks one inherited grant as confirmed by the new owner.
func Affirm(ctx context.Context, tx bun.Tx, grantID, principalID string, at time.Time) error {

	res, err := tx.NewUpdate().Model((*Reaffirmation)(nil)).
		Set("affirmed_by = ?", principalID).
		Set("affirmed_at = ?", at.UTC()).
		Where("grant_id = ?", grantID).
		Where("affirmed_at IS NULL").
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s has no outstanding re-affirmation", ErrGrantNotFound, grantID)
	}
	return nil
}

// PendingReaffirmations returns a tenant's inherited grants still awaiting the
// new owner, or the whole fleet when tenantID is empty.
func PendingReaffirmations(ctx context.Context, db bun.IDB, tenantID string) ([]Reaffirmation, error) {

	q := db.NewSelect().Model((*Reaffirmation)(nil)).
		Where("affirmed_at IS NULL").
		Order("due_at")
	if tenantID != "" {

		q = q.Where("grant_id IN (SELECT id FROM access_grant WHERE tenant_id = ?)", tenantID)
	}
	var out []Reaffirmation
	err := q.Scan(ctx, &out)
	return out, err
}

// LapsedGrantIDs returns the grant ids whose re-affirmation is overdue, as a
// set the enforcement path can subtract from the active set.
func LapsedGrantIDs(ctx context.Context, db bun.IDB, now time.Time) (map[string]bool, error) {

	var rows []Reaffirmation
	err := db.NewSelect().Model(&rows).
		Where("affirmed_at IS NULL").
		Where("due_at <= ?", now.UTC()).
		Scan(ctx)
	if err != nil {

		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {

		out[r.GrantID] = true
	}
	return out, nil
}
