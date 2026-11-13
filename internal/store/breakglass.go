package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Break-glass review outcomes.
const (
	ReviewJustified   = "justified"
	ReviewUnjustified = "unjustified"
)

// BreakglassTTL is the hard time box on a Tier-3 grant (§14.3).
//
// Not extendable: an operator who needs longer requests again, which is another
// notification to the tenant and another row to review. Extension would turn a
// bounded incident into an open-ended one with a single decision behind it.
const BreakglassTTL = 60 * time.Minute

// ReviewWindow is how long a break-glass session may sit unreviewed before it
// blocks the requester from opening another (§14.3).
const ReviewWindow = 24 * time.Hour

// ErrReviewNotFound is returned for a review of an unknown or unreviewed grant.
var ErrReviewNotFound = errors.New("store: no break-glass review")

// BreakglassReview is a second party's verdict on a break-glass session.
//
// A separate table rather than columns on access_grant because the ABSENCE of a
// row is what blocks further break-glass by the same principal. "No row yet" is
// harder to get wrong than a nullable column somebody forgets to set.
type BreakglassReview struct {
	bun.BaseModel `bun:"table:breakglass_review,alias:breakglass_review" json:"-"`

	GrantID    string    `bun:"grant_id,pk" json:"grant_id"`
	ReviewedBy string    `bun:"reviewed_by" json:"reviewed_by"`
	ReviewedAt time.Time `bun:"reviewed_at" json:"reviewed_at"`
	Outcome    string    `bun:"outcome" json:"outcome"`
	Notes      string    `bun:"notes" json:"notes"`
}

// InsertReview records a review inside tx.
func InsertReview(ctx context.Context, tx bun.Tx, r BreakglassReview) error {

	if r.ReviewedAt.IsZero() {

		r.ReviewedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&r).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert review for %s: %w", r.GrantID, err)
	}
	return nil
}

// GetReview returns the review of one grant.
func GetReview(ctx context.Context, db bun.IDB, grantID string) (BreakglassReview, error) {

	var r BreakglassReview
	err := db.NewSelect().Model(&r).Where("grant_id = ?", grantID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return BreakglassReview{}, fmt.Errorf("%w: %s", ErrReviewNotFound, grantID)
	}
	return r, err
}

// BreakglassGrants returns every Tier-3 grant for a tenant, newest first.
// Pass an empty tenantID for the whole fleet.
func BreakglassGrants(ctx context.Context, db bun.IDB, tenantID string) ([]Grant, error) {

	q := db.NewSelect().Model((*Grant)(nil)).
		Where("kind IN (?, ?)", GrantOperatorDataAccess, GrantSupportImpersonate).
		Order("requested_at DESC")
	if tenantID != "" {

		q = q.Where("tenant_id = ?", tenantID)
	}
	var out []Grant
	err := q.Scan(ctx, &out)
	return out, err
}

// UnreviewedBreakglass returns Tier-3 grants requested by this principal that
// have no review row and whose review window has passed.
//
// This is the block in §14.3: an operator who has not had a past session
// reviewed cannot open another. The requester cannot clear it themselves,
// because the review must come from someone else.
func UnreviewedBreakglass(ctx context.Context, db bun.IDB, principalID string, now time.Time) ([]Grant, error) {

	var out []Grant
	err := db.NewSelect().Model(&out).
		Where("requested_by = ?", principalID).
		Where("kind IN (?, ?)", GrantOperatorDataAccess, GrantSupportImpersonate).
		Where("requested_at <= ?", now.UTC().Add(-ReviewWindow)).
		Where("id NOT IN (SELECT grant_id FROM breakglass_review)").
		Order("requested_at").
		Scan(ctx)
	return out, err
}

// OpenBreakglass returns Tier-3 grants that are active right now — the fleet
// view's "break-glass sessions open at this moment" row (§15).
func OpenBreakglass(ctx context.Context, db bun.IDB, now time.Time) ([]Grant, error) {

	all, err := BreakglassGrants(ctx, db, "")
	if err != nil {

		return nil, err
	}
	var out []Grant
	for _, g := range all {

		if g.Active(now) {

			out = append(out, g)
		}
	}
	return out, nil
}

// OverdueBreakglass returns every Tier-3 grant past its review window with no
// review, fleet-wide.
func OverdueBreakglass(ctx context.Context, db bun.IDB, now time.Time) ([]Grant, error) {

	var out []Grant
	err := db.NewSelect().Model(&out).
		Where("kind IN (?, ?)", GrantOperatorDataAccess, GrantSupportImpersonate).
		Where("requested_at <= ?", now.UTC().Add(-ReviewWindow)).
		Where("id NOT IN (SELECT grant_id FROM breakglass_review)").
		Order("requested_at").
		Scan(ctx)
	return out, err
}
