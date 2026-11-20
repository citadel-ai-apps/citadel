package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ErrTransferNotFound is returned when there is no matching open offer.
var ErrTransferNotFound = errors.New("store: no open ownership transfer")

// OwnerTransfer is a transfer offer awaiting the target's answer.
//
// Ownership itself lives in tenant_owner. This row exists only between
// "the owner offered" and "the target accepted", because §14.1 requires both
// parties on the record: a tenant is never pushed onto someone who did not
// agree to be accountable for it.
type OwnerTransfer struct {
	bun.BaseModel `bun:"table:owner_transfer,alias:owner_transfer" json:"-"`

	ID            string     `bun:"id,pk" json:"id"`
	TenantID      string     `bun:"tenant_id" json:"tenant_id"`
	FromPrincipal string     `bun:"from_principal" json:"from_principal"`
	ToPrincipal   string     `bun:"to_principal" json:"to_principal"`
	OfferedBy     string     `bun:"offered_by" json:"offered_by"`
	OfferedAt     time.Time  `bun:"offered_at" json:"offered_at"`
	ExpiresAt     time.Time  `bun:"expires_at" json:"expires_at"`
	AcceptedAt    *time.Time `bun:"accepted_at,nullzero" json:"accepted_at,omitempty"`
	DeclinedAt    *time.Time `bun:"declined_at,nullzero" json:"declined_at,omitempty"`
	CancelledAt   *time.Time `bun:"cancelled_at,nullzero" json:"cancelled_at,omitempty"`
	Reason        string     `bun:"reason,nullzero" json:"reason,omitempty"`
}

// Open reports whether the offer is still awaiting an answer.
func (t OwnerTransfer) Open(now time.Time) bool {

	return t.AcceptedAt == nil && t.DeclinedAt == nil && t.CancelledAt == nil && now.Before(t.ExpiresAt)
}

// InsertTransfer records a new offer. The partial unique index in migration 002
// refuses a second open offer for the same tenant.
func InsertTransfer(ctx context.Context, tx bun.Tx, t OwnerTransfer) error {

	if t.OfferedAt.IsZero() {

		t.OfferedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&t).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert transfer for %s: %w", t.TenantID, err)
	}
	return nil
}

// OpenTransfer returns the tenant's outstanding offer, expired ones included —
// the caller decides what an expired offer means, so the distinction is not
// buried in a query.
func OpenTransfer(ctx context.Context, db bun.IDB, tenantID string) (OwnerTransfer, error) {

	var t OwnerTransfer
	err := db.NewSelect().Model(&t).
		Where("tenant_id = ?", tenantID).
		Where("accepted_at IS NULL AND declined_at IS NULL AND cancelled_at IS NULL").
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return OwnerTransfer{}, fmt.Errorf("%w: %s", ErrTransferNotFound, tenantID)
	}
	if err != nil {

		return OwnerTransfer{}, err
	}
	return t, nil
}

// ListTransfers returns a tenant's transfer history, newest first.
func ListTransfers(ctx context.Context, db bun.IDB, tenantID string) ([]OwnerTransfer, error) {

	var out []OwnerTransfer
	err := db.NewSelect().Model(&out).
		Where("tenant_id = ?", tenantID).
		Order("offered_at DESC", "rowid DESC").
		Scan(ctx)
	return out, err
}

// Transfer outcomes, which map onto the timestamp column that closes the offer.
const (
	TransferAccepted  = "accepted_at"
	TransferDeclined  = "declined_at"
	TransferCancelled = "cancelled_at"
)

// CloseTransfer stamps the outcome column, freeing the tenant for a new offer.
func CloseTransfer(ctx context.Context, tx bun.Tx, id, column string) error {

	switch column {

	case TransferAccepted, TransferDeclined, TransferCancelled:
	default:
		return fmt.Errorf("store: %q is not a transfer outcome column", column)
	}
	res, err := tx.NewUpdate().Model((*OwnerTransfer)(nil)).
		Set("? = ?", bun.Ident(column), time.Now().UTC()).
		Where("id = ?", id).
		Where("accepted_at IS NULL AND declined_at IS NULL AND cancelled_at IS NULL").
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s is already closed", ErrTransferNotFound, id)
	}
	return nil
}
