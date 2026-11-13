package store

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// Denial is one destination a tenant tried to reach and the egress proxy
// refused, aggregated over every attempt at that (host, port).
//
// Denials are a product surface, not an error condition (§9.4): a developer
// debugging a failing integration should see the actual reason rather than an
// opaque timeout. The reason itself is NOT stored — it is derived from
// access_grant at read time by EgressState, so an approver's decision and the
// reason the tenant is shown can never drift apart.
type Denial struct {
	bun.BaseModel `bun:"table:egress_denial,alias:egress_denial" json:"-"`

	TenantID    string    `bun:"tenant_id,pk" json:"tenant_id"`
	Host        string    `bun:"host,pk" json:"host"`
	Port        int       `bun:"port,pk" json:"port"`
	Hits        int       `bun:"hits" json:"hits"`
	FirstSeenAt time.Time `bun:"first_seen_at" json:"first_seen_at"`
	LastSeenAt  time.Time `bun:"last_seen_at" json:"last_seen_at"`
}

// RecordDenials merges a batch of observations into the aggregate.
//
// One statement per row rather than one per attempt: the proxy log is read in
// batches on the reconcile tick, and a hook retrying in a loop collapses into a
// single hits increment. That bound is deliberate — an unbounded insert path
// reachable from inside the sandbox is a denial of service against the control
// plane's own database.
func RecordDenials(ctx context.Context, tx bun.Tx, batch []Denial) error {

	for _, d := range batch {

		if d.Hits <= 0 {

			d.Hits = 1
		}
		if d.FirstSeenAt.IsZero() {

			d.FirstSeenAt = d.LastSeenAt
		}
		_, err := tx.NewInsert().Model(&d).
			On("CONFLICT (tenant_id, host, port) DO UPDATE").
			Set("hits = egress_denial.hits + EXCLUDED.hits").
			Set("last_seen_at = EXCLUDED.last_seen_at").
			Exec(ctx)
		if err != nil {

			return err
		}
	}
	return nil
}

// ListDenials returns a tenant's denials seen since `since`, busiest first.
func ListDenials(ctx context.Context, db bun.IDB, tenantID string, since time.Time) ([]Denial, error) {

	q := db.NewSelect().Model((*Denial)(nil)).
		Where("tenant_id = ?", tenantID).
		Order("hits DESC", "host")
	if !since.IsZero() {

		q = q.Where("last_seen_at >= ?", since.UTC())
	}
	var out []Denial
	err := q.Scan(ctx, &out)
	return out, err
}

// TopDenials is the fleet view's "top egress denials" row (§15), which is both
// a security signal and a support signal.
func TopDenials(ctx context.Context, db bun.IDB, limit int) ([]Denial, error) {

	if limit <= 0 {

		limit = 20
	}
	var out []Denial
	err := db.NewSelect().Model((*Denial)(nil)).
		Order("last_seen_at DESC", "hits DESC").
		Limit(limit).
		Scan(ctx, &out)
	return out, err
}

// DeleteDenials clears a tenant's denial history, used when the last grant goes
// so a stale list does not outlive the access it describes.
func DeleteDenials(ctx context.Context, tx bun.Tx, tenantID string) error {

	_, err := tx.NewDelete().Model((*Denial)(nil)).Where("tenant_id = ?", tenantID).Exec(ctx)
	return err
}
