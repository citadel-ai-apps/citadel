package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Attestation outcomes (§14.5). The asymmetry between the last two is the
// point: a missing rule is a reliability problem, an extra one is either a bug
// in the platform or someone operating outside the control plane.
const (
	OutcomeMatch                   = "match"
	OutcomeGrantWithoutEnforcement = "grant_without_enforcement"
	OutcomeEnforcementWithoutGrant = "enforcement_without_grant"
)

// ErrNoAttestation is returned when a tenant has never been attested.
var ErrNoAttestation = errors.New("store: no attestation for tenant")

// Attestation is a signed report of what a tenant can actually reach, derived
// by inspecting the host and diffed against the grants.
//
// ObservedJSON is what the HOST showed, not what the database intended. An
// audit that reads the same table that generated the rules proves nothing, so
// nothing in this row may be reconstructed from access_grant.
type Attestation struct {
	bun.BaseModel `bun:"table:attestation,alias:attestation" json:"-"`

	ID           string    `bun:"id,pk" json:"id"`
	TenantID     string    `bun:"tenant_id" json:"tenant_id"`
	GeneratedAt  time.Time `bun:"generated_at" json:"generated_at"`
	ObservedJSON string    `bun:"observed_json" json:"observed_json"`
	Outcome      string    `bun:"outcome" json:"outcome"`
	MismatchJSON string    `bun:"mismatch_json,nullzero" json:"mismatch_json,omitempty"`
	GrantsJSON   string    `bun:"grants_json,nullzero" json:"grants_json,omitempty"`
	Signature    string    `bun:"signature" json:"signature"`
}

// InsertAttestation stores a report inside tx.
func InsertAttestation(ctx context.Context, tx bun.Tx, a Attestation) error {

	if a.ID == "" {

		a.ID = NewID("at")
	}
	if a.GeneratedAt.IsZero() {

		a.GeneratedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&a).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert attestation for %s: %w", a.TenantID, err)
	}
	return nil
}

// LatestAttestation returns a tenant's most recent report.
func LatestAttestation(ctx context.Context, db bun.IDB, tenantID string) (Attestation, error) {

	var a Attestation
	err := db.NewSelect().Model(&a).
		Where("tenant_id = ?", tenantID).
		Order("generated_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Attestation{}, fmt.Errorf("%w: %s", ErrNoAttestation, tenantID)
	}
	return a, err
}

// ListAttestations returns a tenant's reports newest first.
func ListAttestations(ctx context.Context, db bun.IDB, tenantID string, limit int) ([]Attestation, error) {

	if limit <= 0 {

		limit = 25
	}
	q := db.NewSelect().Model((*Attestation)(nil)).
		Order("generated_at DESC").
		Limit(limit)
	if tenantID != "" {

		q = q.Where("tenant_id = ?", tenantID)
	}
	var out []Attestation
	err := q.Scan(ctx, &out)
	return out, err
}

// Mismatches returns the latest non-matching report per tenant, the security
// outcome first — the fleet view's "attestation mismatches" row (§15).
//
// Latest-per-tenant rather than every mismatch ever: a tenant whose rule was
// repaired on the next tick should leave the list, while one whose extra rule
// is still there must not scroll away behind its own history.
func Mismatches(ctx context.Context, db bun.IDB) ([]Attestation, error) {

	var out []Attestation
	err := db.NewSelect().Model(&out).
		Where("outcome != ?", OutcomeMatch).
		Where("id IN (SELECT id FROM attestation a2 WHERE a2.tenant_id = attestation.tenant_id "+
			"ORDER BY a2.generated_at DESC LIMIT 1)").
		OrderExpr("CASE outcome WHEN ? THEN 0 ELSE 1 END", OutcomeEnforcementWithoutGrant).
		Order("generated_at DESC").
		Scan(ctx)
	return out, err
}
