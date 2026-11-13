package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Grant kinds (design §14.2). Only egress_host is issued today; the rest are
// declared so the tier rules and the portal can name them.
const (
	GrantEgressHost         = "egress_host"
	GrantSMTPRelay          = "smtp_relay"
	GrantObjectStorage      = "object_storage"
	GrantCustomDomain       = "custom_domain"
	GrantOAuthProvider      = "oauth_provider"
	GrantOperatorDataAccess = "operator_data_access"
	GrantBackupExport       = "backup_export"
	GrantLogAccess          = "log_access"
	GrantSupportImpersonate = "support_impersonation"
)

// Grant directions: outbound is tenant→world, inbound is world→tenant data.
const (
	DirectionOutbound = "outbound"
	DirectionInbound  = "inbound"
)

// Grant decisions (design §8.1).
const (
	DecisionPending      = "pending"
	DecisionAutoApproved = "auto_approved"
	DecisionApproved     = "approved"
	DecisionDenied       = "denied"
	DecisionExpired      = "expired"
	DecisionRevoked      = "revoked"
)

// ErrGrantNotFound is returned for an unknown grant id.
var ErrGrantNotFound = errors.New("store: grant not found")

// Grant is one authorisation for one capability that crosses the sandbox
// boundary. It is the ONLY input to enforcement; release.egress_hosts
// records what a release asked for and never what is allowed.
type Grant struct {
	bun.BaseModel `bun:"table:access_grant,alias:access_grant" json:"-"`

	ID            string     `bun:"id,pk" json:"id"`
	TenantID      string     `bun:"tenant_id" json:"tenant_id"`
	Kind          string     `bun:"kind" json:"kind"`
	Direction     string     `bun:"direction" json:"direction"`
	Subject       string     `bun:"subject" json:"subject"`
	Tier          int        `bun:"tier" json:"tier"`
	Decision      string     `bun:"decision" json:"decision"`
	RequestedBy   string     `bun:"requested_by" json:"requested_by"`
	RequestedAt   time.Time  `bun:"requested_at" json:"requested_at"`
	DecidedBy     string     `bun:"decided_by,nullzero" json:"decided_by,omitempty"`
	DecidedAt     *time.Time `bun:"decided_at,nullzero" json:"decided_at,omitempty"`
	PolicyVersion string     `bun:"policy_version,nullzero" json:"policy_version,omitempty"`
	Justification string     `bun:"justification,nullzero" json:"justification,omitempty"`
	EvidenceRef   string     `bun:"evidence_ref,nullzero" json:"evidence_ref,omitempty"`
	ExpiresAt     time.Time  `bun:"expires_at" json:"expires_at"`
	RevokedBy     string     `bun:"revoked_by,nullzero" json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `bun:"revoked_at,nullzero" json:"revoked_at,omitempty"`
}

// Active reports whether this grant is an input to enforcement right now.
//
// Expiry is evaluated here rather than swept by a cleanup job (§14.2): a grant
// that has passed expires_at simply stops being an input, so the enforcement
// path and the expiry path cannot disagree.
func (g Grant) Active(now time.Time) bool {

	if g.RevokedAt != nil {

		return false
	}
	if g.Decision != DecisionApproved && g.Decision != DecisionAutoApproved {

		return false
	}
	return now.Before(g.ExpiresAt)
}

// State is the grant's effective state, which is what the tenant sees. It
// differs from Decision only in that an approved-but-lapsed grant reads as
// expired without anything having rewritten the row.
func (g Grant) State(now time.Time) string {

	switch {

	case g.RevokedAt != nil:
		return DecisionRevoked
	case g.Decision == DecisionDenied:
		return DecisionDenied
	case g.Decision == DecisionPending:
		return DecisionPending
	case !now.Before(g.ExpiresAt):
		return DecisionExpired
	default:
		return g.Decision
	}
}

// InsertGrant writes a grant row inside tx.
func InsertGrant(ctx context.Context, tx bun.Tx, g Grant) error {

	if g.RequestedAt.IsZero() {

		g.RequestedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&g).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert grant %s: %w", g.ID, err)
	}
	return nil
}

// GetGrant looks a grant up by id.
func GetGrant(ctx context.Context, db bun.IDB, id string) (Grant, error) {

	var g Grant
	err := db.NewSelect().Model(&g).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Grant{}, fmt.Errorf("%w: %s", ErrGrantNotFound, id)
	}
	if err != nil {

		return Grant{}, err
	}
	return g, nil
}

// GrantFilter narrows a grant listing. Zero fields mean "any".
type GrantFilter struct {
	TenantID string
	Kind     string
	Decision string
	Subject  string
}

// ListGrants returns matching grants, newest request first.
func ListGrants(ctx context.Context, db bun.IDB, f GrantFilter) ([]Grant, error) {

	q := db.NewSelect().Model((*Grant)(nil)).Order("requested_at DESC", "id DESC")
	if f.TenantID != "" {

		q = q.Where("tenant_id = ?", f.TenantID)
	}
	if f.Kind != "" {

		q = q.Where("kind = ?", f.Kind)
	}
	if f.Decision != "" {

		q = q.Where("decision = ?", f.Decision)
	}
	if f.Subject != "" {

		q = q.Where("subject = ?", f.Subject)
	}
	var out []Grant
	err := q.Scan(ctx, &out)
	return out, err
}

// ActiveGrants returns the grants that are inputs to enforcement for a tenant.
func ActiveGrants(ctx context.Context, db bun.IDB, tenantID, kind string, now time.Time) ([]Grant, error) {

	all, err := ListGrants(ctx, db, GrantFilter{TenantID: tenantID, Kind: kind})
	if err != nil {

		return nil, err
	}
	out := make([]Grant, 0, len(all))
	for _, g := range all {

		if g.Active(now) {

			out = append(out, g)
		}
	}
	return out, nil
}

// DecideGrant records a human or platform decision on a pending grant.
func DecideGrant(ctx context.Context, tx bun.Tx, id, decision, decidedBy, justification string, expiresAt time.Time) error {

	q := tx.NewUpdate().Model((*Grant)(nil)).
		Set("decision = ?", decision).
		Set("decided_by = ?", decidedBy).
		Set("decided_at = ?", time.Now().UTC()).
		Set("justification = ?", nullStr(justification)).
		Where("id = ?", id).
		Where("decision = ?", DecisionPending)
	if !expiresAt.IsZero() {

		q = q.Set("expires_at = ?", expiresAt.UTC())
	}
	res, err := q.Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s is not pending", ErrGrantNotFound, id)
	}
	return nil
}

// RevokeGrant withdraws a grant. Revocation never deletes the row: the decision
// history is what §14 exists to keep, and §14.7 reads it to refuse a silent
// re-grant. Rows go only with their tenant (DeleteTenant), when every grant,
// decision and revocation is already in the audit chain.
func RevokeGrant(ctx context.Context, tx bun.Tx, id, revokedBy string) error {

	res, err := tx.NewUpdate().Model((*Grant)(nil)).
		Set("revoked_by = ?", revokedBy).
		Set("revoked_at = ?", time.Now().UTC()).
		Where("id = ?", id).
		Where("revoked_at IS NULL").
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s is already revoked", ErrGrantNotFound, id)
	}
	return nil
}

// SubjectWasRefused reports whether this tenant ever had this subject denied or
// revoked.
//
// §14.7: re-requesting such a subject is allowed, auto-granting it is not,
// regardless of tier. Without this, "revoke, then roll back" silently undoes
// the revocation, because the restored release re-declares the host in its
// manifest and it re-enters the pipeline as a fresh request.
func SubjectWasRefused(ctx context.Context, db bun.IDB, tenantID, kind, subject string) (bool, error) {

	n, err := db.NewSelect().Model((*Grant)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("kind = ?", kind).
		Where("subject = ?", subject).
		Where("decision = ? OR revoked_at IS NOT NULL", DecisionDenied).
		Count(ctx)
	return n > 0, err
}
