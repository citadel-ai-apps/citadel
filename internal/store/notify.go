package store

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// Notification audiences.
const (
	AudienceTenant   = "tenant"
	AudienceOperator = "operator"
)

// Notification kinds.
const (
	NotifyGrantPending        = "grant.pending"
	NotifyGrantDecided        = "grant.decided"
	NotifyBreakglassOpened    = "breakglass.opened"
	NotifyBreakglassOverdue   = "breakglass.overdue"
	NotifyBreakglassReviewed  = "breakglass.reviewed"
	NotifyBreakglassClosed    = "breakglass.closed"
	NotifyTransferOffered     = "transfer.offered"
	NotifyGrantReaffirmDue    = "grant.reaffirm_due"
	NotifyAttestationMismatch = "attestation.mismatch"
	NotifyUpgradeRehearsal    = "upgrade.rehearsal"
	NotifyUpgradeResult       = "upgrade.result"
	NotifyRuntimeEOL          = "runtime.eol"
	NotifyRuntimeEOLBlocked   = "runtime.eol.quarantined"
	NotifyRuntimePinned       = "runtime.pinned"
)

// Notification is something the platform told someone, as opposed to something
// it recorded.
//
// The distinction is load-bearing. An audit row proves an action happened; it
// does not put the action in front of the person it happened to. §14.6 hinges
// on the second: an operator opening a customer's database learns that the
// customer is being told as it happens, which is what makes break-glass honest
// rather than merely logged.
//
// PrincipalID empty means "whoever holds a role on this tenant today", so a
// notice reaches the person accountable now rather than the one who was when it
// was written. An operator-audience notice reaches every operator whatever its
// TenantID, which names the tenant it concerns; that is how the other
// operators hear about a break-glass session.
type Notification struct {
	bun.BaseModel `bun:"table:notification,alias:notification" json:"-"`

	ID          string     `bun:"id,pk" json:"id"`
	TenantID    string     `bun:"tenant_id,nullzero" json:"tenant_id,omitempty"`
	PrincipalID string     `bun:"principal_id,nullzero" json:"principal_id,omitempty"`
	Audience    string     `bun:"audience" json:"audience"`
	Kind        string     `bun:"kind" json:"kind"`
	SubjectRef  string     `bun:"subject_ref,nullzero" json:"subject_ref,omitempty"`
	Body        string     `bun:"body" json:"body"`
	CreatedAt   time.Time  `bun:"created_at" json:"created_at"`
	ReadAt      *time.Time `bun:"read_at,nullzero" json:"read_at,omitempty"`
}

// Notify writes a notification inside tx.
//
// Always called in the same transaction as the state change it announces, for
// the reason §14.4 gives about audit events: a crash between the two yields
// an access nobody was told about.
func Notify(ctx context.Context, tx bun.Tx, n Notification) error {

	if n.ID == "" {

		n.ID = NewID("n")
	}
	if n.CreatedAt.IsZero() {

		n.CreatedAt = time.Now().UTC()
	}
	_, err := tx.NewInsert().Model(&n).Exec(ctx)
	return err
}

// NotificationFilter narrows a listing. Zero fields mean "any".
type NotificationFilter struct {
	TenantID string
	Audience string
	Kind     string
	Unread   bool
	Limit    int
}

// ListNotifications returns notifications newest first.
func ListNotifications(ctx context.Context, db bun.IDB, f NotificationFilter) ([]Notification, error) {

	q := db.NewSelect().Model((*Notification)(nil)).Order("created_at DESC", "rowid DESC")
	if f.TenantID != "" {

		q = q.Where("tenant_id = ?", f.TenantID)
	}
	if f.Audience != "" {

		q = q.Where("audience = ?", f.Audience)
	}
	if f.Kind != "" {

		q = q.Where("kind = ?", f.Kind)
	}
	if f.Unread {

		q = q.Where("read_at IS NULL")
	}
	if f.Limit <= 0 {

		f.Limit = 50
	}
	var out []Notification
	err := q.Limit(f.Limit).Scan(ctx, &out)
	return out, err
}

// MarkNotificationsRead stamps a tenant's feed as seen.
//
// Reading is the one mutation allowed here. The record that the notice was SENT
// is the audit event; this column only tracks whether the reader has caught up,
// so overwriting it loses nothing that accountability depends on.
func MarkNotificationsRead(ctx context.Context, tx bun.Tx, tenantID, audience string, at time.Time) error {

	q := tx.NewUpdate().Model((*Notification)(nil)).
		Set("read_at = ?", at.UTC()).
		Where("read_at IS NULL")
	if tenantID != "" {

		q = q.Where("tenant_id = ?", tenantID)
	}
	if audience != "" {

		q = q.Where("audience = ?", audience)
	}
	_, err := q.Exec(ctx)
	return err
}
