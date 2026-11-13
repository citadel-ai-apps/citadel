package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// Desired states (design §8.1).
const (
	DesiredRunning   = "running"
	DesiredStopped   = "stopped"
	DesiredSuspended = "suspended"
	DesiredDeleted   = "deleted"
)

// Observed instance states.
const (
	ObservedStopped   = "stopped"
	ObservedStarting  = "starting"
	ObservedHealthy   = "healthy"
	ObservedUnhealthy = "unhealthy"
	ObservedFailed    = "failed"
)

// ErrTenantNotFound is returned for an unknown tenant id or slug.
var ErrTenantNotFound = errors.New("store: tenant not found")

// Tenant is the control plane's record of one tenant.
//
// The table name is pinned explicitly here and in every other model: bun
// pluralises by default, and this schema is singular (migration 001).
type Tenant struct {
	bun.BaseModel `bun:"table:tenant,alias:tenant" json:"-"`

	ID              string `bun:"id,pk" json:"id"`
	Slug            string `bun:"slug" json:"slug"`
	Hostname        string `bun:"hostname" json:"hostname"`
	OwnerOrphaned   bool   `bun:"owner_orphaned" json:"owner_orphaned"`
	DesiredState    string `bun:"desired_state" json:"desired_state"`
	RuntimeVersion  string `bun:"runtime_version" json:"runtime_version"`
	ImageDigest     string `bun:"image_digest" json:"image_digest"`
	CurrentRelease  string `bun:"current_release,nullzero" json:"current_release,omitempty"`
	CurrentArtifact string `bun:"current_artifact,nullzero" json:"current_artifact,omitempty"`
	NetworkName     string `bun:"network_name" json:"network_name"`
	Subnet          string `bun:"subnet" json:"subnet"`
	GatewayIP       string `bun:"gateway_ip" json:"gateway_ip"`
	EdgeIP          string `bun:"edge_ip" json:"edge_ip"`
	ContainerIP     string `bun:"container_ip,nullzero" json:"container_ip"`
	EgressEnabled   bool   `bun:"egress_enabled" json:"egress_enabled"`
	EgressIP        string `bun:"egress_ip,nullzero" json:"egress_ip,omitempty"`
	Quarantined     bool   `bun:"quarantined" json:"quarantined"`
	// FrozenReason is set while an enforcement_without_grant finding is
	// unresolved (§14.5); empty means not frozen.
	FrozenReason  string     `bun:"frozen_reason,nullzero" json:"frozen_reason,omitempty"`
	FrozenAt      *time.Time `bun:"frozen_at,nullzero" json:"frozen_at,omitempty"`
	CPUs          float64    `bun:"cpus" json:"cpus"`
	MemMiB        int        `bun:"mem_mib" json:"mem_mib"`
	DiskMiB       int        `bun:"disk_mib" json:"disk_mib"`
	BodyCap       string     `bun:"body_cap" json:"body_cap"`
	PurgeOnDelete bool       `bun:"purge_on_delete" json:"purge_on_delete"`
	EncKeyRef     string     `bun:"enc_key_ref" json:"enc_key_ref"`
	CreatedAt     time.Time  `bun:"created_at" json:"created_at"`
}

// Instance is the observed state of a tenant's container.
type Instance struct {
	bun.BaseModel `bun:"table:instance,alias:instance" json:"-"`

	TenantID      string     `bun:"tenant_id,pk" json:"tenant_id"`
	ContainerID   string     `bun:"container_id,nullzero" json:"container_id,omitempty"`
	ObservedState string     `bun:"observed_state" json:"observed_state"`
	RunningDigest string     `bun:"running_digest,nullzero" json:"running_digest,omitempty"`
	RestartCount  int        `bun:"restart_count" json:"restart_count"`
	LastRestartAt *time.Time `bun:"last_restart_at,nullzero" json:"last_restart_at,omitempty"`
	LastHealthAt  *time.Time `bun:"last_health_at,nullzero" json:"last_health_at,omitempty"`
	LastError     string     `bun:"last_error,nullzero" json:"last_error,omitempty"`
	UpdatedAt     time.Time  `bun:"updated_at" json:"updated_at"`
}

// InsertTenant writes a tenant row inside tx.
//
// It does not grant ownership; CreateTenant in the api layer does both in one
// transaction, because a tenant without an owner would leave the tenant unowned the
// moment it existed.
func InsertTenant(ctx context.Context, tx bun.Tx, t Tenant) error {

	if t.CreatedAt.IsZero() {

		t.CreatedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&t).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert tenant %s: %w", t.Slug, err)
	}
	// The instance row exists from the start so the reconciler never has to
	// distinguish "no row yet" from "stopped".
	in := Instance{TenantID: t.ID, ObservedState: ObservedStopped, UpdatedAt: time.Now().UTC()}
	_, err := tx.NewInsert().Model(&in).Exec(ctx)
	return err
}

// GetTenant looks a tenant up by id.
func GetTenant(ctx context.Context, db bun.IDB, id string) (Tenant, error) {

	return getTenantBy(ctx, db, "id", id)
}

// GetTenantBySlug looks a tenant up by slug, which is what citadel accepts.
func GetTenantBySlug(ctx context.Context, db bun.IDB, slug string) (Tenant, error) {

	return getTenantBy(ctx, db, "slug", slug)
}

func getTenantBy(ctx context.Context, db bun.IDB, column, value string) (Tenant, error) {

	var t Tenant
	err := db.NewSelect().Model(&t).Where("? = ?", bun.Ident(column), value).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Tenant{}, fmt.Errorf("%w: %s", ErrTenantNotFound, value)
	}
	if err != nil {

		return Tenant{}, err
	}
	return t, nil
}

// ListTenants returns every tenant, including those pending deletion — the
// reconciler needs the deleted ones to finish tearing them down.
func ListTenants(ctx context.Context, db bun.IDB) ([]Tenant, error) {

	var out []Tenant
	err := db.NewSelect().Model(&out).Order("slug").Scan(ctx)
	return out, err
}

// AllocatedSubnets returns every subnet currently held by a tenant, which is
// the IPAM allocator's exclusion set.
func AllocatedSubnets(ctx context.Context, db bun.IDB) ([]string, error) {

	var out []string
	err := db.NewSelect().Model((*Tenant)(nil)).Column("subnet").Scan(ctx, &out)
	return out, err
}

// SetDesiredState changes a tenant's intent. The reconciler acts on it; nothing
// here touches the host.
func SetDesiredState(ctx context.Context, tx bun.Tx, tenantID, state string) error {

	res, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("desired_state = ?", state).
		Where("id = ?", tenantID).
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return nil
}

// SetRuntimeVersion moves both runtime-version columns in one statement.
//
// They are never moved separately. A row saying 0.40 with a 0.28 digest is
// exactly the condition INV-11's drift alert cannot interpret: the reconciler
// compares the running digest against this column, so a half-written pair
// either hides a real drift or invents one. Only the upgrade state machine
// calls this, and only while holding the tenant's instance lock.
func SetRuntimeVersion(ctx context.Context, tx bun.Tx, tenantID, version, imageDigest string) error {

	if !strings.Contains(imageDigest, "@sha256:") {

		return fmt.Errorf("store: image_digest %q is not a digest reference", imageDigest)
	}
	res, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("runtime_version = ?", version).
		Set("image_digest = ?", imageDigest).
		Where("id = ?", tenantID).
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return nil
}

// SetPurgeOnDelete records that the tenant's data is to be destroyed, not
// retained, when teardown runs.
//
// Retention after deletion is D10: the platform retains by default and only
// discards when an operator asks. The flag lives in the row so the reconciler — which owns teardown —
// sees the same decision the API recorded and audited.
func SetPurgeOnDelete(ctx context.Context, tx bun.Tx, tenantID string) error {

	_, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("purge_on_delete = 1").
		Where("id = ?", tenantID).
		Exec(ctx)
	return err
}

// SetCurrentArtifact records which staged artifact app/current points at.
func SetCurrentArtifact(ctx context.Context, tx bun.Tx, tenantID, sha string) error {

	_, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("current_artifact = ?", nullStr(sha)).
		Where("id = ?", tenantID).
		Exec(ctx)
	return err
}

// AllocatedEgressIPs returns every address currently recorded on the egress
// network, which is that allocator's exclusion set.
//
// Addresses of tenants whose grants have all lapsed are included deliberately:
// the column is not cleared when the last grant goes, so a proxy log line
// written moments before a revocation can never be attributed to whichever
// tenant picked the address up next.
func AllocatedEgressIPs(ctx context.Context, db bun.IDB) ([]string, error) {

	var out []string
	err := db.NewSelect().Model((*Tenant)(nil)).
		Column("egress_ip").Where("egress_ip IS NOT NULL").Scan(ctx, &out)
	return out, err
}

// SetEgressState records whether the tenant currently has an enforced outbound
// path, and the address it is enforced against.
//
// `enabled` is derived from the active grant set on every tick, never from a
// manifest, so this is a cache of a derivation and not a decision.
func SetEgressState(ctx context.Context, tx bun.Tx, tenantID string, enabled bool, egressIP string) error {

	q := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("egress_enabled = ?", enabled).
		Where("id = ?", tenantID)
	if egressIP != "" {

		q = q.Set("egress_ip = ?", egressIP)
	}
	_, err := q.Exec(ctx)
	return err
}

// SetQuarantined flips the edge onto a 503 for this tenant, or back off it.
//
// It touches no data and stops no container: quarantine is an ingress decision
// (§12), which is exactly what makes it usable mid-incident when a forced
// upgrade is not.
func SetQuarantined(ctx context.Context, tx bun.Tx, tenantID string, on bool) error {

	res, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("quarantined = ?", on).
		Where("id = ?", tenantID).
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return nil
}

// SetMemMiB changes a tenant's memory limit. The container is not touched
// here: the reconciler sees the running limit differ from the row on its next
// tick and recreates the container, which keeps the data on its bind mount.
func SetMemMiB(ctx context.Context, tx bun.Tx, tenantID string, mib int) error {

	res, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("mem_mib = ?", mib).
		Where("id = ?", tenantID).
		Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return nil
}

// DeleteTenant removes every control-plane row that belongs to a tenant.
//
// Audit rows are deliberately untouched: audit_event.tenant_id has no foreign
// key and no cascade, because the record of who authorised access must outlive
// the data it describes. Everything else goes, in child-before-parent
// order — a release, backup, grant or transfer row left behind would hold a
// foreign key to a tenant that no longer exists, and SQLite refuses the delete
// rather than orphaning it.
//
// Grants go with the tenant deliberately (§14.7: deletion revokes them). Their
// decisions survive in the audit chain, which is where the accountability
// record belongs. Content-addressed artifacts are NOT touched: a sha can be
// shared by ten tenants (§7).
func DeleteTenant(ctx context.Context, tx bun.Tx, tenantID string) error {

	// The tenant points at a release, so that reference goes before the release
	// rows do.
	if err := SetCurrentRelease(ctx, tx, tenantID, ""); err != nil {

		return err
	}
	// Rows hanging off the tenant's grants and transfers, before those go.
	//
	// Deliberately NOT extended to attestation or notification: §14.7 keeps a
	// tenant's final attestation as the closing record of what it could reach on
	// the day it went away, and a notice is the record of something somebody was
	// told, which outlives the thing it was about. Neither carries a foreign key
	// to tenant for that reason — a reference would have turned "keep the
	// record" into "the deletion fails".
	for _, stmt := range []string{
		`DELETE FROM breakglass_review WHERE grant_id IN
		   (SELECT id FROM access_grant WHERE tenant_id = ?)`,
		`DELETE FROM grant_reaffirmation WHERE grant_id IN
		   (SELECT id FROM access_grant WHERE tenant_id = ?)`,
	} {

		if _, err := tx.ExecContext(ctx, stmt, tenantID); err != nil {

			return fmt.Errorf("store: delete grant-scoped rows for %s: %w", tenantID, err)
		}
	}
	for _, table := range []string{"egress_denial", "owner_transfer", "access_grant", "backup", "upgrade_job", "release"} {

		if _, err := tx.NewDelete().Table(table).Where("tenant_id = ?", tenantID).Exec(ctx); err != nil {

			return fmt.Errorf("store: delete %s rows for %s: %w", table, tenantID, err)
		}
	}
	if _, err := tx.NewDelete().Model((*Instance)(nil)).Where("tenant_id = ?", tenantID).Exec(ctx); err != nil {

		return err
	}
	if _, err := tx.NewDelete().Table("tenant_owner").Where("tenant_id = ?", tenantID).Exec(ctx); err != nil {

		return err
	}
	_, err := tx.NewDelete().Model((*Tenant)(nil)).Where("id = ?", tenantID).Exec(ctx)
	return err
}

// nullStr maps the empty string onto SQL NULL, for the columns where "unset"
// and "empty" must not be the same value.
func nullStr(s string) any {

	if s == "" {

		return nil
	}
	return s
}

// TenantsWithoutOneOwner lists live tenants whose active owner count is not
// exactly one (INV-17). Every write path keeps it at one; this is the
// independent check that says so if one ever does not.
func TenantsWithoutOneOwner(ctx context.Context, db bun.IDB) ([]string, error) {

	var out []string
	err := db.NewRaw(`SELECT t.id FROM tenant t
		WHERE t.desired_state != ?
		  AND (SELECT count(*) FROM current_owner o WHERE o.tenant_id = t.id) != 1
		ORDER BY t.id`, DesiredDeleted).Scan(ctx, &out)
	return out, err
}

// SetFrozen freezes a tenant with reason, or lifts the freeze when reason is
// empty (§14.5).
func SetFrozen(ctx context.Context, tx bun.Tx, tenantID, reason string) error {

	q := tx.NewUpdate().Model((*Tenant)(nil)).Where("id = ?", tenantID)
	if reason == "" {

		q = q.Set("frozen_reason = NULL").Set("frozen_at = NULL")

	} else {

		q = q.Set("frozen_reason = ?", reason).Set("frozen_at = ?", time.Now().UTC())
	}
	res, err := q.Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrTenantNotFound, tenantID)
	}
	return nil
}
