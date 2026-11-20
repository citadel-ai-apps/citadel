package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Release statuses (design §8.1).
const (
	ReleaseUploaded   = "uploaded"
	ReleaseValidated  = "validated"
	ReleaseDeployed   = "deployed"
	ReleaseRolledBack = "rolled_back"
	ReleaseFailed     = "failed"
)

// ErrReleaseNotFound is returned for an unknown release id.
var ErrReleaseNotFound = errors.New("store: release not found")

// Release is one validated, content-addressed tenant package.
//
// Sha256 is the artifact *tree* digest from hostfs.ArtifactDigest, not the
// digest of the uploaded zip: that is the value artifacts/<sha>/ and
// tenant.current_artifact are keyed by, so two uploads that differ only in zip
// metadata share one artifact directory. The zip's own digest is recorded in
// the release.uploaded audit event.
type Release struct {
	bun.BaseModel `bun:"table:release,alias:release" json:"-"`

	ID          string     `bun:"id,pk" json:"id"`
	TenantID    string     `bun:"tenant_id" json:"tenant_id"`
	Sha256      string     `bun:"sha256" json:"sha256"`
	Manifest    string     `bun:"manifest" json:"manifest"`
	PBMin       string     `bun:"pb_min,nullzero" json:"pb_min,omitempty"`
	PBMax       string     `bun:"pb_max,nullzero" json:"pb_max,omitempty"`
	EgressHosts string     `bun:"egress_hosts,nullzero" json:"egress_hosts,omitempty"`
	Status      string     `bun:"status" json:"status"`
	DeployedAt  *time.Time `bun:"deployed_at,nullzero" json:"deployed_at,omitempty"`
	CreatedAt   time.Time  `bun:"created_at" json:"created_at"`
}

// InsertRelease writes a release row inside tx.
func InsertRelease(ctx context.Context, tx bun.Tx, r Release) error {

	if r.CreatedAt.IsZero() {

		r.CreatedAt = time.Now().UTC()
	}
	if _, err := tx.NewInsert().Model(&r).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert release %s: %w", r.ID, err)
	}
	return nil
}

// GetRelease looks a release up by id.
func GetRelease(ctx context.Context, db bun.IDB, id string) (Release, error) {

	var r Release
	err := db.NewSelect().Model(&r).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Release{}, fmt.Errorf("%w: %s", ErrReleaseNotFound, id)
	}
	if err != nil {

		return Release{}, err
	}
	return r, nil
}

// ListReleases returns a tenant's releases, newest first.
func ListReleases(ctx context.Context, db bun.IDB, tenantID string) ([]Release, error) {

	var out []Release
	err := db.NewSelect().Model(&out).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC", "rowid DESC").
		Scan(ctx)
	return out, err
}

// SetReleaseStatus moves a release through the §8.5 state machine. deployedAt is
// stamped only on the transition into deployed.
func SetReleaseStatus(ctx context.Context, tx bun.Tx, id, status string) error {

	q := tx.NewUpdate().Model((*Release)(nil)).
		Set("status = ?", status).
		Where("id = ?", id)
	if status == ReleaseDeployed {

		q = q.Set("deployed_at = ?", time.Now().UTC())
	}
	res, err := q.Exec(ctx)
	if err != nil {

		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {

		return fmt.Errorf("%w: %s", ErrReleaseNotFound, id)
	}
	return nil
}

// PreviousDeployedRelease returns the tenant's most recently deployed release
// other than exclude, which is what a bare `citadel rollback` targets.
//
// A release that was deployed and later rolled back still counts: rolled_back
// says "something newer replaced it", not "it never worked".
func PreviousDeployedRelease(ctx context.Context, db bun.IDB, tenantID, exclude string) (Release, error) {

	var r Release
	err := db.NewSelect().Model(&r).
		Where("tenant_id = ?", tenantID).
		Where("id != ?", exclude).
		Where("deployed_at IS NOT NULL").
		Where("status IN (?, ?)", ReleaseDeployed, ReleaseRolledBack).
		Order("deployed_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Release{}, fmt.Errorf("%w: no earlier deployed release for %s", ErrReleaseNotFound, tenantID)
	}
	if err != nil {

		return Release{}, err
	}
	return r, nil
}

// SetCurrentRelease points the tenant at the release now serving traffic.
func SetCurrentRelease(ctx context.Context, tx bun.Tx, tenantID, releaseID string) error {

	_, err := tx.NewUpdate().Model((*Tenant)(nil)).
		Set("current_release = ?", nullStr(releaseID)).
		Where("id = ?", tenantID).
		Exec(ctx)
	return err
}
