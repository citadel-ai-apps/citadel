package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Backup kinds and their retention (design §11).
const (
	BackupRoutine    = "routine"
	BackupPreDeploy  = "pre_deploy"
	BackupPreUpgrade = "pre_upgrade"
	BackupManual     = "manual"
)

// Snapshot artifact formats.
//
// The two are taken under different conditions and restore differently, so the
// format is a column rather than something the restore path infers from a
// filename:
//
//	FormatImage : the tenant was stopped; a compressed copy of data.img.
//	FormatFiles : the tenant kept serving; a tar of a VACUUM INTO of pb_data.
//	              §11 permits exactly this for a routine backup of a busy
//	              instance — `cp` of a live WAL database stays forbidden.
const (
	FormatImage = "image"
	FormatFiles = "files"
)

// ErrBackupNotFound is returned for an unknown backup id.
var ErrBackupNotFound = errors.New("store: backup not found")

// Backup is one snapshot of a tenant's data image.
//
// PBVersion is load-bearing, not informational: restoring a snapshot written by
// an older binary onto a newer runtime re-triggers the one-way migration
// , so the restore path reads this column before it touches anything.
type Backup struct {
	bun.BaseModel `bun:"table:backup,alias:backup" json:"-"`

	ID        string `bun:"id,pk" json:"id"`
	TenantID  string `bun:"tenant_id" json:"tenant_id"`
	Kind      string `bun:"kind" json:"kind"`
	Format    string `bun:"format" json:"format"`
	Path      string `bun:"path" json:"path"`
	SizeBytes int64  `bun:"size_bytes,nullzero" json:"size_bytes,omitempty"`
	PBVersion string `bun:"pb_version" json:"pb_version"`
	// Sha256 is the archive's digest when it was written; a restore checks it
	// before decompressing anything over a tenant's data. Empty on rows from
	// before migration 007.
	Sha256      string     `bun:"sha256,nullzero" json:"sha256,omitempty"`
	RetainUntil *time.Time `bun:"retain_until,nullzero" json:"retain_until,omitempty"`
	CreatedAt   time.Time  `bun:"created_at" json:"created_at"`
}

// InsertBackup writes a backup row inside tx.
func InsertBackup(ctx context.Context, tx bun.Tx, b Backup) error {

	if b.CreatedAt.IsZero() {

		b.CreatedAt = time.Now().UTC()
	}
	if b.Format == "" {

		b.Format = FormatImage
	}
	if _, err := tx.NewInsert().Model(&b).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert backup %s: %w", b.ID, err)
	}
	return nil
}

// GetBackup looks a backup up by id.
func GetBackup(ctx context.Context, db bun.IDB, id string) (Backup, error) {

	var b Backup
	err := db.NewSelect().Model(&b).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Backup{}, fmt.Errorf("%w: %s", ErrBackupNotFound, id)
	}
	if err != nil {

		return Backup{}, err
	}
	return b, nil
}

// ListBackups returns a tenant's snapshots, newest first.
func ListBackups(ctx context.Context, db bun.IDB, tenantID string) ([]Backup, error) {

	var out []Backup
	err := db.NewSelect().Model(&out).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC", "rowid DESC").
		Scan(ctx)
	return out, err
}

// DeleteBackup removes a backup row inside tx.
//
// The row goes first and the file second (see internal/backup's sweep): a crash
// between the two leaks a file, which an orphan scan finds and which harms
// nobody, where the reverse order leaks a row pointing at nothing — and that is
// discovered by a restore, at the worst possible moment.
func DeleteBackup(ctx context.Context, tx bun.Tx, id string) error {

	res, err := tx.NewDelete().Model((*Backup)(nil)).Where("id = ?", id).Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: delete backup %s: %w", id, err)
	}
	return checkOneRow(res, ErrBackupNotFound, id)
}

// ExpiredBackups returns every snapshot past its retention, oldest first.
//
// Deciding WHICH of these may actually go is the sweep's job, not this query's:
// §11's retention table is a ceiling, and two rows that have passed it must
// still survive — a tenant's last remaining snapshot, and any snapshot an
// in-flight upgrade job depends on for its rollback.
func ExpiredBackups(ctx context.Context, db bun.IDB, now time.Time) ([]Backup, error) {

	var out []Backup
	err := db.NewSelect().Model(&out).
		Where("retain_until IS NOT NULL").
		Where("retain_until < ?", now.UTC()).
		Order("retain_until", "id").
		Scan(ctx)
	return out, err
}

// NewestBackup returns a tenant's most recent snapshot of any kind.
func NewestBackup(ctx context.Context, db bun.IDB, tenantID string) (Backup, error) {

	var b Backup
	err := db.NewSelect().Model(&b).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC", "rowid DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Backup{}, fmt.Errorf("%w: no backup for %s", ErrBackupNotFound, tenantID)
	}
	if err != nil {

		return Backup{}, err
	}
	return b, nil
}

// BackupsReferencedByJobs returns the snapshot ids an in-flight upgrade job
// still needs. INV-4 makes those the only rollback path there is, so no
// retention rule may take one.
func BackupsReferencedByJobs(ctx context.Context, db bun.IDB) (map[string]bool, error) {

	var ids []string
	err := db.NewSelect().Model((*UpgradeJob)(nil)).
		Column("snapshot_id").
		Where("snapshot_id IS NOT NULL").
		Where("state NOT IN (?)", bun.In(UpgradeTerminal)).
		Scan(ctx, &ids)
	if err != nil {

		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {

		out[id] = true
	}
	return out, nil
}

// NewestBackupPerTenant maps tenant id to its most recent snapshot time, which
// is how the fleet view answers "whose routine backup has stopped running?".
func NewestBackupPerTenant(ctx context.Context, db bun.IDB, kind string) (map[string]time.Time, error) {

	var rows []struct {
		TenantID string    `bun:"tenant_id"`
		Newest   time.Time `bun:"newest"`
	}
	q := db.NewSelect().Model((*Backup)(nil)).
		ColumnExpr("tenant_id").
		ColumnExpr("MAX(created_at) AS newest").
		GroupExpr("tenant_id")
	if kind != "" {

		q = q.Where("kind = ?", kind)
	}
	if err := q.Scan(ctx, &rows); err != nil {

		return nil, err
	}
	out := make(map[string]time.Time, len(rows))
	for _, r := range rows {

		out[r.TenantID] = r.Newest
	}
	return out, nil
}

// LatestBackup returns a tenant's most recent snapshot of the given kind, which
// is what a failed deploy restores from.
func LatestBackup(ctx context.Context, db bun.IDB, tenantID, kind string) (Backup, error) {

	var b Backup
	err := db.NewSelect().Model(&b).
		Where("tenant_id = ?", tenantID).
		Where("kind = ?", kind).
		Order("created_at DESC", "rowid DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Backup{}, fmt.Errorf("%w: no %s backup for %s", ErrBackupNotFound, kind, tenantID)
	}
	if err != nil {

		return Backup{}, err
	}
	return b, nil
}
