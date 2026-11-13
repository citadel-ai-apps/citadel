package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Upgrade job states (design §12).
//
// The ladder is pending → rehearsing → snapshotting → applying → verifying →
// succeeded, with rolling_back branching off verifying. Three states are
// terminal without anything having been upgraded: blocked (the compatibility
// gate refused), rehearsed (a rehearse-only run) and failed.
const (
	UpgradePending      = "pending"
	UpgradeRehearsing   = "rehearsing"
	UpgradeSnapshotting = "snapshotting"
	UpgradeApplying     = "applying"
	UpgradeVerifying    = "verifying"
	UpgradeRollingBack  = "rolling_back"
	UpgradeSucceeded    = "succeeded"
	UpgradeFailed       = "failed"
	UpgradeBlocked      = "blocked"
	UpgradeRehearsed    = "rehearsed"
)

// Rehearsal verdicts.
const (
	RehearsalSkipped = "skipped"
	RehearsalPassed  = "passed"
	RehearsalFailed  = "failed"
)

// UpgradeTerminal lists the states from which a job never moves again.
//
// Everything else is "in flight", and an in-flight job is what blocks a deploy
// (INV-6) and what makes the reconciler leave a tenant alone. The list is here
// rather than spelled out at each call site because the partial index in
// migration 005 repeats it in SQL, and the two must agree.
var UpgradeTerminal = []string{UpgradeSucceeded, UpgradeFailed, UpgradeBlocked, UpgradeRehearsed}

// ErrUpgradeJobNotFound is returned for an unknown job id.
var ErrUpgradeJobNotFound = errors.New("store: upgrade job not found")

// ErrNoActiveUpgrade is returned when a tenant has no job in flight.
var ErrNoActiveUpgrade = errors.New("store: no active upgrade job")

// UpgradeJob is one runtime version move for one tenant.
//
// SnapshotID is written before anything is changed, not after: it is the only
// rollback path a one-way migration has (INV-4), so a job that has entered
// `applying` without it recorded is a job nobody can undo.
type UpgradeJob struct {
	bun.BaseModel `bun:"table:upgrade_job,alias:upgrade_job" json:"-"`

	ID            string     `bun:"id,pk" json:"id"`
	TenantID      string     `bun:"tenant_id" json:"tenant_id"`
	FromVersion   string     `bun:"from_version" json:"from_version"`
	ToVersion     string     `bun:"to_version" json:"to_version"`
	SnapshotID    string     `bun:"snapshot_id,nullzero" json:"snapshot_id,omitempty"`
	Rehearsal     string     `bun:"rehearsal,nullzero" json:"rehearsal,omitempty"`
	State         string     `bun:"state" json:"state"`
	Log           string     `bun:"log,nullzero" json:"log,omitempty"`
	RequestedBy   string     `bun:"requested_by,nullzero" json:"requested_by,omitempty"`
	Forced        bool       `bun:"forced" json:"forced"`
	RehearsalJSON string     `bun:"rehearsal_json,nullzero" json:"rehearsal_json,omitempty"`
	CreatedAt     time.Time  `bun:"created_at" json:"created_at"`
	FinishedAt    *time.Time `bun:"finished_at,nullzero" json:"finished_at,omitempty"`
}

// Terminal reports whether the job has stopped moving.
func (j UpgradeJob) Terminal() bool {

	for _, s := range UpgradeTerminal {

		if j.State == s {

			return true
		}
	}
	return false
}

// maxUpgradeLog caps the log column. A rehearsal against a broken package can
// produce megabytes of stack traces, and the job row is read by the portal on
// every poll.
const maxUpgradeLog = 16 << 10

// InsertUpgradeJob writes a job row inside tx.
func InsertUpgradeJob(ctx context.Context, tx bun.Tx, j UpgradeJob) error {

	if j.ID == "" {

		j.ID = NewID("uj")
	}
	if j.CreatedAt.IsZero() {

		j.CreatedAt = time.Now().UTC()
	}
	if j.State == "" {

		j.State = UpgradePending
	}
	if _, err := tx.NewInsert().Model(&j).Exec(ctx); err != nil {

		return fmt.Errorf("store: insert upgrade job %s: %w", j.ID, err)
	}
	return nil
}

// GetUpgradeJob looks a job up by id.
func GetUpgradeJob(ctx context.Context, db bun.IDB, id string) (UpgradeJob, error) {

	var j UpgradeJob
	err := db.NewSelect().Model(&j).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return UpgradeJob{}, fmt.Errorf("%w: %s", ErrUpgradeJobNotFound, id)
	}
	if err != nil {

		return UpgradeJob{}, err
	}
	return j, nil
}

// UpgradeJobFilter narrows a listing. Zero fields mean "any".
type UpgradeJobFilter struct {
	TenantID string
	State    string
	Active   bool // only jobs still in flight
	Since    time.Time
	Limit    int
}

// ListUpgradeJobs returns jobs newest first.
func ListUpgradeJobs(ctx context.Context, db bun.IDB, f UpgradeJobFilter) ([]UpgradeJob, error) {

	q := db.NewSelect().Model((*UpgradeJob)(nil)).Order("created_at DESC", "id DESC")
	if f.TenantID != "" {

		q = q.Where("tenant_id = ?", f.TenantID)
	}
	if f.State != "" {

		q = q.Where("state = ?", f.State)
	}
	if f.Active {

		q = q.Where("state NOT IN (?)", bun.In(UpgradeTerminal))
	}
	if !f.Since.IsZero() {

		q = q.Where("created_at >= ?", f.Since.UTC())
	}
	if f.Limit <= 0 {

		f.Limit = 50
	}
	var out []UpgradeJob
	err := q.Limit(f.Limit).Scan(ctx, &out)
	return out, err
}

// ActiveUpgrade returns the tenant's in-flight job, or ErrNoActiveUpgrade.
//
// This row is the durable half of the INV-6 interlock: a deploy consults it
// before it starts, and the reconciler consults it before it converges a
// tenant. The process-local claim in internal/reconcile closes the window
// around it; this is what survives a restart.
func ActiveUpgrade(ctx context.Context, db bun.IDB, tenantID string) (UpgradeJob, error) {

	var j UpgradeJob
	err := db.NewSelect().Model(&j).
		Where("tenant_id = ?", tenantID).
		Where("state NOT IN (?)", bun.In(UpgradeTerminal)).
		Order("created_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return UpgradeJob{}, ErrNoActiveUpgrade
	}
	if err != nil {

		return UpgradeJob{}, err
	}
	return j, nil
}

// ActiveUpgradeIDs maps in-flight job id to tenant id.
//
// The firewall's unbacked-rule check needs exactly this: a rule tagged
// `rehearsal=<job>` is backed while its job runs and unbacked the moment it
// does not, and the check must not have to query per rule.
func ActiveUpgradeIDs(ctx context.Context, db bun.IDB) (map[string]string, error) {

	var jobs []UpgradeJob
	err := db.NewSelect().Model(&jobs).
		Column("id", "tenant_id").
		Where("state NOT IN (?)", bun.In(UpgradeTerminal)).
		Scan(ctx)
	if err != nil {

		return nil, err
	}
	out := make(map[string]string, len(jobs))
	for _, j := range jobs {

		out[j.ID] = j.TenantID
	}
	return out, nil
}

// SetUpgradeState moves a job along the ladder, stamping finished_at when the
// new state is terminal.
//
// Always called in the same transaction as the audit event that records the
// transition (§14.4), and always BEFORE the work the new state announces:
// a crash during `applying` must leave a row that says `applying`, because
// that is the row that tells a human an irreversible migration may be half
// done.
func SetUpgradeState(ctx context.Context, tx bun.Tx, id, state string) error {

	q := tx.NewUpdate().Model((*UpgradeJob)(nil)).
		Set("state = ?", state).
		Where("id = ?", id)
	if (UpgradeJob{State: state}).Terminal() {

		q = q.Set("finished_at = ?", time.Now().UTC())
	}
	res, err := q.Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: set upgrade job %s state: %w", id, err)
	}
	return checkOneRow(res, ErrUpgradeJobNotFound, id)
}

// SetUpgradeSnapshot records the pre_upgrade snapshot the rollback depends on.
func SetUpgradeSnapshot(ctx context.Context, tx bun.Tx, id, snapshotID string) error {

	res, err := tx.NewUpdate().Model((*UpgradeJob)(nil)).
		Set("snapshot_id = ?", snapshotID).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: set upgrade job %s snapshot: %w", id, err)
	}
	return checkOneRow(res, ErrUpgradeJobNotFound, id)
}

// SetUpgradeRehearsal records the verdict and the report behind it.
func SetUpgradeRehearsal(ctx context.Context, tx bun.Tx, id, verdict, reportJSON string) error {

	res, err := tx.NewUpdate().Model((*UpgradeJob)(nil)).
		Set("rehearsal = ?", verdict).
		Set("rehearsal_json = ?", reportJSON).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: set upgrade job %s rehearsal: %w", id, err)
	}
	return checkOneRow(res, ErrUpgradeJobNotFound, id)
}

// AppendUpgradeLog adds a line to the job's log, capped at maxUpgradeLog.
//
// The cap drops the OLDEST lines, not the newest: the tail is what says how the
// job ended, and that is the part a tenant reads first.
func AppendUpgradeLog(ctx context.Context, tx bun.Tx, id, line string) error {

	j, err := GetUpgradeJob(ctx, tx, id)
	if err != nil {

		return err
	}
	text := j.Log
	if text != "" {

		text += "\n"
	}
	text += line
	if len(text) > maxUpgradeLog {

		text = text[len(text)-maxUpgradeLog:]
	}
	res, err := tx.NewUpdate().Model((*UpgradeJob)(nil)).
		Set("log = ?", text).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: append upgrade job %s log: %w", id, err)
	}
	return checkOneRow(res, ErrUpgradeJobNotFound, id)
}

// checkOneRow turns "updated nothing" into a not-found error, so a typo'd id
// fails loudly instead of succeeding silently.
func checkOneRow(res sql.Result, notFound error, id string) error {

	n, err := res.RowsAffected()
	if err != nil {

		return err
	}
	if n == 0 {

		return fmt.Errorf("%w: %s", notFound, id)
	}
	return nil
}
