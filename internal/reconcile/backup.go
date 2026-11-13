package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/backup"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Snapshot takes a cold backup of a tenant's data, stopping and restarting the
// instance around it.
//
// The reconciler owns this rather than internal/backup because stopping a
// container is a reconciler concern: it holds the lock, it knows the spec, and
// it is what puts the instance back.
//
// Use this whenever something is about to roll back to the result — a deploy, an
// upgrade, a destroy. RoutineSnapshot is the live alternative, and it is not
// interchangeable: it produces a re-serialised database rather than the image
// the tenant actually had.
func (r *Reconciler) Snapshot(ctx context.Context, actor identity.Actor, t store.Tenant, kind string) (store.Backup, error) {

	lock, err := r.fs.LockWait(ctx, t.ID, lockBudget)
	if err != nil {

		return store.Backup{}, err
	}
	defer lock.Release()

	if t, err = r.lockedTenant(ctx, t.ID); err != nil {

		return store.Backup{}, err
	}
	return r.snapshotLocked(ctx, actor, t, kind, lock)
}

// snapshotLocked is Snapshot for a caller that already holds the lock — the
// deploy ladder, the upgrade ladder and teardown all do. t must have been read
// under that lock.
func (r *Reconciler) snapshotLocked(ctx context.Context, actor identity.Actor, t store.Tenant, kind string, lock *hostfs.Lock) (store.Backup, error) {

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return store.Backup{}, err
	}
	handle := driver.Handle{TenantID: t.ID, Name: spec.Name}
	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return store.Backup{}, err
	}
	wasRunning := st.Exists && st.Running
	if wasRunning {

		// The instance is put back on spec's digest afterwards. Refuse before
		// stopping it if that is not the digest it is running (INV-11).
		if err := r.digestGuard(ctx, t, st); err != nil {

			return store.Backup{}, err
		}
		if err := r.drv.Stop(ctx, handle); err != nil {

			return store.Backup{}, err
		}
	}

	b, err := r.backup.Snapshot(ctx, actor, t, kind, lock)
	if err != nil {

		// Put the instance back even when the snapshot failed: a failed backup
		// must not leave a tenant down.
		if wasRunning {

			if _, rerr := r.drv.Ensure(ctx, spec); rerr != nil {

				r.log.Error("cannot restart after a failed snapshot", "tenant", t.ID, "err", rerr)
			}
		}
		return store.Backup{}, err
	}
	if wasRunning {

		h, err := r.drv.Ensure(ctx, spec)
		if err != nil {

			return b, err
		}
		if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

			return b, err
		}
		if err := r.verifyPrevious(ctx, t); err != nil {

			return b, err
		}
	}
	return b, nil
}

// RestoreOutcome says what a successful restore left behind.
type RestoreOutcome struct {
	// LeftStopped is a forced restore across runtime versions: the instance is
	// set desired-stopped rather than booted on a binary that does not match
	// its data (INV-4).
	LeftStopped bool   `json:"left_stopped,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

// RestoreBackup writes a snapshot back over a tenant's data, stopping and
// restarting the instance around it.
//
// Two containers must never have one pb_data open (INV-3), and a restore
// rewrites the file underneath a running one — so the stop is not an
// optimisation. The instance is put back even when the restore failed, for the
// same reason a failed snapshot does not leave a tenant down.
func (r *Reconciler) RestoreBackup(ctx context.Context, actor identity.Actor, t store.Tenant, b store.Backup, force bool) (RestoreOutcome, error) {

	var out RestoreOutcome

	lock, err := r.fs.LockWait(ctx, t.ID, lockBudget)
	if err != nil {

		return out, err
	}
	defer lock.Release()

	// The pb_version guard in backup.Restore compares against this row, so it
	// must be the row as it is now, not as it was before the lock wait.
	if t, err = r.lockedTenant(ctx, t.ID); err != nil {

		return out, err
	}

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return out, err
	}
	handle := driver.Handle{TenantID: t.ID, Name: spec.Name}
	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return out, err
	}
	wasRunning := st.Exists && st.Running
	if wasRunning {

		if err := r.digestGuard(ctx, t, st); err != nil {

			return out, err
		}
		if err := r.drv.Stop(ctx, handle); err != nil {

			return out, err
		}
	}
	restoreErr := r.backup.Restore(ctx, actor, t, b, force, lock)
	// A forced restore of a snapshot taken under another runtime version is
	// data the current binary must not open (INV-4). It is left stopped for an
	// operator to pin the runtime to the snapshot's version first.
	mismatched := force && b.PBVersion != t.RuntimeVersion
	if mismatched && restoreErr == nil {

		r.log.Warn("forced restore across runtime versions; leaving the instance stopped",
			"tenant", t.ID, "backup_pb_version", b.PBVersion, "runtime", t.RuntimeVersion)
		if err := r.db.Tx(ctx, func(tx bun.Tx) error {

			if err := store.SetDesiredState(ctx, tx, t.ID, store.DesiredStopped); err != nil {

				return err
			}
			_, err := r.audit.Append(ctx, tx, auditlog.Event{
				ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
				Action: auditlog.ActionTenantStopped, SubjectRef: "tenant/" + t.ID,
				Detail: map[string]any{
					"reason":            "forced restore across runtime versions",
					"backup":            b.ID,
					"backup_pb_version": b.PBVersion,
					"runtime":           t.RuntimeVersion,
				},
			})
			return err
		}); err != nil {

			return out, err
		}
		out.LeftStopped = true
		out.Hint = fmt.Sprintf("restored data is from %s but the runtime is %s; pin-runtime to %s, then start the tenant",
			b.PBVersion, t.RuntimeVersion, b.PBVersion)
		return out, nil
	}
	if wasRunning && !mismatched {

		h, err := r.drv.Ensure(ctx, spec)
		if err != nil {

			return out, errors.Join(restoreErr, err)
		}
		if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

			r.log.Error("cannot record the restarted instance", "tenant", t.ID, "err", err)
		}
		if restoreErr == nil {

			if err := r.verifyPrevious(ctx, t); err != nil {

				return out, err
			}
		}
	}
	return out, restoreErr
}

// RoutineSnapshot backs a tenant up without stopping it (§11).
//
// The tenant keeps serving throughout: the copy is a VACUUM INTO of each
// database rather than a copy of the image. That is the only reason a nightly
// backup is acceptable at all — a stop-the-world snapshot every night is a
// nightly outage.
func (r *Reconciler) RoutineSnapshot(ctx context.Context, actor identity.Actor, t store.Tenant, kind string) (store.Backup, error) {

	// The short budget, not the long one: a routine backup that cannot get the
	// lock is skipped and taken on the next pass, and waiting would hold the
	// whole fleet's backup sweep behind one busy tenant.
	lock, err := r.fs.LockWait(ctx, t.ID, time.Second)
	if err != nil {

		return store.Backup{}, err
	}
	defer lock.Release()

	// The tenant slice the backup pass walks was read at the start of the
	// tick; the backup's pb_version is stamped from this row, so it must be
	// current (INV-4).
	if t, err = r.lockedTenant(ctx, t.ID); err != nil {

		return store.Backup{}, err
	}
	return r.backup.SnapshotLive(ctx, actor, t, kind, lock, r.liveCopier(t, lock))
}

// liveCopier copies a tenant's pb_data while it keeps serving.
//
// The databases are read from INSIDE the instance's sandbox, by pbsnap over
// driver.Snapshot: under gVisor the host cannot see PocketBase's locks, so a
// host-side SQLite connection to live pb_data unlinks its -wal and -shm on
// close (design.md INV-20).
//
// Two cases fall back to StoppedCopy, where the host is pb_data's only SQLite
// user: an instance that is not running (nothing to exec into, and nothing to
// conflict with), and an image built before pbsnap shipped, which is stopped
// for the copy and started again — a short outage, logged and audited, until
// the tenant moves to a hardening rev that carries pbsnap.
func (r *Reconciler) liveCopier(t store.Tenant, lock *hostfs.Lock) backup.Copier {

	return func(ctx context.Context, dst string) error {

		spec, err := r.specFor(ctx, t)
		if err != nil {

			return err
		}
		st, err := r.drv.Status(ctx, spec)
		if err != nil {

			return err
		}
		if !st.Exists || !st.Running {

			return r.backup.StoppedCopy(ctx, t, dst, lock)
		}
		stream := func(ctx context.Context, name string, w io.Writer) error {

			return r.drv.Snapshot(ctx, spec, name, w)
		}
		err = r.backup.LiveCopy(ctx, t, dst, lock, stream)
		if !errors.Is(err, driver.ErrExecNotFound) {

			return err
		}

		// The copy restarts the instance on spec's digest (INV-11).
		if err := r.digestGuard(ctx, t, st); err != nil {

			return err
		}
		r.log.Warn("the tenant's image has no pbsnap; stopping it for the copy",
			"tenant", t.ID, "image", t.ImageDigest, "err", err)
		r.auditTenant(ctx, t.ID, auditlog.ActionBackupStoppedCopy, "tenant/"+t.ID,
			map[string]any{"stopped": true, "reason": "image has no " + dockerdrv.PbsnapPath, "image": t.ImageDigest})
		if err := r.drv.Stop(ctx, driver.Handle{TenantID: t.ID, Name: spec.Name}); err != nil {

			return err
		}
		copyErr := r.backup.StoppedCopy(ctx, t, dst, lock)
		// Put the instance back whatever the copy did: a backup must not leave
		// a tenant down.
		h, err := r.drv.Ensure(ctx, spec)
		if err != nil {

			r.log.Error("cannot restart after a stopped copy", "tenant", t.ID, "err", err)
			return errors.Join(copyErr, err)
		}
		if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

			return errors.Join(copyErr, err)
		}
		return copyErr
	}
}

// backupPass runs the routine-backup and retention schedules (§11).
//
// On the reconcile tick rather than a cron of its own, for the same reason the
// attestation sweep is: a second scheduler is a second answer to "did it run?".
// The work itself goes to a goroutine — a VACUUM INTO of a 2 GiB database must
// not stretch a 5-second tick — and never more than one pass at a time.
func (r *Reconciler) backupPass(ctx context.Context, tenants []store.Tenant) {

	now := time.Now()
	dueRoutine := now.Sub(r.lastRoutine) >= r.cfg.RoutineBackupInterval.D() && r.cfg.InWindow(now)
	dueSweep := now.Sub(r.lastSweep) >= r.cfg.BackupSweepInterval.D()
	if !dueRoutine && !dueSweep {

		return
	}
	if r.backingUp.Load() {

		return
	}
	if dueRoutine {

		r.lastRoutine = now
	}
	if dueSweep {

		r.lastSweep = now
	}
	r.backingUp.Store(true)
	go func() {

		defer r.backingUp.Store(false)
		if dueRoutine {

			r.routineBackups(ctx, tenants)
		}
		if dueSweep {

			r.sweepBackups(ctx)
		}
	}()
}

func (r *Reconciler) routineBackups(ctx context.Context, tenants []store.Tenant) {

	actor := identity.Actor{ID: identity.PlatformPrincipal, Kind: identity.KindPlatform}
	for _, t := range tenants {

		if t.DesiredState != store.DesiredRunning {

			continue
		}
		tctx, cancel := context.WithTimeout(ctx, r.cfg.BackupTimeout.D())
		_, err := r.RoutineSnapshot(tctx, actor, t, store.BackupRoutine)
		cancel()
		if err != nil {

			if errors.Is(err, hostfs.ErrLocked) || errors.Is(err, ErrUpgradeActive) {

				// A deploy or an upgrade holds the lock. The next pass gets it;
				// both of those took a snapshot of their own anyway.
				r.log.Info("routine backup skipped, tenant is busy", "tenant", t.ID)
				continue
			}
			// §15 alerts on this. A backup that stops happening is silent by
			// construction — nothing else about the tenant changes.
			r.log.Error("ALERT: routine backup failed", "tenant", t.ID, "err", err)
			r.drift.Record(Drift{Kind: DriftBackupFailed, TenantID: t.ID, Detail: err.Error()})
			continue
		}
		r.drift.Clear(DriftBackupFailed, t.ID)
	}
}

func (r *Reconciler) sweepBackups(ctx context.Context) {

	res, err := r.backup.Sweep(ctx, time.Now().UTC())
	if err != nil {

		r.log.Error("ALERT: retention sweep failed", "err", err)
		r.drift.Record(Drift{Kind: DriftBackupFailed, Detail: "retention sweep: " + err.Error()})
		return
	}
	r.lastSweepResult.Store(&res)
	for _, e := range res.Errors {

		r.log.Error("retention sweep could not delete a snapshot", "err", e)
	}
}

// LastSweep returns the most recent retention result, for the fleet view. A nil
// result means no sweep has run since start-up, which is itself worth showing.
func (r *Reconciler) LastSweep() *backup.SweepResult { return r.lastSweepResult.Load() }
