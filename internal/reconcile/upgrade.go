package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Upgrade refusals the API maps onto specific status codes.
var (
	// ErrDeployActive is INV-6 in the other direction from ErrUpgradeActive.
	ErrDeployActive = errors.New("reconcile: a deploy is in flight for this tenant; deploys and upgrades never overlap")
	// ErrUpgradeBlocked is the compatibility gate: the target version is
	// outside the range the deployed release declared it works on.
	ErrUpgradeBlocked = errors.New("reconcile: the target runtime version is outside the deployed release's declared range")
	// ErrSameVersion is an upgrade to the version and image already running.
	ErrSameVersion = errors.New("reconcile: the tenant already runs that version and image")
	// ErrDowngrade is a request to move backwards. Not merely refused: a
	// downgrade is a category error, because a newer binary has already migrated
	// pb_data and the old one cannot be trusted with it (INV-4).
	ErrDowngrade = errors.New("reconcile: runtime upgrades are one-way; going back is a snapshot restore, not an upgrade (INV-4)")
	// ErrVersionNotUpgradable is a target the platform is retiring.
	ErrVersionNotUpgradable = errors.New("reconcile: the target version is deprecated or end-of-life")
	// ErrNotRunning is an upgrade of a tenant that is not meant to be up.
	ErrNotRunning = errors.New("reconcile: the tenant is not running; start it before upgrading")
	// ErrTooManyUpgrades is the fleet-wide concurrency cap.
	ErrTooManyUpgrades = errors.New("reconcile: too many upgrades are already in flight; try again shortly")
)

// Claim kinds for the process-local interlock.
const (
	claimDeploy  = "deploy"
	claimUpgrade = "upgrade"
)

// claim takes the process-local half of INV-6 for one tenant.
//
// Three layers enforce "never move both version axes at once", and each covers
// what the others cannot:
//
//  1. this claim, which closes the window between a gate that reads the job
//     table and the lock that is taken several steps later;
//  2. the upgrade_job row, which survives a restart;
//  3. the instance.lock, which stops two processes touching one container.
//
// Process-local is sufficient because there is exactly one control plane on the
// host. Said explicitly rather than implied: this is not a distributed lock and
// must not be mistaken for one if the platform ever grows a second node.
func (r *Reconciler) claim(tenantID, kind string) (func(), error) {

	r.claimMu.Lock()
	defer r.claimMu.Unlock()

	if held, ok := r.claims[tenantID]; ok {

		if held == claimUpgrade {

			return nil, ErrUpgradeActive
		}
		return nil, ErrDeployActive
	}
	if kind == claimUpgrade && r.upgrades >= r.cfg.MaxConcurrentUpgrades {

		// Each upgrade is an mkfs, a multi-gigabyte copy and two container
		// boots. An EOL sweep that started twenty at once would take the host
		// down in the name of keeping it current.
		return nil, ErrTooManyUpgrades
	}
	r.claims[tenantID] = kind
	if kind == claimUpgrade {

		r.upgrades++
	}
	return func() {

		r.claimMu.Lock()
		defer r.claimMu.Unlock()
		if r.claims[tenantID] == claimUpgrade {

			r.upgrades--
		}
		delete(r.claims, tenantID)
	}, nil
}

// UpgradeRequest is what the caller asked for.
type UpgradeRequest struct {
	// To is the target runtime version.
	To string
	// RehearseOnly stops after the rehearsal, whatever its verdict. Nothing is
	// snapshotted and nothing is applied.
	RehearseOnly bool
	// SkipRehearsal goes straight to the snapshot. Operator-only, recorded as
	// rehearsal='skipped' so the job says what was not done.
	SkipRehearsal bool
	// Forced is the EOL path (§12). It relaxes the state gate — the whole point
	// is to move tenants off a version nobody may choose any more — and relaxes
	// nothing else. In particular it never skips the snapshot, and a forced
	// job whose rehearsal fails is quarantined rather than applied (see
	// eol.go).
	Forced bool
}

// StartUpgrade opens an upgrade job and runs it in the background.
//
// Everything that can be refused without touching the host is refused here,
// synchronously, so the caller gets a real error rather than a job id and a
// failure to poll for. Everything else happens on a detached goroutine: a
// rehearsal is an mkfs plus a copy plus a container boot plus the smoke set,
// which is minutes, and §8.4's GET /upgrade/:jobid exists precisely because
// that cannot be an HTTP round trip.
func (r *Reconciler) StartUpgrade(ctx context.Context, actor identity.Actor, t store.Tenant, req UpgradeRequest) (store.UpgradeJob, error) {

	unclaim, err := r.claim(t.ID, claimUpgrade)
	if err != nil {

		return store.UpgradeJob{}, err
	}
	ok := false
	defer func() {

		if !ok {

			unclaim()
		}
	}()

	target, man, blocked, err := r.upgradeGates(ctx, t, req)
	if err != nil {

		return store.UpgradeJob{}, err
	}

	job := store.UpgradeJob{
		ID:          store.NewID("uj"),
		TenantID:    t.ID,
		FromVersion: t.RuntimeVersion,
		ToVersion:   target.Version,
		State:       store.UpgradePending,
		RequestedBy: actor.ID,
		Forced:      req.Forced,
	}
	if req.SkipRehearsal {

		job.Rehearsal = store.RehearsalSkipped
	}
	err = r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertUpgradeJob(ctx, tx, job); err != nil {

			return err
		}
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant, Kind: store.NotifyUpgradeResult,
			SubjectRef: "upgrade/" + job.ID,
			Body: fmt.Sprintf("A runtime upgrade from %s to %s has started%s.",
				job.FromVersion, job.ToVersion, forcedSuffix(req.Forced)),
		}); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionUpgradeRequested,
			SubjectRef: "upgrade/" + job.ID,
			Detail: map[string]any{
				"from": job.FromVersion, "to": job.ToVersion,
				"forced": req.Forced, "rehearse_only": req.RehearseOnly,
				"skip_rehearsal": req.SkipRehearsal,
			},
		})
		return err
	})
	if err != nil {

		return store.UpgradeJob{}, err
	}

	if blocked != "" {

		// §12's `pending → blocked`. The row is the answer, and it is the only
		// durable one: nothing is copied, nothing is booted, nothing is
		// snapshotted, and the reason is on the job where the tenant will look
		// for it.
		r.log.Info("upgrade blocked by the compatibility gate",
			"tenant", t.ID, "job", job.ID, "to", target.Version, "reason", blocked)
		r.appendLog(ctx, job, blocked)
		r.finish(ctx, actor, t, job, store.UpgradeBlocked, auditlog.ActionUpgradeBlocked,
			blocked, map[string]any{"to": target.Version, "reason": trimDetail(blocked)})
		job.State = store.UpgradeBlocked
		job.Log = blocked
		return job, nil
	}
	ok = true

	// Detached from the request context but bounded. A client hanging up must
	// not abandon a half-applied one-way migration; an upgrade that hangs must
	// not do so forever.
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.cfg.UpgradeTimeout.D())
	go func() {

		defer cancel()
		defer unclaim()
		r.runUpgrade(runCtx, actor, t, job, target, man, req)
	}()
	return job, nil
}

// upgradeGates decides whether an upgrade can proceed, and how it is refused.
//
// Two shapes of refusal, and the difference is deliberate:
//
//   - an ERROR is a malformed request — an unknown version, a downgrade, the
//     tenant already on that version, another job in flight. Nothing happened
//     and there is nothing to record; the caller gets a 4xx.
//   - a BLOCK REASON is the §12 compatibility gate. The request was reasonable
//     and the platform refused it on the tenant's own evidence, so it becomes a
//     `blocked` job: a row, an audit event and a notice, saying exactly which
//     range was declared and which version fell outside it. That is what §12's
//     "tell the tenant exactly which hooks/APIs are at risk" needs somewhere
//     durable — an HTTP error nobody kept is not an answer to "why did my
//     upgrade not happen?" three days later.
//
// Nothing is touched on either path.
func (r *Reconciler) upgradeGates(ctx context.Context, t store.Tenant, req UpgradeRequest) (store.RuntimeVersion, pkgvalidate.Manifest, string, error) {

	var man pkgvalidate.Manifest

	if t.DesiredState != store.DesiredRunning {

		return store.RuntimeVersion{}, man, "", ErrNotRunning
	}
	if t.FrozenReason != "" {

		return store.RuntimeVersion{}, man, "", fmt.Errorf("%w: %s", ErrFrozen, t.FrozenReason)
	}
	target, err := store.GetRuntimeVersion(ctx, r.db.Reader(), req.To)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	cmp, err := pkgvalidate.Compare(target.Version, t.RuntimeVersion)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	switch {

	case cmp == 0 && target.ImageDigest == t.ImageDigest:
		return store.RuntimeVersion{}, man, "", fmt.Errorf("%w: %s", ErrSameVersion, t.RuntimeVersion)
	case cmp == 0:
		// Same PocketBase version, newer hardening rev. The registry row only
		// ever moves forward (store.UpsertRuntimeVersion refuses a lower rev),
		// so a digest that differs from the tenant's is a newer image. It is
		// still an image change, so it takes the whole ladder: rehearsal,
		// snapshot, verify (INV-11).
	case cmp < 0:
		return store.RuntimeVersion{}, man, "", fmt.Errorf("%w: %s is below %s",
			ErrDowngrade, target.Version, t.RuntimeVersion)
	}
	active, err := r.upgradeActive(ctx, t.ID)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	if active {

		return store.RuntimeVersion{}, man, "", ErrUpgradeActive
	}
	// A hardening bump within the version a tenant already runs is a patch,
	// which a deprecated line still takes (§12).
	if !target.Upgradable() && !req.Forced && cmp != 0 {

		return target, man, fmt.Sprintf(
			"%s is %s, so it is not offered as an upgrade target", target.Version, target.State), nil
	}

	// The compatibility gate is against the DEPLOYED release's manifest, not
	// the newest uploaded one: the question is whether the code currently
	// running will run on the target binary.
	if t.CurrentRelease == "" {

		// Nothing deployed, so nothing to break. Upgrading an empty instance is
		// the cheapest time to do it.
		return target, man, "", nil
	}
	rel, err := store.GetRelease(ctx, r.db.Reader(), t.CurrentRelease)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	man, err = release.Manifest(rel)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	okRange, err := pkgvalidate.Satisfies(target.Version, man.PocketBase.Min, man.PocketBase.Max)
	if err != nil {

		return store.RuntimeVersion{}, man, "", err
	}
	if !okRange && !req.Forced {

		return target, man, fmt.Sprintf(
			"release %s declares pocketbase %s–%s, and %s is outside it. Its hooks were written against that range and may not register on %s",
			rel.ID, orAny(man.PocketBase.Min), orAny(man.PocketBase.Max),
			target.Version, target.Version), nil
	}
	return target, man, "", nil
}

// runUpgrade drives the §12 ladder. It never returns an error: the job row and
// the audit chain are the report, and there is nobody left to return one to.
func (r *Reconciler) runUpgrade(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, target store.RuntimeVersion, man pkgvalidate.Manifest, req UpgradeRequest) {

	if !req.SkipRehearsal {

		if !r.rehearseFor(ctx, actor, t, job, target, man, req) {

			return
		}
		if req.RehearseOnly {

			r.finish(ctx, actor, t, job, store.UpgradeRehearsed, auditlog.ActionUpgradeSucceeded,
				"rehearsal complete; nothing was upgraded", nil)
			return
		}

	} else {

		r.log.Warn("upgrading without a rehearsal", "tenant", t.ID, "job", job.ID)
		r.appendLog(ctx, job, "rehearsal skipped by request")
	}

	// SNAPSHOTTING. The lock is taken here and held to the end of the ladder:
	// everything below stops, replaces and restarts the container.
	r.setUpgradeState(ctx, actor, t, job, store.UpgradeSnapshotting, "", nil)
	lock, err := r.fs.LockWait(ctx, t.ID, lockBudget)
	if err != nil {

		r.fail(ctx, actor, t, job, "cannot take the tenant lock: "+err.Error())
		return
	}
	defer lock.Release()

	// Re-read under the lock: a deploy may have changed the release or the
	// digest between the gate and here.
	fresh, err := store.GetTenant(ctx, r.db.Reader(), t.ID)
	if err != nil {

		r.fail(ctx, actor, t, job, err.Error())
		return
	}
	t = fresh
	fromVersion, fromDigest := t.RuntimeVersion, t.ImageDigest

	spec, err := r.specFor(ctx, t)
	if err != nil {

		r.fail(ctx, actor, t, job, err.Error())
		return
	}
	handle := driver.Handle{TenantID: t.ID, Name: spec.Name}
	// The snapshot is labelled fromVersion and the failure path restarts on
	// fromDigest; both are wrong if the instance is not actually on it.
	if _, err := r.guardedStatus(ctx, t, spec); err != nil {

		r.fail(ctx, actor, t, job, err.Error())
		return
	}
	if err := r.drv.Stop(ctx, handle); err != nil {

		r.fail(ctx, actor, t, job, "cannot stop the instance: "+err.Error())
		return
	}
	// The IMAGE format, not the live one: this snapshot is the rollback path
	// (INV-4), and a rollback wants the bytes the tenant actually had.
	snap, err := r.backup.Snapshot(ctx, actor, t, store.BackupPreUpgrade, lock)
	if err != nil {

		// Put the instance back before failing: no snapshot means no upgrade,
		// but it must not also mean an outage.
		if _, rerr := r.drv.Ensure(ctx, spec); rerr != nil {

			r.log.Error("cannot restart after a failed pre-upgrade snapshot", "tenant", t.ID, "err", rerr)
		}
		r.fail(ctx, actor, t, job, "pre-upgrade snapshot failed: "+err.Error())
		return
	}
	// Recorded BEFORE anything changes (§12): a job that has entered
	// `applying` without its snapshot id on the row is a job nobody can undo.
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetUpgradeSnapshot(ctx, tx, job.ID, snap.ID)
	}); err != nil {

		r.fail(ctx, actor, t, job, "cannot record the snapshot id: "+err.Error())
		return
	}
	job.SnapshotID = snap.ID

	// APPLYING. The row change and the container recreate are one locked
	// sequence: a tick landing between them would compare a new desired digest
	// against an old running one and raise a digest-drift alert the platform
	// manufactured itself (INV-11).
	r.setUpgradeState(ctx, actor, t, job, store.UpgradeApplying, auditlog.ActionUpgradeApplied,
		map[string]any{"from": fromVersion, "to": target.Version, "snapshot": snap.ID})
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetRuntimeVersion(ctx, tx, t.ID, target.Version, target.ImageDigest)
	}); err != nil {

		r.fail(ctx, actor, t, job, "cannot record the new runtime version: "+err.Error())
		return
	}
	t.RuntimeVersion, t.ImageDigest = target.Version, target.ImageDigest
	spec.ImageDigest = target.ImageDigest

	// Destroy then Ensure, not Ensure alone: the image is part of the create
	// spec, and diffSpec would recreate anyway — doing it explicitly means the
	// old container is gone before the new one starts against the same pb_data
	// (INV-3).
	if err := r.drv.Destroy(ctx, handle); err != nil {

		r.rollbackUpgrade(ctx, actor, t, job, snap, fromVersion, fromDigest, spec, handle, lock,
			"cannot remove the old container: "+err.Error())
		return
	}
	newHandle, err := r.drv.Ensure(ctx, spec)
	if err != nil {

		r.rollbackUpgrade(ctx, actor, t, job, snap, fromVersion, fromDigest, spec, handle, lock,
			"cannot start on the new version: "+err.Error())
		return
	}
	if err := r.recordStarted(ctx, t, newHandle.ContainerID); err != nil {

		r.log.Error("cannot record the started instance", "tenant", t.ID, "err", err)
	}
	if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

		r.log.Error("cannot re-attach the edge after an upgrade", "tenant", t.ID, "err", err)
	}

	// VERIFYING. Never the health check alone: a version-mismatched binary
	// serves /api/health 200 with a broken data plane (design.md INV-4),
	// which is the exact failure this ladder exists to catch.
	r.setUpgradeState(ctx, actor, t, job, store.UpgradeVerifying, "", nil)
	if err := r.verify(ctx, t, man); err != nil {

		r.appendLog(ctx, job, "verification failed: "+err.Error())
		r.appendLog(ctx, job, r.tailLogs(ctx, newHandle))
		r.rollbackUpgrade(ctx, actor, t, job, snap, fromVersion, fromDigest, spec, newHandle, lock,
			err.Error())
		return
	}
	// Hook-registration errors fail the verification too, even when every smoke
	// request passed.
	//
	// They have to. PocketBase catches a throwing hook file and keeps serving,
	// so an instance whose hooks stopped registering answers HTTP perfectly and
	// does none of its own work — no scheduled jobs, no validation, no
	// side-effects. A rehearsal already fails on exactly this evidence
	// (see Rehearse); verification reading the same log and shrugging would
	// mean the platform says "your app is broken" before the upgrade and "fine"
	// after it, from identical output.
	if hookErrs := health.HookErrors(r.tailLogs(ctx, newHandle)); len(hookErrs) > 0 {

		reason := "the hooks did not register on " + target.Version + ": " + strings.Join(hookErrs, "; ")
		r.appendLog(ctx, job, reason)
		r.rollbackUpgrade(ctx, actor, t, job, snap, fromVersion, fromDigest, spec, newHandle, lock,
			trimDetail(reason))
		return
	}

	r.finish(ctx, actor, t, job, store.UpgradeSucceeded, auditlog.ActionUpgradeSucceeded,
		fmt.Sprintf("upgraded %s → %s", fromVersion, target.Version),
		map[string]any{"from": fromVersion, "to": target.Version, "snapshot": snap.ID})
	r.drift.Clear(DriftUpgradeRollback, t.ID)
	r.log.Info("runtime upgraded", "tenant", t.ID, "job", job.ID,
		"from", fromVersion, "to", target.Version)
}

// rehearseFor runs the rehearsal phase and reports whether the ladder continues.
func (r *Reconciler) rehearseFor(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, target store.RuntimeVersion, man pkgvalidate.Manifest, req UpgradeRequest) bool {

	r.setUpgradeState(ctx, actor, t, job, store.UpgradeRehearsing, auditlog.ActionUpgradeRehearsalStarted,
		map[string]any{"to": target.Version})

	rep := r.Rehearse(ctx, t, job, target, man)
	verdict := store.RehearsalPassed
	if !rep.Passed {

		verdict = store.RehearsalFailed
	}
	raw, _ := json.Marshal(rep)
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetUpgradeRehearsal(ctx, tx, job.ID, verdict, string(raw))
	}); err != nil {

		r.log.Error("cannot record the rehearsal report", "job", job.ID, "err", err)
	}
	r.notifyRehearsal(ctx, t, job, rep)

	if rep.Passed {

		r.auditTenantAs(ctx, actor, t.ID, auditlog.ActionUpgradeRehearsalPassed, "upgrade/"+job.ID,
			map[string]any{"to": target.Version})
		return true
	}
	r.auditTenantAs(ctx, actor, t.ID, auditlog.ActionUpgradeRehearsalFailed, "upgrade/"+job.ID,
		map[string]any{"to": target.Version, "failures": len(rep.Failures)})

	// A forced job does not proceed on a failed rehearsal either. It follows
	// the D11 default (design.md §12): quarantine is reversible and costs
	// availability, a one-way migration onto hooks that are KNOWN broken costs
	// availability and possibly the application.
	if req.Forced {

		r.quarantineForEOL(ctx, actor, t, job, rep)
	}
	summary := "nothing was touched; no snapshot was taken"
	r.fail(ctx, actor, t, job, "rehearsal failed: "+strings.Join(rep.Failures, "; ")+" ("+summary+")")
	return false
}

// rollbackUpgrade restores the pre-upgrade snapshot and reverts the digest.
//
// The version row is reverted BEFORE the restore, and that order is the point:
// it keeps backup.Restore's pb_version guard armed, so the rollback has to
// prove it is putting back what it took. Passing force=true instead would
// disable the one check that catches this class of mistake.
func (r *Reconciler) rollbackUpgrade(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, snap store.Backup, fromVersion, fromDigest string, spec driver.InstanceSpec, handle driver.Handle, lock *hostfs.Lock, reason string) {

	r.setUpgradeState(ctx, actor, t, job, store.UpgradeRollingBack, "", map[string]any{"reason": reason})
	r.log.Error("upgrade failed, rolling back", "tenant", t.ID, "job", job.ID, "err", reason)

	fail := func(err error) {

		// Both the upgrade and its rollback failed. Name both, alert, and hold
		// the tenant stopped and quarantined: the version row and pb_data may
		// now disagree — reverted row, migrated data — and letting the
		// reconciler converge would boot the old binary on it (INV-4). The
		// data is still in the snapshot, and a human decides what happens next.
		detail := fmt.Sprintf("upgrade failed (%s) and rollback failed (%v); snapshot %s", reason, err, snap.ID)
		r.drift.Record(Drift{Kind: DriftUpgradeStuck, TenantID: t.ID, Security: true, Detail: detail})
		r.holdForOperator(ctx, actor, t, detail)
		r.fail(ctx, actor, t, job, fmt.Sprintf("upgrade failed (%s) AND rollback failed (%v); the pre-upgrade snapshot is %s. "+
			"The tenant is stopped and quarantined", reason, err, snap.ID))
	}

	if err := r.drv.Stop(ctx, handle); err != nil {

		fail(err)
		return
	}
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetRuntimeVersion(ctx, tx, t.ID, fromVersion, fromDigest)
	}); err != nil {

		fail(err)
		return
	}
	t.RuntimeVersion, t.ImageDigest = fromVersion, fromDigest
	spec.ImageDigest = fromDigest

	if err := r.backup.Restore(ctx, actor, t, snap, false, lock); err != nil {

		fail(err)
		return
	}
	if err := r.drv.Destroy(ctx, handle); err != nil {

		fail(err)
		return
	}
	newHandle, err := r.drv.Ensure(ctx, spec)
	if err != nil {

		fail(err)
		return
	}
	if err := r.recordStarted(ctx, t, newHandle.ContainerID); err != nil {

		r.log.Error("cannot record the restarted instance", "tenant", t.ID, "err", err)
	}
	if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

		r.log.Error("cannot re-attach the edge after a rollback", "tenant", t.ID, "err", err)
	}
	// Recorded HERE, before verification, because by this point the rollback
	// has happened: the version row is back, the snapshot is restored and the
	// container is recreated. Whether the instance then comes up healthy is a
	// separate fact — and if it does not, "we rolled back" is precisely the
	// event a human reconstructing the incident needs to find. Auditing it only
	// on the happy path would lose it exactly when it matters.
	//
	// §15 alerts on the drift entry: the tenant ends up serving the version they
	// started on, so nothing else about the instance says anything happened.
	r.drift.Record(Drift{Kind: DriftUpgradeRollback, TenantID: t.ID,
		Detail: fmt.Sprintf("upgrade to %s failed and was rolled back: %s", job.ToVersion, reason)})
	r.auditTenantAs(ctx, actor, t.ID, auditlog.ActionUpgradeRolledBack, "upgrade/"+job.ID,
		map[string]any{"to": job.ToVersion, "snapshot": snap.ID, "reason": trimDetail(reason)})

	if err := r.verifyPrevious(ctx, t); err != nil {

		// The rollback ran and the instance still is not serving. The
		// reconciler keeps trying to converge it; this says so loudly rather
		// than reporting the rollback as clean.
		r.drift.Record(Drift{Kind: DriftUpgradeStuck, TenantID: t.ID, Security: true,
			Detail: fmt.Sprintf("rolled back to %s from snapshot %s and the instance is still not healthy: %v",
				fromVersion, snap.ID, err)})
		r.fail(ctx, actor, t, job, fmt.Sprintf(
			"upgrade failed (%s); the rollback restored snapshot %s and reverted to %s, but the instance is still not healthy: %v",
			reason, snap.ID, fromVersion, err))
		return
	}
	r.fail(ctx, actor, t, job, "upgrade failed and was rolled back: "+reason)
}

// holdForOperator stops and quarantines a tenant whose runtime version and
// pb_data may disagree, so nothing restarts it until an operator has looked.
//
// Desired-stopped is what keeps the reconciler from starting it; the digest
// guard is the backstop. Quarantine puts the edge on a 503, and the reason goes
// to the tenant's portal (the 503 itself carries none), so the tenant is told
// rather than left with a dead hostname.
func (r *Reconciler) holdForOperator(ctx context.Context, actor identity.Actor, t store.Tenant, reason string) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetDesiredState(ctx, tx, t.ID, store.DesiredStopped); err != nil {

			return err
		}
		if err := store.SetQuarantined(ctx, tx, t.ID, true); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionTenantQuarantined, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{"reason": trimDetail(reason), "stopped": true},
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot hold the tenant for an operator; the digest guard is the only thing stopping a restart",
			"tenant", t.ID, "err", err)
		return
	}
	t.Quarantined = true
	if err := r.publishRoute(ctx, t); err != nil {

		r.log.Error("cannot republish the quarantined route", "tenant", t.ID, "err", err)
	}
}

// setUpgradeState moves the job and records the move, in one transaction.
func (r *Reconciler) setUpgradeState(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, state, action string, detail map[string]any) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetUpgradeState(ctx, tx, job.ID, state); err != nil {

			return err
		}
		if action == "" {

			return nil
		}
		if detail == nil {

			detail = map[string]any{}
		}
		detail["state"] = state
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     action,
			SubjectRef: "upgrade/" + job.ID,
			Detail:     detail,
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot record an upgrade state change", "job", job.ID, "state", state, "err", err)
	}
}

// fail ends a job, telling the tenant why.
func (r *Reconciler) fail(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, reason string) {

	r.appendLog(ctx, job, reason)
	r.finish(ctx, actor, t, job, store.UpgradeFailed, auditlog.ActionUpgradeFailed, reason,
		map[string]any{"to": job.ToVersion})
}

// finish writes a terminal state, its audit event and the tenant's notice
// together, so a job can never end without the tenant being told.
func (r *Reconciler) finish(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, state, action, body string, detail map[string]any) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetUpgradeState(ctx, tx, job.ID, state); err != nil {

			return err
		}
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant, Kind: store.NotifyUpgradeResult,
			SubjectRef: "upgrade/" + job.ID,
			Body:       fmt.Sprintf("Runtime upgrade %s → %s: %s. %s", job.FromVersion, job.ToVersion, state, body),
		}); err != nil {

			return err
		}
		if detail == nil {

			detail = map[string]any{}
		}
		detail["state"] = state
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     action,
			SubjectRef: "upgrade/" + job.ID,
			Detail:     detail,
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot finish an upgrade job", "job", job.ID, "state", state, "err", err)
	}
}

func (r *Reconciler) appendLog(ctx context.Context, job store.UpgradeJob, line string) {

	if strings.TrimSpace(line) == "" {

		return
	}
	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.AppendUpgradeLog(ctx, tx, job.ID, line)
	})
	if err != nil {

		r.log.Error("cannot append to an upgrade log", "job", job.ID, "err", err)
	}
}

// notifyRehearsal puts the report in front of the tenant (§16 task 6).
func (r *Reconciler) notifyRehearsal(ctx context.Context, t store.Tenant, job store.UpgradeJob, rep RehearsalReport) {

	body := fmt.Sprintf("Rehearsal for the %s → %s upgrade passed. No egress was reachable from it.",
		job.FromVersion, job.ToVersion)
	if !rep.Passed {

		// The failures are quoted verbatim. A tenant is about to go and fix
		// their hooks, and a summary they cannot act on wastes the rehearsal.
		body = fmt.Sprintf("Rehearsal for the %s → %s upgrade FAILED, so nothing was upgraded and no snapshot was taken. %s",
			job.FromVersion, job.ToVersion, strings.Join(rep.Failures, " | "))
	}
	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant, Kind: store.NotifyUpgradeRehearsal,
			SubjectRef: "upgrade/" + job.ID, Body: trimBody(body),
		})
	})
	if err != nil {

		r.log.Error("cannot notify the tenant of a rehearsal", "job", job.ID, "err", err)
	}
}

// auditTenantAs is auditTenant with a real actor instead of the platform.
func (r *Reconciler) auditTenantAs(ctx context.Context, actor identity.Actor, tenantID, action, subject string, detail map[string]any) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenantID,
			Action: action, SubjectRef: subject, Detail: detail,
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot write audit event", "tenant", tenantID, "action", action, "err", err)
	}
}

// reapUpgrades fails jobs the control plane abandoned by restarting.
//
// Deliberately NOT a resume. An `applying` job that was interrupted may have
// run PocketBase's system migrations, which are irreversible, and picking the
// ladder back up from an unknown point is worse than stopping and asking a
// human (INV-4). What this does is close the row — so the tenant is not blocked
// from deploying forever — and raise drift when the digests disagree.
func (r *Reconciler) reapUpgrades(ctx context.Context) {

	jobs, err := store.ListUpgradeJobs(ctx, r.db.Reader(), store.UpgradeJobFilter{Active: true, Limit: 200})
	if err != nil {

		r.log.Error("cannot list active upgrade jobs", "err", err)
		return
	}
	cutoff := time.Now().UTC().Add(-r.cfg.UpgradeTimeout.D())
	for _, job := range jobs {

		if job.CreatedAt.After(cutoff) {

			continue
		}
		r.claimMu.Lock()
		_, running := r.claims[job.TenantID]
		r.claimMu.Unlock()
		if running {

			// This process is still working on it; the job's own timeout will
			// end it.
			continue
		}
		t, err := store.GetTenant(ctx, r.db.Reader(), job.TenantID)
		if err != nil {

			r.log.Error("cannot read the tenant of an abandoned job", "job", job.ID, "err", err)
			continue
		}
		reason := "the control plane restarted during this job; it was not resumed"
		if job.State == store.UpgradeApplying || job.State == store.UpgradeRollingBack {

			reason += fmt.Sprintf(". The tenant is recorded on %s; check the running digest and the %s snapshot before acting",
				t.RuntimeVersion, orNone(job.SnapshotID))
			detail := fmt.Sprintf("job %s was abandoned in %s; snapshot %s", job.ID, job.State, orNone(job.SnapshotID))
			r.drift.Record(Drift{Kind: DriftUpgradeStuck, TenantID: t.ID, Security: true, Detail: detail})
			// Same reason as a failed rollback: nobody knows which binary
			// pb_data was last migrated by.
			r.holdForOperator(ctx, identity.Actor{ID: identity.PlatformPrincipal, Kind: identity.KindPlatform}, t, detail)
		}
		r.log.Error("failing an abandoned upgrade job", "job", job.ID, "tenant", t.ID, "state", job.State)
		platform := identity.Actor{ID: identity.PlatformPrincipal, Kind: identity.KindPlatform}
		r.finish(ctx, platform, t, job, store.UpgradeFailed, auditlog.ActionUpgradeAbandoned, reason,
			map[string]any{"abandoned_in": job.State})
	}
}

func forcedSuffix(forced bool) string {

	if forced {

		return " (forced: the version it runs is end-of-life)"
	}
	return ""
}

func orNone(s string) string {

	if s == "" {

		return "(none)"
	}
	return s
}

// trimDetail keeps an audit detail value inside the 512-byte limit the audit
// log enforces on every field.
func trimDetail(s string) string {

	if len(s) > 400 {

		return s[:400] + "…"
	}
	return s
}

// trimBody keeps a notification readable. The full report is on the job row.
func trimBody(s string) string {

	if len(s) > 2000 {

		return s[:2000] + "…"
	}
	return s
}
