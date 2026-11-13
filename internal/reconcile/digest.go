package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// ErrDigestDrift is a start refused because the desired image is not the one
// the instance last ran (INV-11).
var ErrDigestDrift = errors.New("reconcile: the desired image digest differs from the one this instance last ran; " +
	"refusing to start it (INV-11). Runtime changes go through an upgrade or pin-runtime")

// lastRanDigest is the digest the instance's pb_data was last served by, or ""
// when nothing is known.
//
// An existing container — running OR stopped — is the authority: it is what
// will be restarted. Only when there is no container does the recorded
// instance.running_digest stand in for it, so a container removed by hand (or
// by a crash between destroy and ensure) cannot launder a desired-digest edit
// into a fresh create.
func lastRanDigest(st driver.Status, in store.Instance) string {

	if st.Exists {

		return st.ImageDigest
	}
	return in.RunningDigest
}

// digestDrifted reports whether starting desired would change the runtime
// version under pb_data.
func digestDrifted(st driver.Status, in store.Instance, desired string) (string, bool) {

	last := lastRanDigest(st, in)
	return last, last != "" && last != desired
}

// digestGuard refuses to (re)create a tenant's container on a digest other than
// the one it last ran.
//
// The reconciler never changes an instance's runtime version (INV-11), and it
// is not enough to check only a running container: a stopped one, after a
// reboot, a `tenant stop` or a failed rollback, would otherwise be recreated
// on whatever the row says — a one-way migration with no snapshot (INV-4), or
// an old binary on migrated data. Every start path calls this before it stops,
// destroys or ensures anything. Only the upgrade and pin-runtime operations,
// which move the row and the container together under the lock, bypass it.
func (r *Reconciler) digestGuard(ctx context.Context, t store.Tenant, st driver.Status) error {

	in, err := store.GetInstance(ctx, r.db.Reader(), t.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {

		return err
	}
	last, drifted := digestDrifted(st, in, t.ImageDigest)
	if !drifted {

		r.drift.Clear(DriftDigest, t.ID)
		return nil
	}
	detail := fmt.Sprintf("last ran %s, desired %s", last, t.ImageDigest)
	r.log.Error("DRIFT: desired image digest does not match the one the instance last ran; NOT acting",
		"tenant", t.ID, "detail", detail, "container_exists", st.Exists, "running", st.Running)
	r.drift.Record(Drift{Kind: DriftDigest, TenantID: t.ID, Detail: detail, Security: true})
	r.auditTenant(ctx, t.ID, auditlog.ActionDigestDrift, "tenant/"+t.ID,
		map[string]any{"running": last, "desired": t.ImageDigest, "container_running": st.Running})
	return fmt.Errorf("%w: %s", ErrDigestDrift, detail)
}

// guardedStatus is Status followed by digestGuard, for the start paths.
func (r *Reconciler) guardedStatus(ctx context.Context, t store.Tenant, spec driver.InstanceSpec) (driver.Status, error) {

	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return st, err
	}
	return st, r.digestGuard(ctx, t, st)
}

// lockedTenant re-reads a tenant after its lock is held.
//
// Callers pass a row they read before waiting for the lock; an upgrade that
// finished inside the wait has since moved its runtime version, and acting on
// the stale row would stamp the wrong pb_version on a backup or start the old
// image on migrated data (INV-4). An operation that finds an upgrade in flight
// is refused: the job owns the tenant (INV-6).
func (r *Reconciler) lockedTenant(ctx context.Context, id string) (store.Tenant, error) {

	t, err := store.GetTenant(ctx, r.db.Reader(), id)
	if err != nil {

		return store.Tenant{}, err
	}
	active, err := r.upgradeActive(ctx, id)
	if err != nil {

		return store.Tenant{}, err
	}
	if active {

		return store.Tenant{}, ErrUpgradeActive
	}
	return t, nil
}
