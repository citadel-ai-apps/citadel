package reconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Pin-runtime refusals.
var (
	// ErrPinNeedsStopped is a pin of a tenant that is, or is meant to be, up.
	ErrPinNeedsStopped = errors.New("reconcile: pin-runtime needs the tenant stopped first; " +
		"a runtime change under a live instance is exactly what INV-11 forbids")
	// ErrPinNeedsJustification is a pin with no recorded reason.
	ErrPinNeedsJustification = errors.New("reconcile: pin-runtime needs a justification; it is audited and shown to the tenant")
)

// claimPin is the process-local claim kind for a pin.
const claimPin = "pin"

// PinRuntime points a stopped tenant at a registered runtime version, in either
// direction, without touching pb_data.
//
// It is the second half of the INV-4 rollback: quarantine and stop, pin the
// runtime to the version a snapshot was taken on, restore the snapshot, start.
// It is also the only sanctioned way to change the digest of a tenant that is
// not running, and so the only operation other than an upgrade that may bypass
// the digest guard (INV-11). What makes that safe is what it demands: the
// tenant is desired-stopped and its container is not running, the operator
// names a reason, and the move is audited and announced. It does not start the
// tenant; whoever pinned it decides when the data and binary match.
func (r *Reconciler) PinRuntime(ctx context.Context, actor identity.Actor, tenantID, version, justification string) (store.Tenant, error) {

	if justification == "" {

		return store.Tenant{}, ErrPinNeedsJustification
	}
	unclaim, err := r.claim(tenantID, claimPin)
	if err != nil {

		return store.Tenant{}, err
	}
	defer unclaim()

	lock, err := r.fs.LockWait(ctx, tenantID, lockBudget)
	if err != nil {

		return store.Tenant{}, err
	}
	defer lock.Release()

	t, err := r.lockedTenant(ctx, tenantID)
	if err != nil {

		return store.Tenant{}, err
	}
	if t.DesiredState != store.DesiredStopped && t.DesiredState != store.DesiredSuspended {

		return store.Tenant{}, ErrPinNeedsStopped
	}
	target, err := store.GetRuntimeVersion(ctx, r.db.Reader(), version)
	if err != nil {

		return store.Tenant{}, err
	}
	if target.ImageDigest == t.ImageDigest {

		return store.Tenant{}, fmt.Errorf("%w: %s", ErrSameVersion, t.RuntimeVersion)
	}

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return store.Tenant{}, err
	}
	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return store.Tenant{}, err
	}
	if st.Running {

		return store.Tenant{}, ErrPinNeedsStopped
	}
	// The old container carries the old image; left in place, the digest guard
	// would (rightly) refuse to start it. The next start creates a fresh one.
	if err := r.drv.Destroy(ctx, driver.Handle{TenantID: t.ID, Name: spec.Name}); err != nil {

		return store.Tenant{}, err
	}

	from, fromDigest := t.RuntimeVersion, t.ImageDigest
	err = r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetRuntimeVersion(ctx, tx, t.ID, target.Version, target.ImageDigest); err != nil {

			return err
		}
		// The operator's pin is the assertion that pb_data belongs to the
		// target binary, so it becomes the digest the instance "last ran".
		if err := store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			RunningDigest: new(target.ImageDigest),
		}); err != nil {

			return err
		}
		if _, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionRuntimePinned, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{
				"from": from, "from_digest": fromDigest,
				"to": target.Version, "to_digest": target.ImageDigest,
				"justification": justification,
			},
		}); err != nil {

			return err
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant,
			Kind: store.NotifyRuntimePinned, SubjectRef: "tenant/" + t.ID,
			Body: fmt.Sprintf("Your instance's PocketBase runtime was set from %s to %s by %s: %s",
				from, target.Version, actor.ID, justification),
		})
	})
	if err != nil {

		return store.Tenant{}, err
	}
	r.drift.Clear(DriftDigest, t.ID)
	r.log.Warn("runtime pinned", "tenant", t.ID, "from", from, "to", target.Version, "actor", actor.ID)
	t.RuntimeVersion, t.ImageDigest = target.Version, target.ImageDigest
	return t, nil
}
