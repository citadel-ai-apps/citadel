package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Deploy refusals the API maps onto specific status codes.
var (
	// ErrFrozen is a state change refused while an enforcement_without_grant
	// finding is unresolved (§14.5).
	ErrFrozen = errors.New("reconcile: the tenant is frozen pending a security investigation (§14.5); " +
		"an operator lifts it with `citadel unfreeze`")
	// ErrUpgradeActive enforces the two-axis rule: never move both version
	// axes at once.
	ErrUpgradeActive = errors.New("reconcile: an upgrade job is active for this tenant; deploys and upgrades never overlap")
	// ErrIncompatible is the §6 manifest gate, in the deploy direction.
	ErrIncompatible = errors.New("reconcile: release is incompatible with the tenant's runtime version")
	// ErrEgressDenied is a Tier-0 request: no legitimate reading exists, so the
	// release is rejected rather than deployed with the host unreachable.
	ErrEgressDenied = errors.New("reconcile: release requests an egress host that is never grantable")
	// ErrWrongTenant guards a release id from another tenant.
	ErrWrongTenant = errors.New("reconcile: release belongs to another tenant")
)

// GrantOutcome is what happened to one capability the release asked for. The
// reason is shown to the tenant verbatim (§9.4: denials are a product surface).
type GrantOutcome struct {
	GrantID  string `json:"grant_id,omitempty"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Tier     int    `json:"tier"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// DeployResult is the report a deploy hands back, successful or not.
type DeployResult struct {
	ReleaseID  string         `json:"release_id"`
	Artifact   string         `json:"artifact"`
	Deployed   bool           `json:"deployed"`
	RolledBack bool           `json:"rolled_back"`
	Snapshot   string         `json:"snapshot,omitempty"`
	Grants     []GrantOutcome `json:"grants,omitempty"`
	FailedStep string         `json:"failed_step,omitempty"`
	Error      string         `json:"error,omitempty"`
	Logs       string         `json:"logs,omitempty"`
}

// Deploy runs the §8.5 state machine for one release.
//
// The whole ladder is held under the tenant's instance.lock. The
// reconciler's tick sees ErrLocked and skips the tenant until the deploy
// finishes, so nothing fights over the container half-way through.
func (r *Reconciler) Deploy(ctx context.Context, actor identity.Actor, t store.Tenant, releaseID string) (DeployResult, error) {

	rel, err := store.GetRelease(ctx, r.db.Reader(), releaseID)
	if err != nil {

		return DeployResult{}, err
	}
	if rel.TenantID != t.ID {

		return DeployResult{}, fmt.Errorf("%w: %s", ErrWrongTenant, rel.ID)
	}
	return r.runDeploy(ctx, actor, t, rel, false)
}

// Rollback re-deploys an earlier release. An empty releaseID means the one
// deployed before the current release.
//
// It reverts the code and, on failure, the data — but never a grant: a grant
// survives the release that requested it and is withdrawn by expiry, by the
// tenant or by an operator, never as a side effect (§8.5).
func (r *Reconciler) Rollback(ctx context.Context, actor identity.Actor, t store.Tenant, releaseID string) (DeployResult, error) {

	var rel store.Release
	var err error
	if releaseID == "" {

		rel, err = store.PreviousDeployedRelease(ctx, r.db.Reader(), t.ID, t.CurrentRelease)

	} else {

		rel, err = store.GetRelease(ctx, r.db.Reader(), releaseID)
	}
	if err != nil {

		return DeployResult{}, err
	}
	if rel.TenantID != t.ID {

		return DeployResult{}, fmt.Errorf("%w: %s", ErrWrongTenant, rel.ID)
	}
	return r.runDeploy(ctx, actor, t, rel, true)
}

func (r *Reconciler) runDeploy(ctx context.Context, actor identity.Actor, t store.Tenant, rel store.Release, isRollback bool) (DeployResult, error) {

	res := DeployResult{ReleaseID: rel.ID, Artifact: rel.Sha256}

	// Claimed before the gates, because gates() reads the job table and the
	// lock is not taken until several steps later: without this, two requests
	// can both pass the gate and both proceed (INV-6).
	unclaim, err := r.claim(t.ID, claimDeploy)
	if err != nil {

		return res, err
	}
	defer unclaim()

	man, err := release.Manifest(rel)
	if err != nil {

		return res, err
	}
	if err := r.gates(ctx, t, rel, man); err != nil {

		return res, err
	}

	// Classify before anything is touched. A Tier-0 host rejects the release
	// outright; Tier 1 and Tier 2 both let the deploy continue, the second with
	// the host unreachable and a named reason (§14.3).
	outcomes, err := r.classifyEgress(ctx, t, man)
	if err != nil {

		return res, err
	}
	res.Grants = outcomes

	lock, err := r.fs.LockWait(ctx, t.ID, lockBudget)
	if err != nil {

		return res, err
	}
	defer lock.Release()

	// Re-read under the lock: the tenant may have been stopped, upgraded or
	// re-pointed between the gate and here.
	t, err = store.GetTenant(ctx, r.db.Reader(), t.ID)
	if err != nil {

		return res, err
	}
	if t.FrozenReason != "" {

		return res, fmt.Errorf("%w: %s", ErrFrozen, t.FrozenReason)
	}
	prevArtifact, prevRelease := t.CurrentArtifact, t.CurrentRelease

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return res, err
	}
	handle := driver.Handle{TenantID: t.ID, Name: spec.Name}
	// A deploy recreates the container on the desired digest. If that is not
	// the digest it last ran, the deploy would move the runtime and the release
	// in one operation (INV-6) with no pre-upgrade snapshot (INV-11).
	if _, err := r.guardedStatus(ctx, t, spec); err != nil {

		return res, err
	}

	if err := r.writeGrants(ctx, actor, t, rel, res.Grants); err != nil {

		return res, err
	}

	// Stop first: the snapshot copies data.img, and copying a live WAL database
	// is how a backup becomes a corrupt one (§11).
	if err := r.drv.Stop(ctx, handle); err != nil {

		return res, err
	}
	snap, err := r.backup.Snapshot(ctx, actor, t, store.BackupPreDeploy, lock)
	if err != nil {

		return res, fmt.Errorf("pre-deploy snapshot: %w", err)
	}
	res.Snapshot = snap.ID

	// §8.5 puts ACL regeneration here, between the snapshot and the swap, and
	// the position is the point: a release that just auto-granted a host comes
	// back up with that host already reachable, and one whose grants went away
	// comes back with them already gone. Waiting for the next tick would leave a
	// window of five seconds in which the enforcement and the release disagree.
	//
	// Re-read the tenant: writeGrants may have assigned an egress address.
	if fresh, err := store.GetTenant(ctx, r.db.Reader(), t.ID); err == nil {

		t = fresh
	}
	if err := r.applyEgress(ctx, t); err != nil {

		return res, fmt.Errorf("regenerate egress policy: %w", err)
	}
	// Re-derive the spec: applyEgress may have assigned this tenant its first
	// address on the egress network, and the attachment is part of the create
	// spec rather than something applied to a running container (§8.2). From
	// a re-read row, so the spec carries the address applyEgress assigned.
	if fresh, err := store.GetTenant(ctx, r.db.Reader(), t.ID); err == nil {

		t = fresh
	}
	if fresh, err := r.specFor(ctx, t); err == nil {

		spec = fresh
	}

	deployErr := r.swapAndStart(ctx, t, rel.Sha256, spec, handle, man)
	if deployErr == nil {

		if err := r.recordDeployed(ctx, actor, t, rel, isRollback, res); err != nil {

			return res, err
		}
		res.Deployed = true
		r.log.Info("release deployed", "tenant", t.ID, "release", rel.ID, "artifact", rel.Sha256,
			"rollback", isRollback)
		return res, nil
	}

	// ROLLBACK. The tenant's own pb_migrations run at startup, so a bad
	// migration is the most likely way a tenant bricks themselves — and the
	// pre_deploy snapshot is the only thing that makes it survivable.
	res.FailedStep, res.Error = "verify", deployErr.Error()
	res.Logs = r.tailLogs(ctx, handle)
	r.log.Error("deploy failed, rolling back", "tenant", t.ID, "release", rel.ID, "err", deployErr)

	if err := r.rollbackTo(ctx, actor, t, prevArtifact, snap, spec, handle, lock); err != nil {

		// Both the deploy and its rollback failed. Say both, and leave the
		// reconciler to keep trying to converge the instance.
		return res, fmt.Errorf("deploy failed (%w) and rollback failed: %v", deployErr, err)
	}
	res.RolledBack = true

	if err := r.recordFailed(ctx, actor, t, rel, prevArtifact, prevRelease, snap, deployErr); err != nil {

		return res, err
	}
	return res, nil
}

// gates are the refusals that must happen before anything is touched.
func (r *Reconciler) gates(ctx context.Context, t store.Tenant, rel store.Release, man pkgvalidate.Manifest) error {

	if t.FrozenReason != "" {

		return fmt.Errorf("%w: %s", ErrFrozen, t.FrozenReason)
	}
	active, err := r.upgradeActive(ctx, t.ID)
	if err != nil {

		return err
	}
	if active {

		return ErrUpgradeActive
	}
	ok, err := pkgvalidate.Satisfies(t.RuntimeVersion, man.PocketBase.Min, man.PocketBase.Max)
	if err != nil {

		return err
	}
	if !ok {

		return fmt.Errorf("%w: %s declares pocketbase %s–%s and the tenant runs %s",
			ErrIncompatible, rel.ID, orAny(man.PocketBase.Min), orAny(man.PocketBase.Max), t.RuntimeVersion)
	}
	return nil
}

// upgradeActive reports whether an upgrade job is mid-flight (INV-6).
//
// The durable half of the interlock: it survives a restart, where the
// process-local claim does not. Both are needed — see claim().
func (r *Reconciler) upgradeActive(ctx context.Context, tenantID string) (bool, error) {

	_, err := store.ActiveUpgrade(ctx, r.db.Reader(), tenantID)
	if errors.Is(err, store.ErrNoActiveUpgrade) {

		return false, nil
	}
	return err == nil, err
}

// classifyEgress turns each manifest egress entry into a tier decision. It
// writes nothing: a Tier-0 entry must reject the release before any row exists.
func (r *Reconciler) classifyEgress(ctx context.Context, t store.Tenant, man pkgvalidate.Manifest) ([]GrantOutcome, error) {

	out := make([]GrantOutcome, 0, len(man.Egress))
	for _, host := range man.Egress {

		refused, err := store.SubjectWasRefused(ctx, r.db.Reader(), t.ID, store.GrantEgressHost, host)
		if err != nil {

			return nil, err
		}
		d := grantpolicy.Classify(
			grantpolicy.Request{Kind: store.GrantEgressHost, Subject: host},
			grantpolicy.TenantContext{
				PlatformDomains:   []string{r.cfg.AppsDomain},
				PreviouslyRefused: refused,
			})
		if d.Tier == grantpolicy.TierDenied {

			return nil, fmt.Errorf("%w: %s", ErrEgressDenied, d.Reason)
		}
		out = append(out, GrantOutcome{
			Kind:     store.GrantEgressHost,
			Subject:  host,
			Tier:     d.Tier,
			Decision: grantpolicy.DecisionFor(d.Tier),
			Reason:   d.Reason,
		})
	}
	return out, nil
}

// writeGrants records the requests, skipping any subject that already has a
// live grant or an undecided request. Re-deploying the same manifest must not
// grow a queue of identical pending rows.
func (r *Reconciler) writeGrants(ctx context.Context, actor identity.Actor, t store.Tenant, rel store.Release, outcomes []GrantOutcome) error {

	now := time.Now().UTC()
	for i := range outcomes {

		o := &outcomes[i]
		existing, err := store.ListGrants(ctx, r.db.Reader(), store.GrantFilter{
			TenantID: t.ID, Kind: o.Kind, Subject: o.Subject,
		})
		if err != nil {

			return err
		}
		if id, ok := liveGrant(existing, now); ok {

			o.GrantID = id
			continue
		}

		g := store.Grant{
			ID:            store.NewID("g"),
			TenantID:      t.ID,
			Kind:          o.Kind,
			Direction:     grantpolicy.Direction(o.Kind),
			Subject:       o.Subject,
			Tier:          o.Tier,
			Decision:      o.Decision,
			RequestedBy:   actor.ID,
			RequestedAt:   now,
			PolicyVersion: grantpolicy.PolicyVersion,
			EvidenceRef:   "release/" + rel.ID,
			ExpiresAt:     now.Add(grantpolicy.DefaultTTL(o.Kind)),
		}
		action := auditlog.ActionGrantRequested
		if o.Decision == store.DecisionAutoApproved {

			// Tier 1 is attributable, just not human-gated: the platform
			// principal is the decider and the policy version is on the row.
			g.DecidedBy = identity.PlatformPrincipal
			g.DecidedAt = &now
			g.Justification = o.Reason
			action = auditlog.ActionGrantAutoApproved
		}
		o.GrantID = g.ID

		err = r.db.Tx(ctx, func(tx bun.Tx) error {

			if err := store.InsertGrant(ctx, tx, g); err != nil {

				return err
			}
			_, err := r.audit.Append(ctx, tx, auditlog.Event{
				ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
				Action:     action,
				SubjectRef: "grant/" + g.ID,
				Detail: map[string]any{
					"kind": g.Kind, "subject": g.Subject, "tier": g.Tier,
					"decision": g.Decision, "policy_version": g.PolicyVersion,
					"expires_at": g.ExpiresAt.Format(time.RFC3339), "release": rel.ID,
				},
			})
			return err
		})
		if err != nil {

			return err
		}
	}
	return nil
}

// liveGrant finds a grant for this subject that is still active or still
// awaiting a decision.
func liveGrant(grants []store.Grant, now time.Time) (string, bool) {

	for _, g := range grants {

		if g.Active(now) || g.State(now) == store.DecisionPending {

			return g.ID, true
		}
	}
	return "", false
}

// swapAndStart repoints app/current, recreates the container and verifies it.
//
// Recreate, not Ensure: the bind source is the app/current symlink path, which
// is identical before and after the swap, so the driver's spec diff is empty
// and it would leave the old artifact running. Docker resolves a bind source at
// create time, which is exactly what hostfs.SwapAppCurrent documents.
func (r *Reconciler) swapAndStart(ctx context.Context, t store.Tenant, sha string, spec driver.InstanceSpec, handle driver.Handle, man pkgvalidate.Manifest) error {

	if err := r.fs.SwapAppCurrent(t.ID, sha); err != nil {

		return err
	}
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetCurrentArtifact(ctx, tx, t.ID, sha)
	}); err != nil {

		return err
	}
	if err := r.drv.Destroy(ctx, handle); err != nil {

		return err
	}
	// The one window in a deploy with no PocketBase process on pb_data and the
	// lock held: the only place the seat can be re-created (INV-3).
	r.restoreSeat(ctx, t, spec)
	h, err := r.drv.Ensure(ctx, spec)
	if err != nil {

		return err
	}
	if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

		return err
	}
	if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

		return err
	}
	return r.verify(ctx, t, man)
}

// verify is the health check AND the manifest's own requests. The health check
// alone is not enough: §12 and design.md INV-4 both record an instance
// answering /api/health while its data plane was broken.
func (r *Reconciler) verify(ctx context.Context, t store.Tenant, man pkgvalidate.Manifest) error {

	if err := r.waitReady(ctx, t); err != nil {

		return err
	}
	if man.Healthcheck.Path != health.HealthPath {

		if err := r.hc.Expect(ctx, t.Hostname, "GET", man.Healthcheck.Path, man.Healthcheck.ExpectStatus); err != nil {

			return err
		}
	}
	reqs := make([]health.SmokeRequest, 0, len(man.Smoke))
	for _, s := range man.Smoke {

		reqs = append(reqs, health.SmokeRequest{Method: s.Method, Path: s.Path, ExpectStatus: s.ExpectStatus})
	}
	return r.hc.Replay(ctx, t.Hostname, reqs)
}

// rollbackTo puts the previous artifact and the pre-deploy data back.
func (r *Reconciler) rollbackTo(ctx context.Context, actor identity.Actor, t store.Tenant, prevArtifact string, snap store.Backup, spec driver.InstanceSpec, handle driver.Handle, lock *hostfs.Lock) error {

	if err := r.drv.Stop(ctx, handle); err != nil {

		return err
	}
	if prevArtifact != "" {

		if err := r.fs.SwapAppCurrent(t.ID, prevArtifact); err != nil {

			return err
		}
		if err := r.db.Tx(ctx, func(tx bun.Tx) error {

			return store.SetCurrentArtifact(ctx, tx, t.ID, prevArtifact)
		}); err != nil {

			return err
		}
	}
	// force=false is correct here: the snapshot was taken minutes ago by this
	// same runtime version, so a mismatch would mean something else moved the
	// version underneath the deploy and the restore should refuse.
	if err := r.backup.Restore(ctx, actor, t, snap, false, lock); err != nil {

		return err
	}
	if err := r.drv.Destroy(ctx, handle); err != nil {

		return err
	}
	h, err := r.drv.Ensure(ctx, spec)
	if err != nil {

		return err
	}
	if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

		return err
	}
	if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

		return err
	}
	// The previous release was healthy before, so a failure here is a real
	// problem for the operator rather than a verdict on the new release.
	if err := r.verifyPrevious(ctx, t); err != nil {

		return err
	}
	return nil
}

// verifyPrevious checks the restored instance without replaying the failed
// release's smoke set: those requests describe the release that just failed,
// not the one now running.
func (r *Reconciler) verifyPrevious(ctx context.Context, t store.Tenant) error {

	return r.waitReady(ctx, t)
}

func (r *Reconciler) recordDeployed(ctx context.Context, actor identity.Actor, t store.Tenant, rel store.Release, isRollback bool, res DeployResult) error {

	action := auditlog.ActionReleaseDeployed
	if isRollback {

		action = auditlog.ActionReleaseRolledBack
	}
	pending := 0
	for _, g := range res.Grants {

		if g.Decision == store.DecisionPending {

			pending++
		}
	}
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetReleaseStatus(ctx, tx, rel.ID, store.ReleaseDeployed); err != nil {

			return err
		}
		if err := store.SetCurrentRelease(ctx, tx, t.ID, rel.ID); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     action,
			SubjectRef: "release/" + rel.ID,
			Detail: map[string]any{
				"artifact": rel.Sha256, "snapshot": res.Snapshot,
				"grants_pending": pending, "rollback": isRollback,
			},
		})
		return err
	})
}

func (r *Reconciler) recordFailed(ctx context.Context, actor identity.Actor, t store.Tenant, rel store.Release, prevArtifact, prevRelease string, snap store.Backup, cause error) error {

	return r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetReleaseStatus(ctx, tx, rel.ID, store.ReleaseFailed); err != nil {

			return err
		}
		if err := store.SetCurrentRelease(ctx, tx, t.ID, prevRelease); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionReleaseDeployFailed,
			SubjectRef: "release/" + rel.ID,
			Detail: map[string]any{
				"artifact":          rel.Sha256,
				"restored_artifact": prevArtifact,
				"restored_snapshot": snap.ID,
				// A reference, not a payload: the reason is in the API response
				// and the container logs, which are not audit material (§14.4).
				"reason": truncate(cause.Error(), 400),
			},
		})
		return err
	})
}

// tailLogs collects the last lines of container output so the tenant sees what
// broke, rather than "deploy failed".
func (r *Reconciler) tailLogs(ctx context.Context, h driver.Handle) string {

	rc, err := r.drv.Logs(ctx, h, driver.LogOpts{Tail: "200"})
	if err != nil {

		return ""
	}
	defer rc.Close()

	b, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {

		return string(b)
	}
	return string(b)
}

// orAny renders an open version bound the way a human reads it.
func orAny(v string) string {

	if v == "" {

		return "any"
	}
	return v
}

func truncate(s string, n int) string {

	if len(s) <= n {

		return s
	}
	return s[:n] + "…"
}
