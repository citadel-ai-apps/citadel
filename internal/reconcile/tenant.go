package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// tenant reconciles one tenant, holding its instance.lock for the whole pass.
//
// The lock is what keeps a 5 s tick and a concurrent API call from both acting
// on the same tenant. A tenant whose lock is held is skipped, not
// waited on: the tick should not block on someone else's deploy.
func (r *Reconciler) tenant(ctx context.Context, t store.Tenant) error {

	lock, err := r.fs.Lock(t.ID)
	if err != nil {

		return err
	}
	defer lock.Release()

	// Re-read under the lock: the tenant list was taken before it, and an API
	// call may have changed the desired state in between.
	t, err = store.GetTenant(ctx, r.db.Reader(), t.ID)
	if err != nil {

		return err
	}
	// A superuser password stored by an earlier control plane. Nothing reads
	// it any more, so it is only something to leak.
	if err := r.fs.RemoveLegacySuperuserCredential(t.ID); err != nil {

		return err
	}

	switch t.DesiredState {

	case store.DesiredDeleted:
		return r.destroy(ctx, t)
	case store.DesiredStopped, store.DesiredSuspended:
		return r.ensureStopped(ctx, t)
	case store.DesiredRunning:
		return r.ensureRunning(ctx, t)
	default:
		return fmt.Errorf("reconcile: tenant %s has unknown desired state %q", t.ID, t.DesiredState)
	}
}

// ensureRunning is the §8.3 ladder for a tenant that should be up.
func (r *Reconciler) ensureRunning(ctx context.Context, t store.Tenant) error {

	// An upgrade job in flight owns this tenant (INV-6). Checked before the
	// container is even looked at: the rehearsal phase does NOT hold the
	// instance lock — it releases it as soon as the data copy is made — so
	// without this a tick could land mid-job, compare the digest the job is
	// about to change against the one still running, and raise a drift alert
	// the platform manufactured itself.
	if active, err := r.upgradeActive(ctx, t.ID); err != nil {

		return err

	} else if active {

		r.log.Debug("tenant has an upgrade in flight, leaving it alone", "tenant", t.ID)
		return nil
	}

	// Ordering: mount, then network, then rules, then the container. Never the
	// other way round.
	if err := r.fs.EnsureMounted(t.ID); err != nil {

		return err
	}
	alloc, err := netpolicy.Addresses(mustPrefix(t.Subnet))
	if err != nil {

		return err
	}
	if err := r.net.EnsureTenantNetwork(ctx, t.Slug, alloc); err != nil {

		return err
	}
	// One read of the grant table feeds the rules, the network attachment and
	// the enforced flag, so the three cannot describe different grant sets.
	eg, _, err := r.egressBinding(ctx, t)
	if err != nil {

		return err
	}
	// The platform pass already asserted the INPUT drops and the DOCKER-USER
	// scaffold this tick. These are the tenant's own rules, which must exist
	// before its container can be reached — the intra-network accept is the
	// ingress path (see netpolicy.IntraNetworkRule) — and before it can reach
	// anything, which is why the egress accepts are written here and not after
	// the container starts (§8.3).
	if err := r.ensureTenantRules(ctx, t, eg); err != nil {

		return err
	}
	if err := r.syncEgressState(ctx, t, eg != nil); err != nil {

		return err
	}

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return err
	}

	// The reconciler NEVER changes an instance's runtime version (INV-11),
	// whether its container is running, stopped or gone. A digest difference
	// means somebody edited the desired digest outside an upgrade, or a
	// rollback failed half-way; acting on it would be an unbacked-up one-way
	// migration or an old binary on migrated data. Alert and stop.
	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return err
	}
	if err := r.digestGuard(ctx, t, st); err != nil {

		if errors.Is(err, ErrDigestDrift) {

			return nil
		}
		return err
	}

	// The instance was marked failed after exhausting the ladder. Leave it:
	// a failed instance is a visible problem for an operator, not something to
	// churn container creates over. `citadel tenant restart` clears it.
	in, err := store.GetInstance(ctx, r.db.Reader(), t.ID)
	if err != nil {

		return err
	}
	if in.ObservedState == store.ObservedFailed {

		return nil
	}

	needsStart := !st.Exists || !st.Running || !st.SpecMatches
	if needsStart {

		ready, wait := backoffReady(in.RestartCount, in.LastRestartAt, time.Now())
		if !ready {

			if wait == 0 {

				return r.markFailed(ctx, t, in, "restart ladder exhausted")
			}
			r.log.Debug("waiting out the restart backoff", "tenant", t.ID, "wait", wait)
			return nil
		}
		if st.Exists && len(st.Posture) > 0 {

			// Recreated like any other diff — leaving it running is worse —
			// but never quietly: nothing the platform does produces these.
			r.log.Error("SECURITY: tenant container has settings no tenant container may have; recreating it",
				"tenant", t.ID, "posture", st.Posture)
			r.drift.Record(Drift{Kind: DriftPosture, TenantID: t.ID, Security: true, Repaired: true,
				Detail: strings.Join(st.Posture, "; ")})
			r.auditTenant(ctx, t.ID, auditlog.ActionPostureDrift, "tenant/"+t.ID,
				map[string]any{"posture": st.Posture})

		} else if st.Exists && len(st.SpecDiff) > 0 {

			r.log.Info("container config differs from spec", "tenant", t.ID, "diff", st.SpecDiff)
		}
		h, err := r.drv.Ensure(ctx, spec)
		if err != nil {

			return r.recordAttempt(ctx, t, in, err)
		}
		if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

			return err
		}
		r.auditTenant(ctx, t.ID, auditlog.ActionTenantStarted, "tenant/"+t.ID, nil)
	}

	// Routing and the network attachment are re-asserted every tick, whether or
	// not the container changed. An earlier boot recovery recreated the edge and
	// never re-joined tenant networks, after which every upstream failed to
	// resolve; owning this here is the fix.
	if err := r.ensureEdgeWiring(ctx, t, alloc); err != nil {

		return err
	}
	if err := r.logs.Ensure(ctx, t.ID, config.ContainerName(t.Slug)); err != nil {

		r.log.Warn("could not start host-side log collection", "tenant", t.ID, "err", err)
	}

	return r.checkHealth(ctx, t, in)
}

func (r *Reconciler) ensureEdgeWiring(ctx context.Context, t store.Tenant, alloc netpolicy.Allocation) error {

	attached, err := r.proxy.AttachedNetworks(ctx)
	if err != nil {

		return err
	}
	if attached[t.Slug] != t.EdgeIP {

		if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

			return err
		}
		r.drift.Record(Drift{Kind: DriftMissingRoute, TenantID: t.ID,
			Detail: "edge was not attached to " + t.NetworkName, Repaired: true})
		r.log.Warn("re-attached the edge proxy to a tenant network", "tenant", t.ID, "ip", t.EdgeIP)
	}

	routes, err := r.proxy.RouteIDs(ctx)
	if err != nil {

		return err
	}
	switch _, seen := r.republished.Load(t.ID); {

	case !routes[t.Slug]:
		if err := r.publishRoute(ctx, t); err != nil {

			return err
		}
		r.drift.Record(Drift{Kind: DriftMissingRoute, TenantID: t.ID,
			Detail: "edge route was missing", Repaired: true})

	case !seen:
		// Present, but published by an earlier process: render it once with
		// this release's shape.
		if err := r.publishRoute(ctx, t); err != nil {

			return err
		}
		r.drift.Clear(DriftMissingRoute, t.ID)

	default:
		r.drift.Clear(DriftMissingRoute, t.ID)
	}
	r.republished.Store(t.ID, true)
	_ = alloc
	return nil
}

// RepublishRoute re-renders a tenant's edge route immediately.
//
// Exported for the quarantine endpoint, which exists for the moments when five
// seconds of continued exposure is the thing being argued about, and must not
// wait for the next tick.
func (r *Reconciler) RepublishRoute(ctx context.Context, t store.Tenant) error {

	return r.publishRoute(ctx, t)
}

// publishRoute renders and installs a tenant's edge route.
//
// Called when the route is missing and whenever something that changes its
// SHAPE changes — quarantine, the body cap — rather than on every tick: a PATCH
// per tenant per five seconds is 40 admin calls a second at the 200-tenant
// fanout D1 measured, for a route that is almost always identical.
func (r *Reconciler) publishRoute(ctx context.Context, t store.Tenant) error {

	limited, err := r.proxy.PublishRoute(ctx, r.routeSpec(t))
	if err != nil {

		return err
	}
	if limited {

		r.drift.Clear(DriftRateLimit, t.ID)

	} else {

		// Published, serving, and with no per-tenant limit in front of it. That
		// is a §10 control that is supposed to be there and is not, so it goes
		// on the board rather than into a log line nobody reads.
		r.drift.Record(Drift{Kind: DriftRateLimit, TenantID: t.ID,
			Detail: "edge route published without per-tenant rate limits; edge_image has no rate_limit handler"})
	}
	r.auditTenant(ctx, t.ID, auditlog.ActionRoutePublished, "route/"+t.Slug,
		map[string]any{"hostname": t.Hostname, "quarantined": t.Quarantined, "rate_limited": limited})
	return nil
}

// routeSpec is the edge's view of a tenant.
func (r *Reconciler) routeSpec(t store.Tenant) proxyctl.RouteSpec {

	return proxyctl.RouteSpec{
		Slug:        t.Slug,
		Hostname:    t.Hostname,
		BodyCap:     t.BodyCap,
		Quarantined: t.Quarantined,
		RateLimits: []proxyctl.RateLimit{
			{Name: "api", PathPrefix: "/api/*", Events: r.cfg.RateAPIEvents, Window: r.cfg.RateAPIWindow.D()},
			// The admin UI is where a credential-stuffing run lands, so its
			// budget is an order of magnitude tighter than the API's.
			{Name: "admin", PathPrefix: "/_/*", Events: r.cfg.RateAdminEvents, Window: r.cfg.RateAdminWindow.D()},
		},
	}
}

// checkHealth records the tenant's observed state.
//
// Health means a real data-plane request succeeded, not that /api/health
// answered: a version-mismatched binary serves /api/health 200 with a broken
// data plane (design.md INV-4).
func (r *Reconciler) checkHealth(ctx context.Context, t store.Tenant, in store.Instance) error {

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := r.hc.Ping(probeCtx, t.Hostname); err != nil {

		return r.recordUnhealthy(ctx, t, in, err)
	}
	// A token that cannot be signed is an unhealthy instance, not a control
	// plane error: pb_data is the tenant's, and an unreadable or tampered one
	// is exactly what this check exists to surface.
	tok, err := r.healthToken(t)(probeCtx)
	if err != nil {

		return r.recordUnhealthy(ctx, t, in, err)
	}
	if err := r.hc.DataPlane(probeCtx, t.Hostname, t.RuntimeVersion, tok); err != nil {

		return r.recordUnhealthy(ctx, t, in, err)
	}

	now := time.Now().UTC()
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			ObservedState: new(store.ObservedHealthy),
			LastHealthAt:  new(now),
			RestartCount:  new(0),
			LastError:     new(""),
		})
	})
}

func (r *Reconciler) recordUnhealthy(ctx context.Context, t store.Tenant, in store.Instance, cause error) error {

	// A tenant that has just been created is `starting`, not `unhealthy`: the
	// first boot runs the tenant's own pb_migrations, which can take a while,
	// and calling that unhealthy would start the restart ladder against a
	// working instance.
	state := store.ObservedUnhealthy
	if in.LastHealthAt == nil && in.RestartCount == 0 &&
		time.Since(in.UpdatedAt) < r.cfg.HealthTimeout.D() {

		state = store.ObservedStarting
	}
	r.log.Warn("tenant is not serving its data plane", "tenant", t.ID, "state", state, "err", cause)

	return r.db.Tx(ctx, func(tx bun.Tx) error {

		u := store.InstanceUpdate{
			ObservedState: new(state),
			LastError:     new(cause.Error()),
		}
		if state == store.ObservedUnhealthy {

			// Count this as an attempt so the ladder advances rather than
			// hammering a container that comes up and fails its data plane.
			u.RestartCount = new(in.RestartCount + 1)
			u.LastRestartAt = new(time.Now().UTC())
		}
		return store.UpdateInstance(ctx, tx, t.ID, u)
	})
}

func (r *Reconciler) recordAttempt(ctx context.Context, t store.Tenant, in store.Instance, cause error) error {

	attempts := in.RestartCount + 1
	r.log.Error("cannot bring up tenant container", "tenant", t.ID, "attempt", attempts, "err", cause)
	r.auditTenant(ctx, t.ID, auditlog.ActionRestartAttempted, "tenant/"+t.ID,
		map[string]any{"attempt": attempts})

	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			ObservedState: new(store.ObservedUnhealthy),
			RestartCount:  new(attempts),
			LastRestartAt: new(time.Now().UTC()),
			LastError:     new(cause.Error()),
		})
	}); err != nil {

		return err
	}
	if attempts >= MaxRestarts {

		in.RestartCount = attempts
		return r.markFailed(ctx, t, in, cause.Error())
	}
	return nil
}

func (r *Reconciler) markFailed(ctx context.Context, t store.Tenant, in store.Instance, reason string) error {

	if in.ObservedState == store.ObservedFailed {

		return nil
	}
	r.log.Error("marking instance failed after exhausting the restart ladder",
		"tenant", t.ID, "attempts", in.RestartCount, "reason", reason)
	r.auditTenant(ctx, t.ID, auditlog.ActionMarkedFailed, "tenant/"+t.ID,
		map[string]any{"attempts": in.RestartCount})
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			ObservedState: new(store.ObservedFailed),
			LastError:     new(reason),
		})
	})
}

func (r *Reconciler) recordStarted(ctx context.Context, t store.Tenant, containerID string) error {

	return r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			ContainerID:   new(containerID),
			ObservedState: new(store.ObservedStarting),
			RunningDigest: new(t.ImageDigest),
		})
	})
}

func (r *Reconciler) ensureStopped(ctx context.Context, t store.Tenant) error {

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return err
	}
	st, err := r.drv.Status(ctx, spec)
	if err != nil {

		return err
	}
	if !st.Exists || !st.Running {

		return r.db.Tx(ctx, func(tx bun.Tx) error {

			return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
				ObservedState: new(store.ObservedStopped),
			})
		})
	}
	if err := r.drv.Stop(ctx, driver.Handle{TenantID: t.ID, Name: spec.Name}); err != nil {

		return err
	}
	r.logs.Stop(t.ID)
	r.auditTenant(ctx, t.ID, auditlog.ActionTenantStopped, "tenant/"+t.ID, nil)
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			ObservedState: new(store.ObservedStopped),
			RestartCount:  new(0),
		})
	})
}

// destroy tears a tenant down in the reverse order of provisioning.
//
// Order matters: the edge has to leave the network before the network can be
// removed, and the data image has to be unmounted before its directory can be
// touched.
func (r *Reconciler) destroy(ctx context.Context, t store.Tenant) error {

	r.log.Info("destroying tenant", "tenant", t.ID)

	// §8.3's final backup is NOT here. It is taken by the destroy endpoint,
	// before the row is marked deleted: there it is attributed to the principal
	// who asked, and a snapshot that fails can still abort the destruction —
	// neither of which is true once teardown has started.

	// The rule set to remove has to be derived BEFORE the grants are deleted
	// with the tenant row, or teardown removes the intra-network accept and
	// leaves every egress accept behind — which the next tick then reports as an
	// unbacked rule that nobody wrote.
	eg, _, err := r.egressBinding(ctx, t)
	if err != nil {

		return err
	}
	// The final attestation (§14.7): the signed record of what the tenant
	// could reach at the moment it was torn down, taken from the host while
	// there is still a host to look at. It outlives the tenant, as the audit
	// rows do. Best-effort: an unreachable proxy must not block a teardown.
	if r.attest != nil {

		if rep, err := r.attest.Generate(ctx, t.ID); err != nil {

			r.log.Error("cannot take the final attestation", "tenant", t.ID, "err", err)

		} else {

			r.recordAttestation(t.ID, rep.Outcome, len(rep.Findings))
		}
	}
	r.logs.Stop(t.ID)

	spec, err := r.specFor(ctx, t)
	if err != nil {

		// A missing encryption key must not block teardown: the container can
		// still be removed by name.
		spec = driver.InstanceSpec{TenantID: t.ID, Name: containerNameFor(t)}
	}
	if err := r.drv.Destroy(ctx, driver.Handle{TenantID: t.ID, Name: spec.Name}); err != nil {

		return err
	}
	if err := r.proxy.RemoveRoute(ctx, t.Slug); err != nil {

		return err
	}
	r.auditTenant(ctx, t.ID, auditlog.ActionRouteRemoved, "route/"+t.Slug, nil)

	if err := r.proxy.DetachNetwork(ctx, t.Slug); err != nil {

		return err
	}
	if err := r.egress.DetachTenant(ctx, spec.Name); err != nil {

		return err
	}
	if err := r.net.RemoveTenantNetwork(ctx, t.Slug); err != nil {

		return err
	}

	// Only the rules the control plane knows it wrote are removed. Anything
	// else still tagged for this tenant came from outside the control plane and
	// is reported, never force-removed.
	changes, leftovers, err := r.net.TeardownTenant(t.ID,
		netpolicy.TenantRules(t.ID, t.Slug, ingressOrZero(t), eg))
	if err != nil {

		return err
	}
	for _, c := range changes {

		r.auditTenant(ctx, t.ID, auditlog.ActionRuleRemoved, "rule/"+c.Rule.Comment, nil)
	}
	for _, o := range leftovers {

		detail := unbackedRuleDetail(o)
		r.log.Error("SECURITY: a rule tagged for this tenant survives its teardown; NOT removing it",
			"tenant", t.ID, "detail", detail)
		r.drift.Record(Drift{Kind: DriftUnbackedRule, TenantID: t.ID, Detail: detail, Security: true})
		r.auditTenant(ctx, t.ID, auditlog.ActionUnbackedRule, "rule/"+o.Comment, nil)
	}

	if err := r.fs.Unmount(t.ID); err != nil {

		return err
	}

	// Data retention is D10. Nothing purges retained data automatically (D10a),
	// so the default is to KEEP the data image, the keys and the
	// directory — the reconciler then reports the directory as an orphan, which
	// is a visible reminder rather than a silent loss. An operator who asked to
	// purge gets what they asked for, and the audit row records which it was.
	purged := t.PurgeOnDelete
	if purged {

		// Keys last: without the encryption key the data image is unreadable,
		// so removing it first would turn a failed purge into unrecoverable
		// data instead of a retry.
		if err := r.fs.RemoveTenantDir(t.ID); err != nil {

			return err
		}
		if err := r.fs.RemoveKeys(t.ID); err != nil {

			return err
		}
		// The snapshots too: they are copies of the same data, and leaving them
		// behind would make "purge" mean "purge most of it".
		if err := r.fs.RemoveBackups(t.ID); err != nil {

			return err
		}
		r.log.Warn("purged tenant data on destroy", "tenant", t.ID)
	}

	// The tenant and instance rows go; the audit rows stay.
	if err := r.db.Tx(ctx, func(tx bun.Tx) error {

		if _, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    platformActor.ID,
			ActorKind:  platformActor.Kind,
			TenantID:   t.ID,
			Action:     auditlog.ActionTenantDestroyed,
			SubjectRef: "tenant/" + t.ID,
			Detail:     map[string]any{"slug": t.Slug, "data_retained": !purged},
		}); err != nil {

			return err
		}
		return store.DeleteTenant(ctx, tx, t.ID)
	}); err != nil {

		return err
	}
	r.drift.ClearTenant(t.ID)
	return nil
}

// ensureTenantRules asserts the tenant's DOCKER-USER rules and records any
// repair as drift.
func (r *Reconciler) ensureTenantRules(ctx context.Context, t store.Tenant, eg *netpolicy.EgressBinding) error {

	known, err := r.grantIDsFor(ctx, t.ID)
	if err != nil {

		return err
	}
	in, err := netpolicy.ParseIngress(t.EdgeIP, t.ContainerIP)
	if err != nil {

		return err
	}
	changes, err := r.net.EnsureTenantRules(t.ID, t.Slug, in, eg, known, false)
	if err != nil {

		return err
	}
	if len(changes) == 0 {

		r.drift.Clear(DriftMissingRule, t.ID)
		return nil
	}
	r.recordRuleChanges(ctx, t.ID, changes)
	return nil
}

// ingressOrZero is the tenant's ingress path for teardown, where a row with
// unparseable addresses must still be torn down: the zero Ingress simply
// leaves the intra-network accept out of the expected set, and whatever is
// left over is reported rather than removed.
func ingressOrZero(t store.Tenant) netpolicy.Ingress {

	in, _ := netpolicy.ParseIngress(t.EdgeIP, t.ContainerIP)
	return in
}

// recordRuleChanges audits every netpolicy write for a tenant (§14.4), not
// only the repairs: a rule written because a grant was approved, or removed
// because one lapsed, is exactly the record of who could reach what and when.
// A rule that was expected and missing is also drift.
func (r *Reconciler) recordRuleChanges(ctx context.Context, tenantID string, changes []netpolicy.Change) {

	for _, c := range changes {

		detail := map[string]any{"chain": c.Rule.Chain, "v6": c.Rule.V6}
		switch {

		case c.Removed:
			r.auditTenant(ctx, tenantID, auditlog.ActionRuleRemoved, "rule/"+c.Rule.Comment, detail)
		case c.Repaired:
			r.drift.Record(Drift{
				Kind:     DriftMissingRule,
				TenantID: tenantID,
				Detail:   c.Rule.String(),
				Repaired: true,
				Security: true,
			})
			r.auditTenant(ctx, tenantID, auditlog.ActionRuleRepaired, "rule/"+c.Rule.Comment, detail)
		default:
			r.auditTenant(ctx, tenantID, auditlog.ActionRuleWritten, "rule/"+c.Rule.Comment, detail)
		}
	}
}
