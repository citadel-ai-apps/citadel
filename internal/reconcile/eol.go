package reconcile

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// eolPass nags tenants on a deprecated version and forces upgrades past EOL
// (§12).
//
// Runs on the tick, guarded by its own interval. The two halves are deliberately
// asymmetric: the nag is cheap, idempotent and frequent; the force is rate
// limited, batched, and never touches a tenant that is already contained.
func (r *Reconciler) eolPass(ctx context.Context, tenants []store.Tenant) {

	now := time.Now().UTC()
	// The nag interval doubles as the pass interval: nothing here needs to
	// happen more often than a tenant can be told about it.
	if now.Sub(r.lastEOL) < r.cfg.EOLNagInterval.D() {

		return
	}
	r.lastEOL = now

	versions, err := store.ListRuntimeVersions(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot list runtime versions", "err", err)
		return
	}
	byVersion := make(map[string]store.RuntimeVersion, len(versions))
	for _, v := range versions {

		byVersion[v.Version] = v
	}

	forced := 0
	for _, t := range tenants {

		rv, ok := byVersion[t.RuntimeVersion]
		if !ok || t.DesiredState != store.DesiredRunning {

			continue
		}
		switch rv.State {

		case store.VersionDeprecated:
			if rv.EOLAt == nil || now.After(*rv.EOLAt) {

				continue
			}
			if err := r.nag(ctx, t, rv, versions); err != nil {

				r.log.Error("cannot nag a tenant about a deprecated version", "tenant", t.ID, "err", err)
			}

		case store.VersionEOL:
			if rv.EOLAt == nil || now.Before(rv.EOLAt.Add(r.cfg.EOLGrace.D())) {

				continue
			}
			if forced >= r.cfg.EOLForceBatch {

				continue
			}
			if r.forceUpgrade(ctx, t, rv, versions) {

				forced++
			}
		}
	}
}

// nag tells a tenant their version is going away, once per EOLNagInterval.
//
// Idempotency comes from the notification feed rather than a new column: the
// last notice of this kind for this tenant is the record of when they were last
// told, and a second source of that fact could disagree with the first.
func (r *Reconciler) nag(ctx context.Context, t store.Tenant, rv store.RuntimeVersion, versions []store.RuntimeVersion) error {

	recent, err := store.ListNotifications(ctx, r.db.Reader(), store.NotificationFilter{
		TenantID: t.ID, Kind: store.NotifyRuntimeEOL, Limit: 1,
	})
	if err != nil {

		return err
	}
	if len(recent) > 0 && time.Since(recent[0].CreatedAt) < r.cfg.EOLNagInterval.D() {

		return nil
	}
	target := nextTarget(t.RuntimeVersion, versions)
	body := fmt.Sprintf(
		"PocketBase %s is deprecated and reaches end of life on %s. Rehearse the upgrade to %s now: a rehearsal changes nothing and tells you whether your hooks still register. After the EOL date the platform upgrades this instance itself.",
		rv.Version, rv.EOLAt.Format("2006-01-02"), orNone(target))
	err = r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant, Kind: store.NotifyRuntimeEOL,
			SubjectRef: "runtime_version/" + rv.Version, Body: body,
		}); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: identity.PlatformPrincipal, ActorKind: identity.KindPlatform, TenantID: t.ID,
			Action:     auditlog.ActionEOLNagged,
			SubjectRef: "runtime_version/" + rv.Version,
			Detail:     map[string]any{"eol_at": rv.EOLAt.Format(time.RFC3339), "target": target},
		})
		return err
	})
	return err
}

// forceUpgrade opens a platform-initiated job for a tenant past EOL.
//
// It goes through StartUpgrade like any other, which is the point: a forced
// upgrade cannot skip the pre_upgrade snapshot, cannot skip the rehearsal, and
// cannot skip the verification, because there is only one ladder.
//
// What Forced changes is exactly one gate — a tenant may not CHOOSE an eol
// version, but the platform moving them off one has to be able to target
// whatever is current.
func (r *Reconciler) forceUpgrade(ctx context.Context, t store.Tenant, rv store.RuntimeVersion, versions []store.RuntimeVersion) bool {

	if t.Quarantined {

		// Already contained. Forcing a one-way migration on an instance the
		// platform has deliberately taken off the network adds risk and
		// relieves nothing.
		return false
	}
	recent, err := store.ListUpgradeJobs(ctx, r.db.Reader(), store.UpgradeJobFilter{
		TenantID: t.ID, Since: time.Now().UTC().Add(-24 * time.Hour), Limit: 5,
	})
	if err != nil {

		r.log.Error("cannot read recent upgrade jobs", "tenant", t.ID, "err", err)
		return false
	}
	for _, j := range recent {

		if j.Forced {

			// One forced attempt per tenant per day. A version that breaks a
			// tenant's hooks would otherwise be retried every tick forever.
			return false
		}
	}
	target := nextTarget(t.RuntimeVersion, versions)
	if target == "" {

		r.log.Error("a tenant is past EOL with no version to move to",
			"tenant", t.ID, "version", t.RuntimeVersion)
		return false
	}
	platform := identity.Actor{ID: identity.PlatformPrincipal, Kind: identity.KindPlatform}
	job, err := r.StartUpgrade(ctx, platform, t, UpgradeRequest{To: target, Forced: true})
	if err != nil {

		r.log.Error("cannot start a forced upgrade", "tenant", t.ID, "to", target, "err", err)
		return false
	}
	r.auditTenant(ctx, t.ID, auditlog.ActionEOLForceScheduled, "upgrade/"+job.ID,
		map[string]any{"from": rv.Version, "to": target})
	r.log.Warn("forced an upgrade off an end-of-life version",
		"tenant", t.ID, "from", rv.Version, "to", target, "job", job.ID)
	return true
}

// quarantineForEOL contains a tenant whose forced upgrade cannot safely proceed.
//
// This follows the D11 default (design.md §12) rather than accepting that
// "some instances may not come back healthy" at EOL: quarantine is reversible and
// costs availability, where a one-way migration onto hooks a rehearsal has just
// PROVEN broken costs availability and possibly the application. The rehearsal
// exists to know the difference, so acting on what it found is the only reading
// that makes running it worthwhile.
//
// The tenant's data is untouched and the instance keeps running behind a 503;
// the operator alert and the tenant's notice both carry the rehearsal's
// failures verbatim, so somebody can act on them.
//
// The same containment covers an operator's `--force` upgrade, which is not
// about end-of-life at all: actor says which it was, so the notices name the
// real cause and the audit row names who forced it.
func (r *Reconciler) quarantineForEOL(ctx context.Context, actor identity.Actor, t store.Tenant, job store.UpgradeJob, rep RehearsalReport) {

	what, tenantWhy := "forced EOL upgrade", "This instance runs an end-of-life PocketBase version and the rehearsal of the forced upgrade failed"
	if actor.ID != identity.PlatformPrincipal {

		what, tenantWhy = "operator-forced upgrade", "An operator forced an upgrade of this instance and its rehearsal failed"
	}
	reason := fmt.Sprintf("%s %s → %s: the rehearsal failed, so the upgrade was not applied: %s",
		what, job.FromVersion, job.ToVersion, strings.Join(rep.Failures, " | "))

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetQuarantined(ctx, tx, t.ID, true); err != nil {

			return err
		}
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant, Kind: store.NotifyRuntimeEOLBlocked,
			SubjectRef: "upgrade/" + job.ID,
			Body:       trimBody(tenantWhy + ", so the upgrade was NOT applied and your data was not touched. The instance is quarantined — it returns 503 — until its hooks work on " + job.ToVersion + ". What failed: " + strings.Join(rep.Failures, " | ")),
		}); err != nil {

			return err
		}
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceOperator, Kind: store.NotifyRuntimeEOLBlocked,
			SubjectRef: "upgrade/" + job.ID,
			Body:       trimBody("A " + what + " could not proceed and the tenant was quarantined instead. " + reason),
		}); err != nil {

			return err
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionEOLQuarantined,
			SubjectRef: "upgrade/" + job.ID,
			Detail:     map[string]any{"from": job.FromVersion, "to": job.ToVersion, "failures": len(rep.Failures)},
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot quarantine a tenant whose forced upgrade failed", "tenant", t.ID, "err", err)
		return
	}
	// Applied now rather than on the next tick, for the same reason the
	// operator endpoint does it inline: quarantine exists for the moments when
	// five more seconds of exposure is the thing being argued about.
	t.Quarantined = true
	if err := r.RepublishRoute(ctx, t); err != nil {

		r.log.Error("cannot republish the route of a quarantined tenant", "tenant", t.ID, "err", err)
	}
	r.log.Error("ALERT: a forced EOL upgrade failed its rehearsal; the tenant is quarantined",
		"tenant", t.ID, "job", job.ID, "reason", reason)
}

// nextTarget is the lowest registered version above `from` that a tenant may be
// moved onto.
//
// Lowest rather than newest on purpose: §12 keeps three or four minor lines, and
// hooks written for 0.28 are likelier to survive 0.30 than 0.40. A tenant being
// moved by the platform gets the smallest step that exists.
func nextTarget(from string, versions []store.RuntimeVersion) string {

	best := ""
	for _, v := range versions {

		if !v.Upgradable() {

			continue
		}
		up, err := pkgvalidate.Compare(v.Version, from)
		if err != nil || up <= 0 {

			continue
		}
		if best == "" {

			best = v.Version
			continue
		}
		if lower, err := pkgvalidate.Compare(v.Version, best); err == nil && lower < 0 {

			best = v.Version
		}
	}
	return best
}
