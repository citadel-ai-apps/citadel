package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/egressctl"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// accountabilityPass runs the §14 housekeeping that is not enforcement.
//
// Enforcement itself needs nothing here: expiry, revocation and a lapsed
// re-affirmation all work by a grant no longer being returned from
// enforceableGrants on the ordinary tick. What this pass does is the part that
// has to be noticed rather than merely to take effect — the signed attestation,
// the notice to a tenant whose access has gone quiet, the operator whose
// break-glass session is past its review window, and the chain head written
// somewhere it cannot be retracted.
//
// Each piece is on its own schedule and each failure is logged rather than
// returned. A stale anchor must not stop tenants reconciling.
func (r *Reconciler) accountabilityPass(ctx context.Context, tenants []store.Tenant) {

	now := time.Now().UTC()

	if r.attest != nil && now.Sub(r.lastAttest) >= r.cfg.AttestInterval.D() && !r.attesting.Load() {

		r.lastAttest = now
		// In the background, and never more than one sweep at a time. Each
		// tenant costs a Docker inspect and two proxy reads, each with its own
		// timeout — on a full host an inline sweep would hold the tick long
		// enough to stop tenants reconciling, which is a reliability failure
		// caused by the accountability machinery. Incidents do not wait for
		// this: checkUnbackedRules calls AttestNow the moment it finds one.
		r.attesting.Store(true)
		go func() {

			defer r.attesting.Store(false)
			r.attestAll(ctx, tenants)
			r.checkLiveACLOwners(ctx)
		}()
	}
	if r.signer != nil && now.Sub(r.lastAnchor) >= r.cfg.AnchorInterval.D() {

		r.lastAnchor = now
		r.anchorChain(ctx)
	}
	r.checkBreakglass(ctx, now)
	r.checkReaffirmations(ctx, now)
	r.checkOwners(ctx)
}

// checkOwners raises a security drift for any tenant that is not owned by
// exactly one principal (INV-17).
func (r *Reconciler) checkOwners(ctx context.Context) {

	bad, err := store.TenantsWithoutOneOwner(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot check tenant ownership", "err", err)
		return
	}
	flagged := make(map[string]bool, len(bad))
	for _, id := range bad {

		flagged[id] = true
		r.log.Error("SECURITY: tenant does not have exactly one accountable owner", "tenant", id)
		r.drift.Record(Drift{Kind: DriftOwnerless, TenantID: id, Security: true,
			Detail: "tenant does not have exactly one active owner (INV-17)"})
	}
	for _, d := range r.drift.List() {

		if d.Kind == DriftOwnerless && !flagged[d.TenantID] {

			r.drift.Clear(DriftOwnerless, d.TenantID)
		}
	}
}

func (r *Reconciler) attestAll(ctx context.Context, tenants []store.Tenant) {

	for _, t := range tenants {

		if t.DesiredState == store.DesiredDeleted {

			continue
		}
		rep, err := r.attest.Generate(ctx, t.ID)
		if err != nil {

			r.log.Error("cannot attest tenant", "tenant", t.ID, "err", err)
			continue
		}
		r.recordAttestation(t.ID, rep.Outcome, len(rep.Findings))
	}
}

// checkLiveACLOwners attests the part of the running proxy no per-tenant
// attestation looks at: allowlist blocks for tenants that do not exist, or that
// hold no active egress grant (INV-19). Each per-tenant report reads only its
// own block, so a block for a deleted or invented tenant would otherwise never
// be seen.
func (r *Reconciler) checkLiveACLOwners(ctx context.Context) {

	if r.egress == nil {

		return
	}
	live, err := r.egress.LiveACL(ctx)
	if err != nil {

		r.log.Warn("cannot read the running proxy's allowlist", "err", err)
		return
	}
	tenants, err := store.ListTenants(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot list tenants", "err", err)
		return
	}
	now := time.Now().UTC()
	backed := map[string]bool{}
	for _, t := range tenants {

		if t.DesiredState == store.DesiredDeleted {

			continue
		}
		grants, err := r.egressGrants(ctx, t, now)
		if err != nil {

			r.log.Error("cannot read egress grants", "tenant", t.ID, "err", err)
			return
		}
		if len(grants) > 0 {

			backed[egressctl.TenantACL{TenantID: t.ID}.ACLName()] = true
		}
	}
	found := false
	for key, hosts := range live {

		if backed[key] || len(hosts) == 0 {

			continue
		}
		found = true
		detail := fmt.Sprintf("running proxy allows %d host(s) for %q, which has no active egress grant", len(hosts), key)
		r.log.Error("SECURITY: "+detail, "acl", key)
		r.drift.Record(Drift{Kind: DriftUnbackedACL, Detail: detail, Security: true})
		r.auditPlatform(ctx, auditlog.ActionEgressACLUnbacked, "egress-acl/"+key,
			map[string]any{"hosts": len(hosts)})
	}
	if !found {

		r.drift.Clear(DriftUnbackedACL, "")
	}
}

// AttestNow generates one tenant's attestation immediately, outside the
// schedule. Called when the unbacked-rule check has already found something:
// waiting hours for the next scheduled pass to produce the signed record of an
// incident already detected would be the wrong way round.
func (r *Reconciler) AttestNow(ctx context.Context, tenantID string) {

	if r.attest == nil {

		return
	}
	rep, err := r.attest.Generate(ctx, tenantID)
	if err != nil {

		r.log.Error("cannot attest tenant", "tenant", tenantID, "err", err)
		return
	}
	r.recordAttestation(tenantID, rep.Outcome, len(rep.Findings))
}

func (r *Reconciler) recordAttestation(tenantID, outcome string, findings int) {

	switch outcome {

	case store.OutcomeEnforcementWithoutGrant:
		// Not repaired here or anywhere. Removing the rule would destroy the
		// evidence and hide a recurring intrusion behind a self-healing loop,
		// so the response is to make it loud and leave it alone.
		r.log.Error("SECURITY: attestation found enforcement with no grant behind it",
			"tenant", tenantID, "findings", findings)
		r.drift.Record(Drift{
			Kind: DriftUnbackedRule, TenantID: tenantID, Security: true,
			Detail: fmt.Sprintf("attestation: %d enforcement path(s) with no grant", findings),
		})

	case store.OutcomeGrantWithoutEnforcement:
		r.log.Warn("approved access is not in effect; repairing on the next tick",
			"tenant", tenantID, "findings", findings)
	}
}

func (r *Reconciler) anchorChain(ctx context.Context) {

	a, err := auditlog.Anchor(ctx, r.db, r.signer, r.cfg.AnchorsDir())
	if err != nil {

		r.log.Error("cannot anchor the audit chain", "err", err)
		return
	}
	r.auditPlatform(ctx, auditlog.ActionAuditAnchored, fmt.Sprintf("audit/seq/%d", a.Seq),
		map[string]any{"head_hash": a.HeadHash, "location": a.Location})
}

// checkBreakglass raises the 24-hour review notice.
//
// A session past its review window also blocks the requester from opening
// another (a younger unreviewed one does not), but
// that block lives on the request path where it can refuse; here the job is to
// make sure somebody is told, once, rather than discovering it during the next
// incident.
func (r *Reconciler) checkBreakglass(ctx context.Context, now time.Time) {

	overdue, err := store.OverdueBreakglass(ctx, r.db.Reader(), now)
	if err != nil {

		r.log.Error("cannot read break-glass sessions", "err", err)
		return
	}
	for _, g := range overdue {

		if r.notified(overdueKey(g.ID)) {

			continue
		}
		r.log.Warn("a break-glass session is past its review window",
			"grant", g.ID, "tenant", g.TenantID, "requested_by", g.RequestedBy)
		err := r.db.Tx(ctx, func(tx bun.Tx) error {

			return store.Notify(ctx, tx, store.Notification{
				TenantID: g.TenantID, Audience: store.AudienceOperator,
				Kind: store.NotifyBreakglassOverdue, SubjectRef: "grant/" + g.ID,
				Body: fmt.Sprintf("Break-glass session %s (requested by %s) is past its 24h review. "+
					"%s cannot open another until somebody else reviews it.",
					g.ID, g.RequestedBy, g.RequestedBy),
			})
		})
		if err != nil {

			r.log.Error("cannot notify about an overdue break-glass review", "grant", g.ID, "err", err)
			continue
		}
		r.markNotified(overdueKey(g.ID))
	}
}

// checkReaffirmations tells a new owner that inherited access is about to lapse,
// and records the moment it does.
//
// The lapse itself needs no action: enforceableGrants stops returning the grant
// at due_at. What would be wrong is for that to happen silently — the tenant
// would see an integration break with nothing in the portal explaining why.
func (r *Reconciler) checkReaffirmations(ctx context.Context, now time.Time) {

	pending, err := store.PendingReaffirmations(ctx, r.db.Reader(), "")
	if err != nil {

		r.log.Error("cannot read pending grant re-affirmations", "err", err)
		return
	}
	for _, ra := range pending {

		if !ra.Lapsed(now) || r.notified(lapseKey(ra.GrantID)) {

			continue
		}
		g, err := store.GetGrant(ctx, r.db.Reader(), ra.GrantID)
		if err != nil {

			r.log.Error("cannot read a lapsed grant", "grant", ra.GrantID, "err", err)
			continue
		}
		err = r.db.Tx(ctx, func(tx bun.Tx) error {

			if _, err := r.audit.Append(ctx, tx, auditlog.Event{
				ActorID:    auditlog.PlatformPrincipal,
				ActorKind:  auditlog.ActorPlatform,
				TenantID:   g.TenantID,
				Action:     auditlog.ActionGrantReaffirmLapsed,
				SubjectRef: "grant/" + g.ID,
				Detail:     map[string]any{"kind": g.Kind, "transfer": ra.TransferID},
			}); err != nil {

				return err
			}
			return store.Notify(ctx, tx, store.Notification{
				TenantID: g.TenantID, Audience: store.AudienceTenant,
				Kind: store.NotifyGrantReaffirmDue, SubjectRef: "grant/" + g.ID,
				Body: fmt.Sprintf("Access to %s was inherited when this project changed hands and "+
					"was not re-affirmed within 30 days, so it is no longer in effect. "+
					"Re-affirm it to restore it.", g.Subject),
			})
		})
		if err != nil {

			r.log.Error("cannot record a lapsed re-affirmation", "grant", g.ID, "err", err)
			continue
		}
		r.markNotified(lapseKey(ra.GrantID))
	}
}

func overdueKey(grantID string) string { return "breakglass-overdue/" + grantID }
func lapseKey(grantID string) string   { return "reaffirm-lapsed/" + grantID }

// notified reports whether this one-shot notice has already gone out in this
// process.
//
// In-memory rather than a column, because the cost of getting it wrong is
// asymmetric: a restart that re-sends one notice is noise, while a column that
// says "told" when the write failed is a notice nobody ever gets.
func (r *Reconciler) notified(key string) bool {

	r.noticeMu.Lock()
	defer r.noticeMu.Unlock()
	return r.notices[key]
}

func (r *Reconciler) markNotified(key string) {

	r.noticeMu.Lock()
	defer r.noticeMu.Unlock()
	r.notices[key] = true
}
