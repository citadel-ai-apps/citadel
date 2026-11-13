package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/egressctl"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// egressBinding derives a tenant's enforced outbound access from its ACTIVE
// grants, and from nothing else.
//
// Returns nil when the tenant has no active grant, which is the default and the
// happy path: no address on the egress network, no accept rule, no outbound
// path at all.
//
// Expiry and revocation need no hook anywhere. store.Grant.Active is evaluated
// against `now` on every read, so the next tick simply derives a smaller set and
// the rules and the ACL follow. That is why §8.3 puts grant expiry on the normal
// tick and nowhere else: an enforcement path and an expiry path that are the
// same code cannot disagree.
func (r *Reconciler) egressBinding(ctx context.Context, t store.Tenant) (*netpolicy.EgressBinding, []store.Grant, error) {

	grants, err := r.egressGrants(ctx, t, time.Now().UTC())
	if err != nil {

		return nil, nil, err
	}
	if len(grants) == 0 {

		return nil, nil, nil
	}

	egressIP, err := r.ensureEgressIP(ctx, t)
	if err != nil {

		return nil, nil, err
	}
	proxyIP, err := r.egress.ProxyIP()
	if err != nil {

		return nil, nil, err
	}

	ids := make([]string, 0, len(grants))
	for _, g := range grants {

		ids = append(ids, g.ID)
	}
	// Sorted so a rule set that has not changed renders in the same order and
	// the idempotent insert finds every rule already present.
	sort.Strings(ids)

	return &netpolicy.EgressBinding{
		TenantIP: egressIP,
		ProxyIP:  proxyIP,
		Port:     r.cfg.EgressProxyPort,
		GrantIDs: ids,
	}, grants, nil
}

// enforceableGrants is the ONE place that decides which grants are inputs to
// enforcement on this tick.
//
// Three things can take a grant out of effect, and all three work the same way:
// it stops being returned here. Expiry is store.Grant.Active against now;
// revocation is the revoked_at column; and a Tier-2 grant inherited through an
// ownership transfer and never re-affirmed lapses at its due date (§14.7).
// None of them rewrites the grant row, and none of them is a cleanup job — a
// second path that removed grants could disagree with the path that enforces
// them, and the disagreement would be invisible until somebody could reach a
// host nobody had authorised.
func (r *Reconciler) enforceableGrants(ctx context.Context, tenantID, kind string, now time.Time) ([]store.Grant, error) {

	grants, err := store.ActiveGrants(ctx, r.db.Reader(), tenantID, kind, now)
	if err != nil {

		return nil, err
	}
	lapsed, err := store.LapsedGrantIDs(ctx, r.db.Reader(), now)
	if err != nil {

		return nil, err
	}
	if len(lapsed) == 0 {

		return grants, nil
	}
	out := grants[:0]
	for _, g := range grants {

		if !lapsed[g.ID] {

			out = append(out, g)
		}
	}
	return out, nil
}

// egressGrants is enforceableGrants for egress, with quarantine applied.
//
// Quarantine is the instant stop (§12): it already takes the tenant off the
// edge, and a quarantined tenant that kept its outbound path could go on
// talking to the hosts it was granted — exfiltrating, or taking instructions —
// while the platform was investigating it. Its grants are not touched; they
// stop being inputs to enforcement until the quarantine lifts, exactly as an
// expired grant does, and the proxy ACL, the DOCKER-USER accepts and the
// egress network attachment all follow from that on the same tick.
func (r *Reconciler) egressGrants(ctx context.Context, t store.Tenant, now time.Time) ([]store.Grant, error) {

	if t.Quarantined {

		return nil, nil
	}
	return r.enforceableGrants(ctx, t.ID, store.GrantEgressHost, now)
}

// ensureEgressIP returns the tenant's address on the egress network, allocating
// and persisting one on first use.
//
// Allocated once and never released. Re-using an address a tenant recently held
// would make a proxy log line written moments before a revocation attributable
// to whichever tenant picked it up next — and those log lines are the evidence
// behind every denial the portal shows.
func (r *Reconciler) ensureEgressIP(ctx context.Context, t store.Tenant) (netip.Addr, error) {

	if t.EgressIP != "" {

		addr, err := netip.ParseAddr(t.EgressIP)
		if err != nil {

			return netip.Addr{}, fmt.Errorf("reconcile: tenant %s has a malformed egress_ip %q: %w", t.ID, t.EgressIP, err)
		}
		return addr, nil
	}

	pool, err := netip.ParsePrefix(r.cfg.EgressSubnet)
	if err != nil {

		return netip.Addr{}, fmt.Errorf("reconcile: egress subnet: %w", err)
	}
	var addr netip.Addr
	err = r.db.Tx(ctx, func(tx bun.Tx) error {

		// The caller's row may be stale: an address assigned since it was read
		// is the tenant's address, and handing out a second one would move the
		// tenant off the address its rules and its container were built for.
		cur, err := store.GetTenant(ctx, tx, t.ID)
		if err != nil {

			return err
		}
		if cur.EgressIP != "" {

			addr, err = netip.ParseAddr(cur.EgressIP)
			return err
		}
		// Read the exclusion set inside the transaction: two tenants handed the
		// same address would each have an accept rule matching the other's
		// traffic.
		held, err := store.AllocatedEgressIPs(ctx, tx)
		if err != nil {

			return err
		}
		taken, err := netpolicy.ParseAddrs(held)
		if err != nil {

			return err
		}
		addr, err = netpolicy.AllocateEgressIP(pool, taken)
		if err != nil {

			return err
		}
		if err := store.SetEgressState(ctx, tx, t.ID, true, addr.String()); err != nil {

			return err
		}
		_, err = r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    identity.PlatformPrincipal,
			ActorKind:  identity.KindPlatform,
			TenantID:   t.ID,
			Action:     auditlog.ActionEgressAddressAssigned,
			SubjectRef: "tenant/" + t.ID,
			Detail:     map[string]any{"address": addr.String(), "network": r.cfg.EgressNetwork},
		})
		return err
	})
	if err != nil {

		return netip.Addr{}, err
	}
	return addr, nil
}

// syncEgressState keeps tenant.egress_enabled in step with the derivation.
//
// A cached derivation, not a decision: it exists so GET /egress and the portal
// can answer "is this enforced right now?" without re-deriving, and it is
// rewritten whenever the answer changes.
func (r *Reconciler) syncEgressState(ctx context.Context, t store.Tenant, enabled bool) error {

	if t.EgressEnabled == enabled {

		return nil
	}
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetEgressState(ctx, tx, t.ID, enabled, ""); err != nil {

			return err
		}
		action := auditlog.ActionEgressEnforced
		if !enabled {

			action = auditlog.ActionEgressWithdrawn
		}
		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    identity.PlatformPrincipal,
			ActorKind:  identity.KindPlatform,
			TenantID:   t.ID,
			Action:     action,
			SubjectRef: "tenant/" + t.ID,
		})
		return err
	})
}

// applyEgress re-derives and re-asserts one tenant's outbound POLICY now,
// rather than waiting for the next tick.
//
// Called from the deploy ladder (§8.5) before the container swap, so the rules
// and the proxy ACL already describe the release that is about to start. It
// deliberately does not touch the network attachment: the container those rules
// were written for is about to be destroyed, and swapAndStart re-attaches the
// new one once it exists. Policy first, path second (§8.3).
func (r *Reconciler) applyEgress(ctx context.Context, t store.Tenant) error {

	eg, _, err := r.egressBinding(ctx, t)
	if err != nil {

		return err
	}
	known, err := r.grantIDsFor(ctx, t.ID)
	if err != nil {

		return err
	}
	in, err := netpolicy.ParseIngress(t.EdgeIP, t.ContainerIP)
	if err != nil {

		return err
	}
	if _, err := r.net.EnsureTenantRules(t.ID, t.Slug, in, eg, known, false); err != nil {

		return err
	}
	if err := r.syncEgressState(ctx, t, eg != nil); err != nil {

		return err
	}
	return r.egressPass(ctx)
}

// egressPass is the platform-wide half: the network, the proxy, the generated
// allowlist and the denial log.
//
// Runs once per tick, after the edge. Building the allowlist needs every
// tenant's active grants, so it is a fleet-wide question and not a per-tenant
// one — and rendering it once means the proxy is reloaded once, not once per
// tenant.
func (r *Reconciler) egressPass(ctx context.Context) error {

	if err := r.net.EnsureEgressNetwork(ctx); err != nil {

		return err
	}

	tenants, err := store.ListTenants(ctx, r.db.Reader())
	if err != nil {

		return err
	}
	now := time.Now().UTC()
	acls := make([]egressctl.TenantACL, 0, len(tenants))
	byIP := make(map[string]string, len(tenants))
	for _, t := range tenants {

		if t.EgressIP != "" {

			byIP[t.EgressIP] = t.ID
		}
		if t.DesiredState == store.DesiredDeleted {

			continue
		}
		grants, err := r.egressGrants(ctx, t, now)
		if err != nil {

			return err
		}
		if len(grants) == 0 || t.EgressIP == "" {

			continue
		}
		hosts := make([]string, 0, len(grants))
		for _, g := range grants {

			hosts = append(hosts, g.Subject)
		}
		acls = append(acls, egressctl.TenantACL{TenantID: t.ID, IP: t.EgressIP, Hosts: hosts})
	}

	res, err := r.egress.Ensure(ctx, acls)
	// Before the error check: a tamper found on a render whose reload then
	// failed is still a tamper, and the file has already been overwritten.
	if t := res.Tampered; t != nil {

		r.log.Error("SECURITY: the egress proxy allowlist was edited outside the control plane; "+
			"regenerated from grants, the edited copy kept as evidence",
			"found", t.FoundDigest, "expected", t.WantDigest, "evidence", t.EvidencePath,
			"added", t.Added, "removed", t.Removed)
		r.drift.Record(Drift{
			Kind:     DriftEgressACLTampered,
			Detail:   fmt.Sprintf("allowlist %s found, %s expected; %d line(s) added, %d removed; evidence %s", t.FoundDigest, t.WantDigest, len(t.Added), len(t.Removed), t.EvidencePath),
			Repaired: true,
			Security: true,
		})
		r.auditPlatform(ctx, auditlog.ActionEgressACLTampered, "egress/"+t.FoundDigest,
			map[string]any{"expected": t.WantDigest, "added": len(t.Added), "removed": len(t.Removed),
				"evidence": t.EvidencePath})
	}
	if err != nil {

		r.drift.Record(Drift{Kind: DriftEgressACL, Detail: err.Error(), Security: true})
		return err
	}
	r.drift.Clear(DriftEgressACL, "")
	if res.Changed {

		r.auditPlatform(ctx, auditlog.ActionEgressACLReloaded, "egress/"+r.egress.ConfigDigest(),
			map[string]any{"tenants": len(acls), "sni": r.egress.SNIEnforced()})
	}

	if err := r.egress.RotateLogs(r.cfg.LogMaxBytes, r.cfg.LogKeep); err != nil {

		r.log.Warn("could not rotate the egress proxy log", "err", err)
	}
	return r.collectDenials(ctx, byIP)
}

// collectDenials drains the proxy's access log into the aggregate.
//
// Denials are a product surface, not an error condition (§9.4): a developer
// debugging a failing integration sees the actual reason rather than an opaque
// timeout. One audit event per tick that saw refusals, never one per refusal —
// a hook in a retry loop must not be able to write the audit chain.
func (r *Reconciler) collectDenials(ctx context.Context, byIP map[string]string) error {

	denials, unknown, err := r.egress.CollectDenials(byIP)
	if err != nil {

		return err
	}
	for _, ip := range unknown {

		// Traffic on the egress network from an address the database does not
		// know about is the same class of signal as an unbacked firewall rule:
		// something is enforcing, or being enforced against, outside the
		// control plane.
		r.log.Error("egress traffic from an address no tenant holds",
			"source_ip", ip)
		r.drift.Record(Drift{Kind: DriftUnbackedEgress, Detail: "unknown source " + ip, Security: true})
	}
	if len(unknown) == 0 {

		r.drift.Clear(DriftUnbackedEgress, "")
	}
	if len(denials) == 0 {

		return nil
	}

	perTenant := map[string]int{}
	for _, d := range denials {

		perTenant[d.TenantID] += d.Hits
	}
	return r.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.RecordDenials(ctx, tx, denials); err != nil {

			return err
		}
		for tenantID, hits := range perTenant {

			_, err := r.audit.Append(ctx, tx, auditlog.Event{
				ActorID:    identity.PlatformPrincipal,
				ActorKind:  identity.KindPlatform,
				TenantID:   tenantID,
				Action:     auditlog.ActionEgressDenied,
				SubjectRef: "tenant/" + tenantID,
				Detail:     map[string]any{"hits": hits},
			})
			if err != nil {

				return err
			}
		}
		return nil
	})
}

// knownGrantIDs maps every tenant onto every grant id that EXISTS for it,
// whatever the decision — not just the active ones.
//
// That distinction is the whole of the attestation boundary, and getting it wrong in
// either direction is a real failure:
//
//   - keyed on ACTIVE grants, a rule whose grant was revoked a second ago reads
//     as an intrusion, and the platform pages someone every time an operator
//     does their job;
//   - keyed on nothing, a rule an operator hand-wrote with a forged grant id is
//     silently garbage-collected, which destroys the evidence §14.5 depends on.
//
// Keyed on existence, a lapsed grant's rule is garbage to collect and a
// fabricated one is an incident. "A tagged rule with no matching grant" in §9.6
// means no grant ROW, not no active grant.
func (r *Reconciler) knownGrantIDs(ctx context.Context, tenants []store.Tenant) (map[string]map[string]bool, error) {

	out := make(map[string]map[string]bool, len(tenants))
	for _, t := range tenants {

		ids, err := r.grantIDsFor(ctx, t.ID)
		if err != nil {

			return nil, err
		}
		out[t.ID] = ids
	}
	return out, nil
}

func (r *Reconciler) grantIDsFor(ctx context.Context, tenantID string) (map[string]bool, error) {

	grants, err := store.ListGrants(ctx, r.db.Reader(), store.GrantFilter{TenantID: tenantID})
	if err != nil {

		return nil, err
	}
	ids := make(map[string]bool, len(grants))
	for _, g := range grants {

		ids[g.ID] = true
	}
	return ids, nil
}
