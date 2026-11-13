package attest

import (
	"fmt"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Finding kinds.
const (
	FindEgressHost    = "egress_host"
	FindFirewallRule  = "firewall_rule"
	FindPublishedPort = "published_port"
	FindNoEnforcement = "no_enforcement_path"
	FindNetwork       = "network"
	FindMount         = "mount"
)

// expectation is the shape the platform gives every tenant container, which no
// grant changes: the networks it may sit on and the paths mounted into it. The
// zero value checks nothing, for callers that cannot say.
type expectation struct {
	TenantID string
	// Network is the tenant's own internal network.
	Network string
	// EgressNetwork is the one network that needs an active egress grant.
	EgressNetwork string
	// Mounts maps each permitted destination to its mode.
	Mounts map[string]string
}

// diff compares what the host is doing against what was authorised.
//
// The two directions are not symmetric and must not be collapsed into one list.
// "Approved but not in effect" is a functional bug the reconciler repairs on its
// next tick. "In effect with nothing behind it" is either a platform bug or
// somebody operating outside the control plane, and the only safe response is
// to report it and leave it alone.
func diff(grants []store.Grant, lapsed map[string]bool, obs Observed, exp expectation) ([]Granted, []Finding, string) {

	now := time.Now().UTC()

	active := map[string]store.Grant{} // grant id -> grant
	allowed := map[string]string{}     // subject -> grant id, egress hosts only
	out := make([]Granted, 0, len(grants))
	for _, g := range grants {

		row := Granted{
			ID: g.ID, Kind: g.Kind, Direction: g.Direction, Subject: g.Subject,
			Tier: g.Tier, State: g.State(now), DecidedBy: g.DecidedBy,
			DecidedAt: g.DecidedAt, ExpiresAt: g.ExpiresAt,
			Enforcible: enforcible(g.Kind),
		}
		// A grant awaiting re-affirmation after a transfer is not an input to
		// enforcement, exactly like an expired one: it stops being an input
		// rather than being revoked, so the enforcement path and the lapse path
		// are the same code and cannot disagree.
		if g.Active(now) && !lapsed[g.ID] {

			active[g.ID] = g
			if g.Kind == store.GrantEgressHost {

				allowed[g.Subject] = g.ID
			}

		} else if lapsed[g.ID] {

			row.State = "awaiting re-affirmation"
		}
		out = append(out, row)
	}

	var findings []Finding
	reachable := map[string]bool{}
	for _, h := range obs.Reachable {

		reachable[h] = true
	}
	ruleGrants := map[string]bool{}
	known := map[string]bool{}
	for _, g := range grants {

		known[g.ID] = true
	}
	for _, r := range obs.Rules {

		where := r.Chain + " line " + fmt.Sprint(r.Line)
		id, ok := r.Fields["grant"]
		switch {

		case ok && !known[id]:
			ruleGrants[id] = true
			findings = append(findings, Finding{
				Kind: FindFirewallRule, GrantID: id, Subject: r.Comment, Where: where,
				Detail:   "a firewall rule is tagged with a grant id that has no row in the control plane",
				Security: true,
			})

		case ok && active[id].ID == "":
			// Known, but expired, revoked, denied, pending or awaiting
			// re-affirmation. The reconciler removes it on its next tick; until
			// then it IS enforcement with no grant behind it, and the report
			// says so rather than trusting that the removal will happen.
			findings = append(findings, Finding{
				Kind: FindFirewallRule, GrantID: id, Subject: r.Comment, Where: where,
				Detail:   "a firewall rule is tagged with a grant that is not active",
				Security: true,
			})

		case ok:
			ruleGrants[id] = true

		case exp.TenantID != "" && !netpolicy.PlatformShaped(exp.TenantID, r):
			findings = append(findings, Finding{
				Kind: FindFirewallRule, Subject: r.Comment, Where: where,
				Detail:   "a firewall rule is tagged for this tenant but is not a shape the platform writes",
				Security: true,
			})
		}
	}

	// The container's networks and mounts. Neither is something a grant
	// changes, except the egress network, which needs an active egress grant.
	if exp.Network != "" {

		hasEgress := false
		for _, g := range active {

			if g.Kind == store.GrantEgressHost {

				hasEgress = true
			}
		}
		for _, n := range obs.Networks {

			if n == exp.Network || (n == exp.EgressNetwork && hasEgress) {

				continue
			}
			findings = append(findings, Finding{
				Kind: FindNetwork, Subject: n, Where: "container configuration",
				Detail:   "the container is attached to a network no active grant puts it on",
				Security: true,
			})
		}
	}
	if exp.Mounts != nil {

		for _, m := range obs.BindMounts {

			dst, mode := mountDest(m)
			if want, ok := exp.Mounts[dst]; ok && want == mode {

				continue
			}
			findings = append(findings, Finding{
				Kind: FindMount, Subject: m, Where: "container configuration",
				Detail:   "the container has a mount the platform does not give tenants",
				Security: true,
			})
		}
	}

	// Enforcement with nothing behind it, on the proxy side.
	for _, host := range obs.Reachable {

		if _, ok := allowed[host]; !ok {

			findings = append(findings, Finding{
				Kind: FindEgressHost, Subject: host, Where: "egress proxy allowlist",
				Detail:   "the running proxy allows this host with no active grant authorising it",
				Security: true,
			})
		}
	}

	for _, p := range obs.PublishedPort {

		// A published tenant port is a DNAT rule and a route around the host
		// firewall's INPUT chain. There is no grant kind that authorises one.
		findings = append(findings, Finding{
			Kind: FindPublishedPort, Subject: p, Where: "container configuration",
			Detail:   "the container publishes a host port; no tenant container may publish any",
			Security: true,
		})
	}

	// Authorised but not in effect.
	for id, g := range active {

		switch {

		case !enforcible(g.Kind):
			findings = append(findings, Finding{
				Kind: FindNoEnforcement, GrantID: id, Subject: g.Subject,
				Where: "none",
				Detail: fmt.Sprintf("a %s grant is approved, but this platform has no machinery "+
					"that puts one into effect; it is recorded and expiring, not enforced", g.Kind),
			})

		case obs.ProxyReadable && !inEffect(g.Subject, reachable):
			findings = append(findings, Finding{
				Kind: FindEgressHost, GrantID: id, Subject: g.Subject,
				Where:  "egress proxy allowlist",
				Detail: "approved, but the running proxy is not allowing it",
			})

		case obs.RulesReadable && !ruleGrants[id]:
			findings = append(findings, Finding{
				Kind: FindFirewallRule, GrantID: id, Subject: g.Subject,
				Where:  "DOCKER-USER",
				Detail: "approved, but no firewall rule carries this grant id",
			})
		}
	}

	for i := range out {

		out[i].Enforced = reachable[out[i].Subject] && active[out[i].ID].ID != ""
	}
	return out, findings, outcome(findings)
}

// outcome collapses the findings into the three-way result of §14.5.
//
// A security finding wins over everything else. A tenant with one missing rule
// and one rule nobody granted is an incident, not a partially-degraded config:
// grading it on the majority of its findings would let an intrusion hide behind
// ordinary noise.
func outcome(findings []Finding) string {

	worst := store.OutcomeMatch
	for _, f := range findings {

		if f.Security {

			return store.OutcomeEnforcementWithoutGrant
		}
		// A grant of a kind nothing can enforce is an honest statement about
		// the platform, not a divergence between intent and the host.
		if f.Kind != FindNoEnforcement {

			worst = store.OutcomeGrantWithoutEnforcement
		}
	}
	return worst
}

// inEffect reports whether the running proxy admits host, directly or through
// a wildcard. The proxy is given a host only once: one that a granted wildcard
// already covers is left out of the list (egressctl.SquidDomains), because
// Squid would otherwise drop one of the two entries itself.
func inEffect(host string, reachable map[string]bool) bool {

	if reachable[host] {

		return true
	}
	name := strings.TrimPrefix(host, "*.")
	// Squid's ".example.com" also matches example.com, so a wildcard covers
	// its own apex. A wildcard grant is covered only by a strictly wider one.
	if name == host && reachable["*."+name] {

		return true
	}
	for i := range len(name) {

		if name[i] == '.' && reachable["*."+name[i+1:]] {

			return true
		}
	}
	return false
}

// mountDest splits an Observed.BindMounts entry, "src:dst:mode", from the
// right: the source is a host path and is not trusted to be colon-free.
func mountDest(m string) (string, string) {

	i := strings.LastIndexByte(m, ':')
	if i < 0 {

		return m, ""
	}
	mode := m[i+1:]
	rest := m[:i]
	j := strings.LastIndexByte(rest, ':')
	if j < 0 {

		return rest, mode
	}
	return rest[j+1:], mode
}
