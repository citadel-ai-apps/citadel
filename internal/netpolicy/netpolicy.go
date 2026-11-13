// Package netpolicy creates tenant networks and writes the firewall rules that
// contain them (design §9).
//
// This is the package where a mistake is a breach (design §9). Two
// consequences show up throughout:
//
//   - Every rule it writes has a matching probe in test/netprobe that fails if
//     the rule is absent.
//   - It asserts rule ORDER, not merely rule presence. DOCKER-USER runs before
//     Docker's own established-connection accept, so a correct-looking set of
//     rules in the wrong order is a broken egress path or a silently ineffective
//     deny (design.md §9.5).
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// Manager owns network creation and the firewall ruleset.
type Manager struct {
	cfg    config.Config
	docker client.APIClient
	ipt    *ipt
	log    *slog.Logger

	// mu serialises every rule write. The reconcile tick, an API-driven
	// provision and an upgrade's rehearsal all edit DOCKER-USER, and
	// removeByComment deletes by LINE NUMBER from a listing: an insert by
	// another goroutine between the listing and the delete shifts the lines,
	// and the delete takes out whatever moved into that slot — a platform
	// deny included.
	mu sync.Mutex
	// hostHasIPv6 reports whether the kernel has IPv6 at all. A field so
	// tests can choose; see EnsurePlatformRules.
	hostHasIPv6 func() bool
}

// kernelIPv6 reports whether the kernel has IPv6 enabled. With it disabled
// (ipv6.disable=1) there is no v6 traffic to filter and ip6tables cannot load
// its tables, so a failed v6 rule means nothing; with it enabled, a failed v6
// rule is a hole.
func kernelIPv6() bool {

	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

func ptrBool(b bool) *bool { return &b }

// New returns a Manager.
func New(cfg config.Config, docker client.APIClient, log *slog.Logger) *Manager {

	return &Manager{cfg: cfg, docker: docker, ipt: newIpt(), log: log, hostHasIPv6: kernelIPv6}
}

// Change is one rule the Manager had to write or remove.
//
// Returned rather than merely logged so the caller can record an audit event in
// the same transaction as whatever else it is doing (§14.4 lists netpolicy rule
// writes and drift repairs as audited).
type Change struct {
	Rule     Rule
	Repaired bool // the rule was expected to exist already: this is drift
	Removed  bool // the rule was pruned because no active grant justifies it
}

// EnsurePlatformRules asserts the rules that are not per-tenant: the host-protection
// INPUT drops, the edge ingress accept and the DOCKER-USER scaffold.
//
// Called on every reconcile tick. A Docker daemon restart, a `docker network
// prune` or an unrelated firewall reload can drop these, so the reconciler
// treats a missing rule as drift to repair and logs it loudly (§8.3). `first`
// suppresses the drift flag on the very first assertion at start-up, when
// absence is expected rather than alarming.
func (m *Manager) EnsurePlatformRules(first bool) ([]Change, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	var changes []Change

	hostRules, err := hostProtectRules(m.cfg)
	if err != nil {

		return changes, err
	}
	for _, r := range hostRules {

		wrote, err := m.ipt.insert(r, 1)
		if err != nil {

			// INPUT exists in every ip6tables filter table, so unlike the v6
			// DOCKER-USER chain (which only exists when Docker manages
			// ip6tables) a failure here is not a thinner chain set: on a
			// kernel with IPv6 it leaves the host reachable over v6 from every
			// tenant bridge. Only a kernel without IPv6 makes it moot.
			if r.V6 && (m.hostHasIPv6 == nil || !m.hostHasIPv6()) {

				m.log.Warn("ip6tables host protection could not be asserted; the kernel has no IPv6",
					"rule", r.String(), "err", err)
				continue
			}
			return changes, fmt.Errorf("netpolicy: assert host protection: %w", err)
		}
		if wrote {

			changes = append(changes, Change{Rule: r, Repaired: !first})
			if !first {

				m.log.Error("DRIFT REPAIRED: tenant host-protection rule was missing from INPUT",
					"rule", r.String())
			}
		}
	}

	// Written bottom-up so each -I lands above the last: inserting at position
	// 1 in reverse order leaves the slice's order in the chain.
	//
	// Except a missing v4 DROP: it goes above the first platform deny, not at
	// the top. On a fresh chain that is the same thing, but when one deny is
	// missing from an otherwise complete chain — drift, or a rule added in a
	// newer release — position 1 would put it above the conntrack accept and
	// every tenant's grant accepts.
	rules, err := dockerUserRules(m.cfg)
	if err != nil {

		return changes, err
	}
	if err := m.dropDuplicatePlatformRules(rules); err != nil {

		return changes, err
	}
	for i := len(rules) - 1; i >= 0; i-- {

		r := rules[i]
		pos := 1
		if !r.V6 {

			present, err := m.ipt.exists(r)
			if err != nil {

				return changes, fmt.Errorf("netpolicy: assert DOCKER-USER: %w", err)
			}
			if !present {

				if pos, err = m.repairPosition(r); err != nil {

					return changes, err
				}
			}
		}
		wrote, err := m.ipt.insert(r, pos)
		if err != nil {

			// The v6 metadata and range denies are best-effort ONLY where
			// there is no v6 DOCKER-USER chain at all: Docker is not managing
			// ip6tables, so it routes no container IPv6, and no platform
			// network has IPv6 enabled (checkNetwork refuses one that does).
			// Where the chain exists, v6 forwarding is live and a deny that
			// cannot be written is a gap in INV-7, not a thinner chain set.
			if r.V6 {

				noKernelV6 := m.hostHasIPv6 == nil || !m.hostHasIPv6()
				if _, lerr := m.ipt.list(r.Chain, true); lerr != nil || noKernelV6 {

					m.log.Warn("the v6 deny is moot: no IPv6 kernel or no ip6tables DOCKER-USER chain",
						"rule", r.String(), "err", err)
					continue
				}
			}
			return changes, fmt.Errorf("netpolicy: assert DOCKER-USER: %w", err)
		}
		if wrote {

			changes = append(changes, Change{Rule: r, Repaired: !first})
			if !first {

				m.log.Error("DRIFT REPAIRED: DOCKER-USER rule was missing",
					"rule", r.String())
			}
		}
	}
	return changes, nil
}

// EgressBinding is the tenant's side of the egress path.
//
// Every field is derived from the ACTIVE access_grant set and never from the
// tenant's manifest. One accept is written per grant id, even though
// the packet match is identical for all of them, because §9.6 requires every
// rule to carry the decision that authorised it: a rule must be traceable to a
// grant, diffable against the database, and garbage-collectable. That tag is
// what internal/attest reads off the host in §14.5.
type EgressBinding struct {
	TenantIP netip.Addr
	ProxyIP  netip.Addr
	Port     int
	GrantIDs []string
}

// TenantRules is the DOCKER-USER rule set a tenant should have.
//
// With no binding it is a single intra-network accept, which keeps the ingress
// path open (see IntraNetworkRule). With one it becomes:
//
//	intra-network accept · one accept per grant · default deny for this tenant
//
// The order of the slice is the order of the chain, and it is load-bearing:
// EnsureTenantRules writes the accepts above every deny and the tenant's own
// deny above the platform's unconditional ones.
//
// An invalid Ingress yields no intra-network accept at all: a tenant the
// control plane cannot place on its network is unreachable rather than open.
func TenantRules(tenantID, slug string, in Ingress, eg *EgressBinding) []Rule {

	var rules []Rule
	if in.Valid() {

		rules = append(rules, IntraNetworkRule(tenantID, config.BridgeName(slug), in))
	}
	if eg == nil || len(eg.GrantIDs) == 0 {

		return rules
	}
	for _, gid := range eg.GrantIDs {

		rules = append(rules, EgressAcceptRule(tenantID, gid, eg.TenantIP, eg.ProxyIP, eg.Port))
	}
	return append(rules, TenantDropRule(tenantID, eg.TenantIP))
}

// EnsureTenantRules converges a tenant's DOCKER-USER rules onto the set its
// active grants justify: it writes what is missing AND removes what is no
// longer justified.
//
// Writing alone is not enough, and that was found the hard way. Revoking a
// grant regenerates the proxy allowlist and detaches the tenant from the egress
// network, so the path really does close — but the accept rule stayed in the
// chain, which is the platform manufacturing the exact
// `enforcement_without_grant` condition §14.5 exists to detect. §9.6 says the
// rules are *rewritten* when the active grant set changes, not merely asserted.
//
// `knownGrants` is every grant id that EXISTS for this tenant, whatever its
// decision — not just the active ones. That distinction is the whole of the
// Attestation boundary:
//
//   - a rule tagged with a grant that exists but is revoked or expired is one
//     the control plane wrote under an authorisation that has since lapsed. It
//     is garbage to collect.
//   - a rule tagged with a grant id that has no row at all was authorised by
//     nothing and written by nobody accountable. It is reported and left
//     exactly where it is, because removing it destroys the evidence.
//
// Two insert positions, not one. Accepts go immediately BELOW the conntrack
// accept and ABOVE every deny; the tenant's own default-deny goes immediately
// ABOVE the platform's unconditional denies. Position is not cosmetic:
//
//   - below a deny an accept can never match (the §9.5 trap: Docker bridges live
//     in 172.16.0.0/12, so the tenant→proxy accept has to outrank that deny);
//   - above the conntrack accept it would shadow the established-connection fast
//     path, and the proxy's replies die half-open (design.md §9.5);
//   - a tenant DROP placed among the accepts would sit above some other tenant's
//     accept, which AssertOrder correctly reports as unreachable.
func (m *Manager) EnsureTenantRules(tenantID, slug string, in Ingress, eg *EgressBinding, knownGrants map[string]bool, first bool) ([]Change, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if !in.Valid() {

		return nil, fmt.Errorf("netpolicy: tenant %s has no edge or container address", tenantID)
	}

	acceptPos, err := m.insertPosition()
	if err != nil {

		return nil, err
	}
	desired := TenantRules(tenantID, slug, in, eg)

	var changes []Change
	for _, r := range desired {

		pos := acceptPos
		if r.IsDrop() {

			// Re-read for each deny: every accept written above it has already
			// shifted the chain down by one.
			pos, err = m.denyPosition()
			if err != nil {

				return changes, err
			}
		}
		wrote, err := m.ipt.insert(r, pos)
		if err != nil {

			return changes, fmt.Errorf("netpolicy: assert tenant rules for %s: %w", tenantID, err)
		}
		if wrote {

			changes = append(changes, Change{Rule: r, Repaired: !first})
			if !first {

				m.log.Error("DRIFT REPAIRED: tenant DOCKER-USER rule was missing",
					"tenant", tenantID, "rule", r.String())
			}
		}
	}

	pruned, err := m.pruneTenantRules(tenantID, desired, knownGrants)
	if err != nil {

		return changes, err
	}
	return append(changes, pruned...), nil
}

// pruneTenantRules removes this tenant's rules that its active grants no longer
// justify, and leaves alone anything it cannot account for.
func (m *Manager) pruneTenantRules(tenantID string, desired []Rule, knownGrants map[string]bool) ([]Change, error) {

	want := make(map[string]bool, len(desired))
	for _, r := range desired {

		want[r.Comment] = true
	}

	observed, err := m.Observe()
	if err != nil {

		return nil, err
	}
	var changes []Change
	for _, o := range observed {

		if o.Fields["tenant"] != tenantID || want[o.Comment] {

			continue
		}
		grant, tagged := o.Fields["grant"]
		if tagged && !knownGrants[grant] {

			// Nothing ever authorised this. Reported by checkUnbackedRules,
			// never removed here.
			continue
		}
		if !PlatformShaped(tenantID, o) {

			// Tagged for this tenant but not a shape the platform writes:
			// somebody else put it there. Same answer as an unknown grant —
			// evidence, reported, never silently repaired (INV-19).
			continue
		}
		n, err := m.ipt.removeByComment(o.Chain, o.Comment, o.V6)
		if err != nil {

			return changes, fmt.Errorf("netpolicy: prune %s: %w", o.Comment, err)
		}
		if n > 0 {

			m.log.Info("removed a tenant rule its grants no longer justify",
				"tenant", tenantID, "rule", o.Comment, "count", n)
			changes = append(changes, Change{Rule: Rule{Chain: o.Chain, Comment: o.Comment, V6: o.V6}, Removed: true})
		}
	}
	return changes, nil
}

// dropDuplicatePlatformRules removes every copy of a platform rule whose
// comment appears in DOCKER-USER more often than the platform writes it.
//
// Each platform rule has a comment of its own, so a second rule under the same
// comment is one this release did not write: a release (older or newer) that
// rendered it with a different spec, or somebody's hand edit. -C cannot see it
// — it checks for THIS release's spec, finds it, and is satisfied — and the
// other copy keeps doing whatever it did. Seen on the development VM: an older
// binary re-added the ingress accept without its egress-subnet exclusion,
// above the current one, and the hair-pin it closed was open again. Every copy
// goes; the pass below then writes the current one back in its place.
//
// ACCEPTs only. Removing an accept can only close a path, so doing it without
// asking is safe. A stray DROP is a different matter: wherever it sits it
// denies, and if it sits above an accept it breaks the egress path, which is
// an ordering violation AssertOrder reports for a human, not something to
// rearrange behind the operator's back.
func (m *Manager) dropDuplicatePlatformRules(desired []Rule) error {

	want := map[string]int{}
	for _, r := range desired {

		if !r.V6 && !r.IsDrop() {

			want[r.Comment]++
		}
	}
	listed, err := m.ipt.list(ChainDockerUser, false)
	if err != nil {

		return fmt.Errorf("netpolicy: read %s: %w", ChainDockerUser, err)
	}
	have := map[string]int{}
	for _, lr := range listed {

		have[lr.Comment]++
	}
	for comment, n := range want {

		if have[comment] <= n {

			continue
		}
		removed, err := m.ipt.removeByComment(ChainDockerUser, comment, false)
		if err != nil {

			return fmt.Errorf("netpolicy: remove duplicate %s: %w", comment, err)
		}
		m.log.Error("DRIFT REPAIRED: a platform rule was present more than once, under specs this release did not all write",
			"comment", comment, "copies", have[comment], "removed", removed)
	}
	return nil
}

// repairPosition is where a missing v4 platform rule goes.
//
// A DROP goes above the first platform deny (see denyPosition). An ACCEPT
// other than the conntrack accept goes just below the conntrack accept: at
// position 1 it would precede it, which AssertOrder reports. An ACCEPT whose
// spec changed between releases is still in the chain under its old spec and
// the same comment, so that stale copy is removed first — otherwise the old
// rule keeps accepting what the new one was written to refuse.
func (m *Manager) repairPosition(r Rule) (int, error) {

	if r.IsDrop() {

		return m.denyPosition()
	}
	if _, err := m.ipt.removeByComment(r.Chain, r.Comment, r.V6); err != nil {

		return 0, fmt.Errorf("netpolicy: remove stale %s: %w", r.Comment, err)
	}
	if r.Comment == tagConntrack {

		return 1, nil
	}
	return m.insertPosition()
}

// insertPosition is the line just after the platform's conntrack accept, or 1
// when that rule is not present yet.
func (m *Manager) insertPosition() (int, error) {

	listed, err := m.ipt.list(ChainDockerUser, false)
	if err != nil {

		return 0, fmt.Errorf("netpolicy: read %s: %w", ChainDockerUser, err)
	}
	for _, lr := range listed {

		if lr.Comment == tagConntrack {

			return lr.Line + 1, nil
		}
	}
	return 1, nil
}

// denyPosition is the line of the platform's first unconditional deny, which is
// where a per-tenant default-deny belongs: below every accept, above the denies
// that would otherwise swallow this tenant's own proxy traffic.
//
// Falls back to appending at the end of the chain when the platform scaffold is
// not present, which only happens before the first platform pass.
func (m *Manager) denyPosition() (int, error) {

	listed, err := m.ipt.list(ChainDockerUser, false)
	if err != nil {

		return 0, fmt.Errorf("netpolicy: read %s: %w", ChainDockerUser, err)
	}
	for _, lr := range listed {

		fields, ours := ParseTag(lr.Comment)
		if !ours {

			continue
		}
		if _, isPlatformDeny := fields["deny"]; isPlatformDeny {

			return lr.Line, nil
		}
	}
	return len(listed) + 1, nil
}

// OrderViolation describes a DOCKER-USER chain whose rules are in an order that
// does not work, even though every rule is present.
type OrderViolation struct {
	Reason  string `json:"reason"`
	Chain   string `json:"chain"`
	Listing string `json:"listing"`
}

func (v OrderViolation) Error() string { return "netpolicy: " + v.Reason }

// AssertOrder checks the DOCKER-USER chain against the shape
// design.md §9.5 verified:
//
//   - the conntrack ESTABLISHED,RELATED accept is the first rule this package
//     owns, and no owned ACCEPT or DROP precedes it;
//   - no ACCEPT sits below the first DROP.
//
// Only rules this package tagged are considered. Docker inserts nothing into
// DOCKER-USER itself, but an operator might, and reporting their rule as an
// ordering violation would be wrong — an untagged rule in DOCKER-USER is an
// `enforcement_without_grant` question for attestation, not an
// ordering one.
func (m *Manager) AssertOrder() error {

	listed, err := m.ipt.list(ChainDockerUser, false)
	if err != nil {

		return fmt.Errorf("netpolicy: read %s: %w", ChainDockerUser, err)
	}

	conntrackLine, firstDropLine := 0, 0
	var raw []string
	for _, lr := range listed {

		raw = append(raw, fmt.Sprintf("%d %s %s", lr.Line, lr.Target, lr.Comment))
		if _, ours := ParseTag(lr.Comment); !ours {

			continue
		}
		if lr.Comment == tagConntrack && conntrackLine == 0 {

			conntrackLine = lr.Line
		}
		if lr.Target == "DROP" && firstDropLine == 0 {

			firstDropLine = lr.Line
		}
	}
	listing := strings.Join(raw, "\n")

	if conntrackLine == 0 {

		return OrderViolation{
			Chain:   ChainDockerUser,
			Reason:  "the conntrack ESTABLISHED,RELATED accept is absent; reply traffic to a tenant will be swallowed by the RFC1918 denies",
			Listing: listing,
		}
	}
	for _, lr := range listed {

		if _, ours := ParseTag(lr.Comment); !ours {

			continue
		}
		if lr.Line < conntrackLine && (lr.Target == "ACCEPT" || lr.Target == "DROP") {

			return OrderViolation{
				Chain:   ChainDockerUser,
				Reason:  fmt.Sprintf("rule %d (%s) precedes the conntrack accept at %d", lr.Line, lr.Target, conntrackLine),
				Listing: listing,
			}
		}
		if firstDropLine > 0 && lr.Target == "ACCEPT" && lr.Line > firstDropLine {

			return OrderViolation{
				Chain:   ChainDockerUser,
				Reason:  fmt.Sprintf("ACCEPT at %d sits below the first DROP at %d; that accept can never match", lr.Line, firstDropLine),
				Listing: listing,
			}
		}
	}
	return nil
}

// Observed is one rule this package owns, as read off the live host.
type Observed struct {
	Chain   string            `json:"chain"`
	Line    int               `json:"line"`
	Target  string            `json:"target"`
	Comment string            `json:"comment"`
	Fields  map[string]string `json:"fields"`
	V6      bool              `json:"v6"`
}

// Observe returns every rule tagged by this package, from the host.
//
// This is the input to drift detection now and to internal/attest later.
// It reads the kernel, never the database: an audit that reads the same table
// that generated the rules proves nothing.
func (m *Manager) Observe() ([]Observed, error) {

	var out []Observed
	for _, chain := range []string{ChainInput, ChainDockerUser} {

		for _, v6 := range []bool{false, true} {

			listed, err := m.ipt.list(chain, v6)
			if err != nil {

				if v6 {

					continue // best-effort, as everywhere else on the v6 path
				}
				return nil, err
			}
			for _, lr := range listed {

				fields, ours := ParseTag(lr.Comment)
				if !ours {

					continue
				}
				out = append(out, Observed{
					Chain: lr.Chain, Line: lr.Line, Target: lr.Target,
					Comment: lr.Comment, Fields: fields, V6: lr.V6,
				})
			}
		}
	}
	return out, nil
}

// ErrNetworkMismatch means a network exists under a platform name but is not
// the network the platform would have created.
var ErrNetworkMismatch = errors.New("netpolicy: existing network does not match")

// checkNetwork verifies a network found by name before it is relied on.
//
// The name alone proves nothing: a network created by hand, by an older bug or
// by an operator experiment under t-<slug> could be non-internal, on another
// bridge (outside the br-t-+ INPUT drop), on another subnet (outside every rule
// written for this tenant) or IPv6-enabled. Any of those voids the isolation the
// rules assume, so a mismatch is refused and reported rather than adopted, and
// never "fixed" by deleting a network something may be attached to.
func checkNetwork(insp network.Inspect, wantInternal bool, wantBridge, wantSubnet string) error {

	var problems []string
	if insp.Internal != wantInternal {

		problems = append(problems, fmt.Sprintf("internal=%v, want %v", insp.Internal, wantInternal))
	}
	if got := insp.Options["com.docker.network.bridge.name"]; got != wantBridge {

		problems = append(problems, fmt.Sprintf("bridge %q, want %q", got, wantBridge))
	}
	if insp.Labels[LabelManaged] != "true" {

		problems = append(problems, "not labelled as platform-managed")
	}
	if insp.EnableIPv6 {

		problems = append(problems, "IPv6 enabled")
	}
	if wantSubnet != "" {

		found := false
		for _, c := range insp.IPAM.Config {

			if c.Subnet == wantSubnet {

				found = true
			}
		}
		if !found {

			problems = append(problems, fmt.Sprintf("no subnet %s", wantSubnet))
		}
	}
	if len(problems) > 0 {

		return fmt.Errorf("%w: %s: %s", ErrNetworkMismatch, insp.Name, strings.Join(problems, "; "))
	}
	return nil
}

// EnsureTenantNetwork creates a tenant's internal bridge network if absent.
//
// `internal: true` is what closes escape routes 1, 3 and 4 from one declarative
// setting, with no ruleset of the platform's own to drift (§9.2). Ingress still
// works because the edge proxy joins this network, not because a port is
// published.
func (m *Manager) EnsureTenantNetwork(ctx context.Context, slug string, alloc Allocation) error {

	name := config.NetworkName(slug)
	if insp, err := m.docker.NetworkInspect(ctx, name, network.InspectOptions{}); err == nil {

		return checkNetwork(insp, true, config.BridgeName(slug), alloc.Subnet.String())

	} else if !client.IsErrNotFound(err) {

		return fmt.Errorf("netpolicy: inspect network %s: %w", name, err)
	}
	if len(slug) > config.MaxSlugLen {

		return fmt.Errorf("netpolicy: slug %q is %d chars; the bridge name br-t-%s would exceed IFNAMSIZ and stop matching %s",
			slug, len(slug), slug, config.BridgeWildcard)
	}
	_, err := m.docker.NetworkCreate(ctx, name, network.CreateOptions{
		Driver: "bridge",
		// Explicitly off: a daemon-wide default-network-opts change would
		// otherwise give this network IPv6 that no v6 rule covers.
		EnableIPv6: ptrBool(false),
		Internal:   true, // no outbound path at all, by default
		IPAM: &network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{{
				Subnet:  alloc.Subnet.String(),
				Gateway: alloc.GatewayIP.String(),
			}},
		},
		Options: map[string]string{
			// Predictable name so the `br-t-+` INPUT wildcard covers it.
			"com.docker.network.bridge.name": config.BridgeName(slug),
		},
		Labels: map[string]string{
			LabelManaged: "true",
			LabelTenant:  slug,
		},
	})
	if err != nil {

		return fmt.Errorf("netpolicy: create network %s: %w", name, err)
	}
	return nil
}

// EnsureEgressNetwork creates the one NON-internal network in the platform.
//
// It holds the forward proxy and nothing else. A tenant joins it only while it
// has an active grant, and even then the DOCKER-USER rules permit exactly one
// destination on it — the proxy's port. Being non-internal is what gives the
// proxy a route out; it is not what gives the tenant one (§9.4).
//
// The bridge name deliberately does not match config.BridgeWildcard: the
// host-protection INPUT drop covers `br-t-+`, and the proxy is platform code
// that needs its own host path.
func (m *Manager) EnsureEgressNetwork(ctx context.Context) error {

	name := m.cfg.EgressNetwork
	if insp, err := m.docker.NetworkInspect(ctx, name, network.InspectOptions{}); err == nil {

		want := m.cfg.EgressSubnet
		if p, err := netip.ParsePrefix(want); err == nil {

			want = p.Masked().String()
		}
		return checkNetwork(insp, false, m.cfg.EgressBridge, want)

	} else if !client.IsErrNotFound(err) {

		return fmt.Errorf("netpolicy: inspect network %s: %w", name, err)
	}
	subnet, err := netip.ParsePrefix(m.cfg.EgressSubnet)
	if err != nil {

		return fmt.Errorf("netpolicy: egress subnet: %w", err)
	}
	gateway := addOffset(subnet.Masked().Addr(), gatewayOffset)
	_, err = m.docker.NetworkCreate(ctx, name, network.CreateOptions{
		Driver: "bridge",
		// Explicitly off: a daemon-wide default-network-opts change would
		// otherwise give this network IPv6 that no v6 rule covers.
		EnableIPv6: ptrBool(false),
		Internal:   false,
		IPAM: &network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{{
				Subnet:  subnet.Masked().String(),
				Gateway: gateway.String(),
			}},
		},
		Options: map[string]string{
			"com.docker.network.bridge.name": m.cfg.EgressBridge,
		},
		Labels: map[string]string{LabelManaged: "true"},
	})
	if err != nil {

		return fmt.Errorf("netpolicy: create network %s: %w", name, err)
	}
	return nil
}

// Labels the control plane puts on the Docker objects it owns, so recovery can
// enumerate them without trusting the database.
const (
	LabelManaged = "v2p.managed"
	LabelTenant  = "v2p.tenant"
)

// RemoveTenantNetwork destroys a tenant's network.
func (m *Manager) RemoveTenantNetwork(ctx context.Context, slug string) error {

	name := config.NetworkName(slug)
	err := m.docker.NetworkRemove(ctx, name)
	if err == nil || client.IsErrNotFound(err) {

		return nil
	}
	return fmt.Errorf("netpolicy: remove network %s: %w", name, err)
}

// TeardownTenant removes the tenant rules the control plane knows it wrote, and
// reports any tenant-tagged rule left behind that it did not write.
//
// Deletion matches on the comment tag, so it can never take out the
// platform-wide `br-t-+` host-protection rule: that rule is shared by every
// tenant, and removing it on one tenant's teardown would open escape route 2
// for all the others.
//
// `expected` is the rule set derived from the tenant's active grants — empty
// when the tenant has none. A leftover is therefore either a bug or something
// written outside the control plane, and it is returned rather than
// force-removed: auto-removing it would destroy the evidence that the
// `enforcement_without_grant` outcome depends on.
func (m *Manager) TeardownTenant(tenantID string, expected []Rule) (changes []Change, leftovers []Observed, err error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range expected {

		removed, err := m.ipt.remove(r)
		if err != nil {

			return changes, nil, err
		}
		if removed {

			changes = append(changes, Change{Rule: r})
		}
	}
	observed, err := m.Observe()
	if err != nil {

		return changes, nil, err
	}
	for _, o := range observed {

		if o.Fields["tenant"] == tenantID {

			leftovers = append(leftovers, o)
		}
	}
	return changes, leftovers, nil
}

// UnbackedRules returns tagged rules with nothing behind them: a tenant the
// control plane does not know about, or — now that rules carry `grant=` — a
// grant that is not in that tenant's active set.
//
// `activeGrants` maps a known tenant id onto the grant ids currently authorising
// its access. A tenant present in `known` but absent from `activeGrants` is
// simply a tenant with no grants, and any `grant=` rule bearing its id is
// unbacked.
//
// Never repaired and never deleted (§8.3, §9.6). A missing rule is a
// reliability problem; an extra one is either a platform bug or someone
// operating outside the control plane, and hiding it behind a self-healing loop
// would conceal a recurring intrusion. This is the input to the
// `enforcement_without_grant` outcome.
//
// `liveJobs` is the set of upgrade jobs still in flight, which is what backs a
// `rehearsal=` rule. Passing an empty map makes every rehearsal rule unbacked,
// which is the correct reading when no job is running.
func (m *Manager) UnbackedRules(known map[string]bool, activeGrants map[string]map[string]bool, liveJobs map[string]bool) ([]Observed, error) {

	observed, err := m.Observe()
	if err != nil {

		return nil, err
	}
	var out []Observed
	for _, o := range observed {

		if job, ok := o.Fields["rehearsal"]; ok {

			// A rehearsal rule is backed by its job being in flight, not by a
			// grant: a rehearsal is granted nothing (§12). One that outlives its
			// job is reported here and, like every other unbacked rule, left
			// exactly where it is.
			if !liveJobs[job] {

				out = append(out, o)
			}
			continue
		}
		tenant, ok := o.Fields["tenant"]
		if !ok {

			continue
		}
		if !known[tenant] || !PlatformShaped(tenant, o) {

			out = append(out, o)
			continue
		}
		grant, tagged := o.Fields["grant"]
		if tagged && !activeGrants[tenant][grant] {

			out = append(out, o)
		}
	}
	return out, nil
}

// ReservedPrefixes parses the configured never-allocate list.
func (m *Manager) ReservedPrefixes() ([]netip.Prefix, error) {

	return ParsePrefixes(m.cfg.ReservedSubnets)
}

// Pool parses the configured subnet pool.
func (m *Manager) Pool() (netip.Prefix, error) {

	return netip.ParsePrefix(m.cfg.SubnetPool)
}
