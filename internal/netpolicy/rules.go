package netpolicy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

// Tag renders a rule comment. Every rule carries the tenant it belongs to and,
// where one applies, the grant id that justifies it — so a rule can
// be traced to the decision that authorised it, diffed against the database,
// and garbage-collected (§9.6). A tagged rule with no matching grant is an
// incident, not drift.
func Tag(parts ...string) string {

	return TagPrefix + " " + strings.Join(parts, " ")
}

// Platform-wide rule tags.
const (
	tagHostProtect = TagPrefix + " platform host-protect"
	// The egress bridge's own INPUT drop. A separate tag from the br-t-+ pair,
	// which acceptance and netprobe scripts match by exact spec.
	tagHostProtectEgress = TagPrefix + " platform host-protect=egress"
	tagConntrack         = TagPrefix + " platform conntrack"
	tagIngress           = TagPrefix + " platform ingress"
	// Tagged as a deny so denyPosition puts each tenant's own default deny
	// above it, with the rest of the per-tenant rules.
	tagEgressBypass = TagPrefix + " platform deny=egress-bypass"
)

func tagDeny(cidr string) string { return Tag("platform", "deny="+cidr) }

// TenantTag is the comment on a rule belonging to one tenant.
func TenantTag(tenantID string, extra ...string) string {

	return Tag(append([]string{"tenant=" + tenantID}, extra...)...)
}

// hostProtectRules are the host-protection pair.
//
// DOCKER-USER is jumped from FORWARD and therefore never sees container→host
// traffic, which lands in INPUT. Confirmed empirically that a host service
// bound on 0.0.0.0 was reachable from a tenant container on an `internal:
// true` network until these rules were applied (design.md §9.3) — they
// are load-bearing, not defence in depth.
//
// The wildcard `br-t-+` is iptables interface-match syntax, so every tenant
// bridge must be named br-t-<slug>, and the slug must fit IFNAMSIZ.
//
// The egress bridge is deliberately outside that wildcard (config.EgressBridge),
// and it is the one bridge whose gateway is a route to the host: a tenant with
// a grant has an interface on it, so without a drop of its own every service
// on the host — sshd, a public portal, anything bound to 0.0.0.0 — was one hop
// away from tenant code. Everything entering from that bridge is dropped except
// what comes from the proxy, which is platform code.
func hostProtectRules(cfg config.Config) ([]Rule, error) {

	spec := []string{"-i", config.BridgeWildcard, "-j", "DROP"}
	rules := []Rule{
		{Chain: ChainInput, Spec: spec, Comment: tagHostProtect},
		{Chain: ChainInput, Spec: spec, Comment: tagHostProtect, V6: true},
	}
	if cfg.EgressBridge == "" {

		return rules, nil
	}
	proxy, err := egressProxy(cfg)
	if err != nil {

		return nil, err
	}
	return append(rules,
		Rule{
			Chain:   ChainInput,
			Spec:    []string{"-i", cfg.EgressBridge, "!", "-s", proxy.String(), "-j", "DROP"},
			Comment: tagHostProtectEgress,
		},
		// The proxy has no IPv6 address, so nothing on this bridge has any
		// business reaching the host over v6.
		Rule{
			Chain:   ChainInput,
			Spec:    []string{"-i", cfg.EgressBridge, "-j", "DROP"},
			Comment: tagHostProtectEgress,
			V6:      true,
		},
	), nil
}

func egressProxy(cfg config.Config) (netip.Addr, error) {

	pool, err := netip.ParsePrefix(cfg.EgressSubnet)
	if err != nil {

		return netip.Addr{}, fmt.Errorf("netpolicy: egress subnet: %w", err)
	}
	return EgressProxyIP(pool)
}

// DeniedRanges are never allowlistable, for any tenant, under any grant.
//
// 169.254.0.0/16 covers cloud instance metadata, which is the most likely
// credential-leak path from a tenant hook. The RFC1918 ranges cover the host's
// own networks and every other tenant's bridge.
//
// 100.64.0.0/10 is carrier-grade NAT space, which some clouds use for their own
// metadata and DNS endpoints (Alibaba's metadata service is 100.100.100.200)
// and which overlay networks such as Tailscale put on the host. 127.0.0.0/8 is
// never a legitimate forwarded destination.
var DeniedRanges = []string{
	"169.254.0.0/16",
	"10.0.0.0/8",
	"192.168.0.0/16",
	"172.16.0.0/12",
	"100.64.0.0/10",
	"127.0.0.0/8",
}

// DeniedRangesV6 is the IPv6 metadata endpoint, plus unique-local and
// link-local space, the v6 counterparts of the private ranges above.
var DeniedRangesV6 = []string{"fd00:ec2::254/128", "fc00::/7", "fe80::/10"}

// dockerUserRules returns the platform's DOCKER-USER chain in the order
// design.md §9.5 verified as correct, top to bottom:
//
//  1. conntrack ESTABLISHED,RELATED ACCEPT
//  2. the edge ingress accept
//  3. per-grant egress accepts (none when a tenant has no grant)
//  4. the egress-bridge bypass deny (see egressBypassRule)
//  5. the unconditional denies
//
// Rule 1 is not optional and its position is not cosmetic. DOCKER-USER runs
// before Docker's own DOCKER-CT established-accept, and the reply path from an
// egress proxy back to a tenant has a destination inside a denied RFC1918
// range — so without it the connection half-opens and dies. Observed
// exactly that after fixing the more obvious accept-below-deny ordering bug.
//
// Rule 2 is the same trap on the ingress side. A request arriving on the
// host's own address is DNATed by Docker to the edge container, whose address
// is on docker0 inside 172.16.0.0/12, and then traverses FORWARD — so the
// RFC1918 deny swallows the SYN and ingress from off the host times out. It
// hides well: a request to 127.0.0.1 goes through docker-proxy and never
// touches FORWARD, so the health checker and an in-guest curl both succeed.
// Observed live from the Mac against the UTM guest.
//
// Matched on the conntrack DNAT state and original destination port rather than
// on the edge's address or bridge, which change when the edge is recreated:
// only a published host port produces that state, and the edge is the only
// container that publishes one (INV-12). Tenant bridges are excluded so a
// tenant cannot hair-pin to the edge through the host address.
func dockerUserRules(cfg config.Config) ([]Rule, error) {

	ingress := []string{"-p", "tcp", "!", "-i", "br-t-+"}
	if cfg.EgressBridge != "" {

		// The egress bridge is not a tenant bridge, so the interface exclusion
		// above does not cover it, and a granted tenant could hair-pin to the
		// edge through the host address and reach any other tenant. Its
		// addresses all sit in the egress subnet, and FORWARD sees them before
		// Docker's MASQUERADE rewrites them.
		if _, err := netip.ParsePrefix(cfg.EgressSubnet); err != nil {

			return nil, fmt.Errorf("netpolicy: egress subnet: %w", err)
		}
		ingress = append(ingress, "!", "-s", cfg.EgressSubnet)
	}
	ingress = append(ingress,
		"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", strconv.Itoa(cfg.EdgeHTTPPort),
		"-j", "ACCEPT")
	rules := []Rule{{
		Chain:   ChainDockerUser,
		Spec:    []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		Comment: tagConntrack,
	}, {
		Chain:   ChainDockerUser,
		Spec:    ingress,
		Comment: tagIngress,
	}}
	if cfg.EgressBridge != "" {

		bypass, err := egressBypassRule(cfg)
		if err != nil {

			return nil, err
		}
		rules = append(rules, bypass)
	}
	for _, cidr := range DeniedRanges {

		rules = append(rules, Rule{
			Chain:   ChainDockerUser,
			Spec:    []string{"-d", cidr, "-j", "DROP"},
			Comment: tagDeny(cidr),
		})
	}
	for _, cidr := range DeniedRangesV6 {

		rules = append(rules, Rule{
			Chain:   ChainDockerUser,
			Spec:    []string{"-d", cidr, "-j", "DROP"},
			Comment: tagDeny(cidr),
			V6:      true,
		})
	}
	return rules, nil
}

// egressBypassRule drops everything that leaves the egress bridge for another
// interface, unless it comes from the proxy.
//
// The egress network is the one non-internal network, so Docker gives it a
// route out and a MASQUERADE. The per-tenant default deny only covers addresses
// the control plane has allocated, and the RFC1918 denies only cover private
// destinations — so any OTHER address on the bridge reached the internet
// directly, never touching the proxy. test/netprobe 08 and 11 caught exactly
// that from a sidecar on v2p-egress. This rule is what makes "the proxy is the
// only way out" true for the whole bridge rather than per allocated address.
//
// Matched on the outbound interface rather than on destination ranges, so
// tenant→proxy traffic (same bridge) is untouched and nothing about the
// address pools needs to be known. Replies from the internet to the proxy enter
// on the uplink, so they do not match either.
func egressBypassRule(cfg config.Config) (Rule, error) {

	proxy, err := egressProxy(cfg)
	if err != nil {

		return Rule{}, err
	}
	return Rule{
		Chain: ChainDockerUser,
		Spec: []string{
			"-i", cfg.EgressBridge,
			"!", "-o", cfg.EgressBridge,
			"!", "-s", proxy.String(),
			"-j", "DROP",
		},
		Comment: tagEgressBypass,
	}, nil
}

// IntraNetworkRule permits traffic that both enters and leaves one tenant's own
// bridge.
//
// This is load-bearing, and it is the trap §9.5 only half-describes. The design
// notes that Docker bridges live in 172.16.0.0/12 so a tenant→proxy ACCEPT must
// sit above the RFC1918 denies. The same problem applies to everything INSIDE a
// tenant network, including the ingress path §9.2 depends on: the edge proxy
// joins the tenant's network and dials the container, and that destination is
// inside the RFC1918 pool too. Same-bridge container traffic traverses FORWARD
// (br_netfilter), so DOCKER-USER sees it, and the deny swallows the SYN. The
// symptom is a tenant that is up and serving while every request 502s with an
// i/o timeout — observed live on the host.
//
// Scoped by INTERFACE on both sides, so cross-tenant traffic is excluded by
// construction: each tenant has its own bridge and the two interface names
// differ. A wildcard `-i br-t-+ -o br-t-+` would NOT be safe: it would permit
// tenant→tenant.
//
// And scoped by DIRECTION: only a new connection from the edge's address to
// the tenant's PocketBase port is accepted; replies ride the conntrack accept.
// The edge listens on every interface it has, including its address on this
// bridge, and routes by Host header, so a tenant that can connect to it can
// name any other tenant — one the attacker owns included, which is a two-way
// channel out of a sandbox INV-7 says has none.
//
// This rule only sees same-bridge traffic where br_netfilter is loaded, and
// Docker 29 does not load it (verified on the development VM). Where it is
// absent, a tenant CAN connect to the edge, and the boundary is the edge's
// own: every tenant route refuses client addresses in the tenant and egress
// pools (proxyctl.tenantRoute), so the request falls through to the
// catch-all 404. test/netprobe/15 asserts whichever layer the host has.
//
// It grants nothing else. Container→host is INPUT, not FORWARD, and no
// metadata or off-network address can be reached through a rule that requires
// the packet to leave on the same tenant bridge it arrived on.
func IntraNetworkRule(tenantID, bridge string, in Ingress) Rule {

	return Rule{
		Chain: ChainDockerUser,
		Spec: []string{
			"-i", bridge,
			"-o", bridge,
			"-s", in.EdgeIP.String(),
			"-d", in.TenantIP.String(),
			"-p", "tcp", "--dport", config.PocketBasePort,
			"-m", "conntrack", "--ctstate", "NEW",
			"-j", "ACCEPT",
		},
		// A different comment from the old bidirectional accept, so the prune
		// removes that rule from hosts that still carry it.
		Comment: TenantTag(tenantID, "intra-network=edge"),
	}
}

// Ingress is the one connection a tenant network carries: the edge, at its
// pinned address, dialling the tenant's container.
type Ingress struct {
	EdgeIP   netip.Addr
	TenantIP netip.Addr
}

// Valid reports whether both ends are set.
func (in Ingress) Valid() bool { return in.EdgeIP.IsValid() && in.TenantIP.IsValid() }

// ParseIngress builds an Ingress from the addresses stored on a tenant row.
func ParseIngress(edgeIP, tenantIP string) (Ingress, error) {

	e, err := netip.ParseAddr(edgeIP)
	if err != nil {

		return Ingress{}, fmt.Errorf("netpolicy: edge address %q: %w", edgeIP, err)
	}
	t, err := netip.ParseAddr(tenantIP)
	if err != nil {

		return Ingress{}, fmt.Errorf("netpolicy: tenant address %q: %w", tenantIP, err)
	}
	return Ingress{EdgeIP: e, TenantIP: t}, nil
}

// EgressAcceptRule is the per-grant hole in the deny-all posture.
//
// A manifest declaration is a request, not a grant, so a tenant with no active
// grant gets no rule at all. When one is written it lands between the conntrack
// accept and the first deny, which is the ordering the rest of the chain
// assumes.
func EgressAcceptRule(tenantID, grantID string, tenantIP, proxyIP netip.Addr, port int) Rule {

	return Rule{
		Chain: ChainDockerUser,
		Spec: []string{
			"-s", tenantIP.String(),
			"-d", proxyIP.String(),
			"-p", "tcp", "--dport", fmt.Sprint(port),
			"-j", "ACCEPT",
		},
		Comment: TenantTag(tenantID, "grant="+grantID),
	}
}

// tenantRuleShapes are the comment suffixes of every tenant rule this package
// writes, or once wrote, that carries no grant. A tenant-tagged rule with no
// grant and none of these shapes is not something the platform ever wrote.
// "intra-network" is the old bidirectional accept, kept so hosts that still
// carry it are cleaned up rather than reported.
var tenantRuleShapes = []string{"intra-network=edge", "egress-default-deny", "intra-network"}

// PlatformShaped reports whether a rule tagged for tenantID is one the
// platform writes: either grant-tagged, or one of the fixed per-tenant shapes.
func PlatformShaped(tenantID string, o Observed) bool {

	if _, ok := o.Fields["grant"]; ok {

		return true
	}
	for _, shape := range tenantRuleShapes {

		if o.Comment == TenantTag(tenantID, shape) {

			return true
		}
	}
	return false
}

// TenantDropRule denies everything else from a tenant that has egress.
func TenantDropRule(tenantID string, tenantIP netip.Addr) Rule {

	return Rule{
		Chain:   ChainDockerUser,
		Spec:    []string{"-s", tenantIP.String(), "-j", "DROP"},
		Comment: TenantTag(tenantID, "egress-default-deny"),
	}
}

// ParseTag pulls the key=value pairs out of a rule comment.
//
// internal/attest will read these off the live host to build a
// tenant's access attestation from what the kernel shows rather than from the
// database. The tag format exists for that.
func ParseTag(comment string) (fields map[string]string, ours bool) {

	parts := strings.Fields(comment)
	if len(parts) == 0 || parts[0] != TagPrefix {

		return nil, false
	}
	fields = map[string]string{}
	for _, p := range parts[1:] {

		if k, v, ok := strings.Cut(p, "="); ok {

			fields[k] = v

		} else {

			fields[p] = ""
		}
	}
	return fields, true
}
