package netpolicy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/network"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

// fakeIpt stands in for the iptables binaries, without root.
//
// It APPLIES the inserts it is given rather than only recording them, so a
// later -L sees the chain as it now is. That is the whole point: position is
// computed from a listing, so a fake that always replays the original chain
// would make every "was it inserted in the right place?" assertion pass by
// construction — and rule order is the thing §9.5 says to assert
// programmatically because reading it by eye is where the bugs came from.
type fakeIpt struct {
	listings map[string]string // "bin CHAIN" -> output, kept current
	writes   []string
	// present names, by comment, the rules -C reports as installed. Everything
	// else is absent, so insert() writes it.
	present map[string]bool
}

func (f *fakeIpt) run(bin string, args ...string) (string, error) {

	if len(args) >= 2 && args[0] == "-L" {

		key := bin + " " + args[1]
		if out, ok := f.listings[key]; ok {

			return out, nil
		}
		return "Chain " + args[1] + " (policy ACCEPT)\n", nil
	}
	f.writes = append(f.writes, bin+" "+strings.Join(args, " "))
	if args[0] == "-C" {

		for i := range args {

			if args[i] == "--comment" && i+1 < len(args) && f.present[args[i+1]] {

				return "", nil
			}
		}
		return "", &iptError{bin: bin, args: args, code: 1}
	}
	if args[0] == "-I" {

		f.apply(bin, args)
	}
	if args[0] == "-D" {

		f.deleteLine(bin, args)
	}
	return "", nil
}

// deleteLine applies `-D CHAIN <line>`, which is how a rule known only from a
// listing is removed: the spec that produced it is not derivable once the grant
// that justified it is gone.
func (f *fakeIpt) deleteLine(bin string, args []string) {

	if len(args) < 3 {

		return
	}
	chain := args[1]
	line, err := strconv.Atoi(args[2])
	if err != nil {

		return
	}
	key := bin + " " + chain
	rules := parseListing(f.listings[key])
	if line < 1 || line > len(rules) {

		return
	}
	rules = append(rules[:line-1], rules[line:]...)
	f.listings[key] = listing(chain, rules...)
}

// apply inserts a synthetic listing line for an -I, at the position given.
func (f *fakeIpt) apply(bin string, args []string) {

	if len(args) < 3 {

		return
	}
	chain := args[1]
	pos, err := strconv.Atoi(args[2])
	if err != nil {

		return
	}
	target, comment := "", ""
	for i := range args {

		if args[i] == "-j" && i+1 < len(args) {

			target = args[i+1]
		}
		if args[i] == "--comment" && i+1 < len(args) {

			comment = args[i+1]
		}
	}
	line := fmt.Sprintf("%-10s all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* %s */", target, comment)

	key := bin + " " + chain
	rules := parseListing(f.listings[key])
	if pos < 1 || pos > len(rules)+1 {

		pos = len(rules) + 1
	}
	rules = append(rules, "")
	copy(rules[pos:], rules[pos-1:])
	rules[pos-1] = line
	if f.listings == nil {

		f.listings = map[string]string{}
	}
	f.listings[key] = listing(chain, rules...)
}

// parseListing is the inverse of listing(): it strips the two header lines and
// the line-number column.
func parseListing(out string) []string {

	var rules []string
	for i, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {

		if i < 2 || line == "" {

			continue
		}
		fields := strings.SplitN(strings.TrimLeft(line, " "), " ", 2)
		if len(fields) != 2 {

			continue
		}
		// num, then pkts and bytes, then the rule.
		rest := strings.TrimLeft(fields[1], " ")
		for range 2 {

			parts := strings.SplitN(rest, " ", 2)
			if len(parts) != 2 {

				break
			}
			rest = strings.TrimLeft(parts[1], " ")
		}
		rules = append(rules, rest)
	}
	return rules
}

func testManager(t *testing.T, f *fakeIpt) *Manager {

	t.Helper()
	m := &Manager{ipt: &ipt{r: f}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return m
}

// listing renders `iptables -L CHAIN -n -v --line-numbers` output: the columns
// are num, pkts, bytes, target, then the rest.
func listing(chain string, rules ...string) string {

	var b strings.Builder
	fmt.Fprintf(&b, "Chain %s (1 references)\n", chain)
	b.WriteString("num   pkts bytes target     prot opt in     out     source               destination\n")
	for i, r := range rules {

		fmt.Fprintf(&b, "%d        0     0 %s\n", i+1, r)
	}
	return b.String()
}

func conntrackLine() string {

	return `ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED /* ` + tagConntrack + ` */`
}

func denyLine(cidr string) string {

	return `DROP       all  --  *      *       0.0.0.0/0            ` + cidr + `           /* ` + tagDeny(cidr) + ` */`
}

func acceptLine(tenant string) string {

	return `ACCEPT     tcp  --  *      *       10.213.1.3           10.214.0.2           tcp dpt:3128 /* ` +
		TenantTag(tenant, "grant=g-1") + ` */`
}

// TestAssertOrderAcceptsTheVerifiedShape is the order design.md §9.5
// established: conntrack first, per-grant accepts above the denies.
func TestAssertOrderAcceptsTheVerifiedShape(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			acceptLine("demo"),
			denyLine("169.254.0.0/16"),
			denyLine("10.0.0.0/8"),
			denyLine("192.168.0.0/16"),
			denyLine("172.16.0.0/12"),
		),
	}}
	if err := testManager(t, f).AssertOrder(); err != nil {

		t.Fatalf("the verified-correct shape was rejected: %v", err)
	}
}

// TestAssertOrderRejectsDeniesAboveTheAccept is the first observed
// failure mode: the tenant→proxy accept is swallowed by the 10.0.0.0/8 deny and
// egress breaks with an opaque timeout.
func TestAssertOrderRejectsDeniesAboveTheAccept(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			denyLine("10.0.0.0/8"),
			acceptLine("demo"),
		),
	}}
	err := testManager(t, f).AssertOrder()
	if err == nil {

		t.Fatal("an ACCEPT below the first DROP was accepted; that accept can never match")
	}
	if !strings.Contains(err.Error(), "below the first DROP") {

		t.Fatalf("error %q does not name the ordering problem", err)
	}
}

// TestAssertOrderRejectsAMissingConntrackRule is the second, subtler
// failure: with the accepts above the denies but no conntrack rule, the reply
// path from the proxy has a destination inside a denied range and the
// connection half-opens and dies. DOCKER-USER runs before Docker's DOCKER-CT.
func TestAssertOrderRejectsAMissingConntrackRule(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			acceptLine("demo"),
			denyLine("10.0.0.0/8"),
		),
	}}
	err := testManager(t, f).AssertOrder()
	if err == nil {

		t.Fatal("a chain with no conntrack accept was accepted")
	}
	if !strings.Contains(err.Error(), "conntrack") {

		t.Fatalf("error %q does not name the missing conntrack accept", err)
	}
}

func TestAssertOrderRejectsRulesAboveTheConntrackAccept(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			denyLine("10.0.0.0/8"),
			conntrackLine(),
		),
	}}
	err := testManager(t, f).AssertOrder()
	if err == nil {

		t.Fatal("a DROP above the conntrack accept was accepted")
	}
	if !strings.Contains(err.Error(), "precedes the conntrack accept") {

		t.Fatalf("error %q does not name the problem", err)
	}
}

// TestAssertOrderIgnoresUntaggedRules: an operator's own rule in DOCKER-USER is
// an enforcement_without_grant question for attestation, not an
// ordering violation to report here.
func TestAssertOrderIgnoresUntaggedRules(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			`ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0`,
			conntrackLine(),
			denyLine("10.0.0.0/8"),
		),
	}}
	if err := testManager(t, f).AssertOrder(); err != nil {

		t.Fatalf("an untagged rule was treated as an ordering violation: %v", err)
	}
}

// TestPlatformRulesLandInTheVerifiedOrder checks that writing bottom-up with
// -I 1 leaves the chain in the intended top-to-bottom order.
func TestPlatformRulesLandInTheVerifiedOrder(t *testing.T) {

	f := &fakeIpt{}
	m := testManager(t, f)
	m.cfg.EdgeHTTPPort = 8080
	if _, err := m.EnsurePlatformRules(true); err != nil {

		t.Fatal(err)
	}

	var inserted []string
	for _, w := range f.writes {

		if strings.Contains(w, " -I ") {

			inserted = append(inserted, w)
		}
	}
	// Reversing the insertion order gives the resulting chain order, because
	// every insert goes to position 1.
	var chain []string
	for i := len(inserted) - 1; i >= 0; i-- {

		chain = append(chain, inserted[i])
	}

	var docker []string
	for _, c := range chain {

		if strings.Contains(c, ChainDockerUser) && strings.HasPrefix(c, "iptables ") {

			docker = append(docker, c)
		}
	}
	if len(docker) == 0 {

		t.Fatal("no DOCKER-USER rules were written")
	}
	// Identified by tag, not by "conntrack": the ingress accept matches on
	// conntrack state too.
	if !strings.Contains(docker[0], tagConntrack) {

		t.Fatalf("first DOCKER-USER rule is %q, want the conntrack accept", docker[0])
	}
	for _, c := range docker[1:] {

		if strings.Contains(c, tagConntrack) {

			t.Fatalf("the conntrack accept appears below another rule: %v", docker)
		}
	}

	// The ingress accept must sit above every deny, or off-host requests to the
	// edge are DNATed into 172.16.0.0/12 and dropped.
	ingress, firstDeny := -1, -1
	for i, c := range docker {

		if strings.Contains(c, tagIngress) && ingress < 0 {

			ingress = i
		}
		if strings.Contains(c, "-j DROP") && firstDeny < 0 {

			firstDeny = i
		}
	}
	if ingress < 0 {

		t.Fatalf("no edge ingress accept was written: %v", docker)
	}
	if firstDeny >= 0 && ingress > firstDeny {

		t.Fatalf("the edge ingress accept sits below a deny: %v", docker)
	}
	want := "--ctorigdstport " + strconv.Itoa(m.cfg.EdgeHTTPPort)
	if !strings.Contains(docker[ingress], want) || !strings.Contains(docker[ingress], "! -i br-t-+") {

		t.Fatalf("ingress accept %q does not match DNAT to the edge port from a non-tenant interface", docker[ingress])
	}
}

// TestHostProtectionIsTaggedAndWildcarded covers the host-protection rules. The tag is
// what lets teardown and test/netprobe tell the platform's rule apart from
// anyone else's identical-looking one.
func TestHostProtectionIsTaggedAndWildcarded(t *testing.T) {

	f := &fakeIpt{}
	if _, err := testManager(t, f).EnsurePlatformRules(true); err != nil {

		t.Fatal(err)
	}
	var v4, v6 bool
	for _, w := range f.writes {

		if !strings.Contains(w, " -I INPUT") {

			continue
		}
		if !strings.Contains(w, "-i br-t-+") {

			t.Fatalf("INPUT rule %q does not use the br-t-+ wildcard", w)
		}
		if !strings.Contains(w, tagHostProtect) {

			t.Fatalf("INPUT rule %q carries no v2p tag", w)
		}
		if !strings.Contains(w, "-j DROP") {

			t.Fatalf("INPUT rule %q is not a DROP", w)
		}
		if strings.HasPrefix(w, "iptables ") {

			v4 = true
		}
		if strings.HasPrefix(w, "ip6tables ") {

			v6 = true
		}
	}
	if !v4 || !v6 {

		t.Fatalf("host protection written for v4=%v v6=%v; both are required", v4, v6)
	}
}

func TestDeniedRangesCoverMetadataAndRFC1918(t *testing.T) {

	want := map[string]bool{
		// The metadata endpoint is the most likely credential-leak path and is
		// never allowlistable.
		"169.254.0.0/16": false,
		"10.0.0.0/8":     false,
		"192.168.0.0/16": false,
		"172.16.0.0/12":  false,
	}
	for _, cidr := range DeniedRanges {

		if _, ok := want[cidr]; ok {

			want[cidr] = true
		}
	}
	for cidr, present := range want {

		if !present {

			t.Errorf("%s is not in the unconditional deny set", cidr)
		}
	}
	if len(DeniedRangesV6) == 0 || DeniedRangesV6[0] != "fd00:ec2::254/128" {

		t.Errorf("the IPv6 metadata endpoint is missing from the v6 deny set: %v", DeniedRangesV6)
	}
}

func TestParseTagExtractsTenantAndGrant(t *testing.T) {

	fields, ours := ParseTag(TenantTag("demo", "grant=g-4f21"))
	if !ours {

		t.Fatal("a rule this package wrote was not recognised as ours")
	}
	if fields["tenant"] != "demo" || fields["grant"] != "g-4f21" {

		t.Fatalf("fields = %v", fields)
	}

	// Somebody else's comment must not be claimed: attestation uses this to
	// decide what the control plane is accountable for.
	if _, ours := ParseTag("netprobe tenant=npr"); ours {

		t.Fatal("a foreign comment was claimed as ours")
	}
	if _, ours := ParseTag(""); ours {

		t.Fatal("an empty comment was claimed as ours")
	}
}

func TestEgressAcceptRuleShape(t *testing.T) {

	r := EgressAcceptRule("demo", "g-1",
		netip.MustParseAddr("10.213.1.3"), netip.MustParseAddr("10.214.0.2"), 3128)
	args := r.args("-I", 1)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-s 10.213.1.3") || !strings.Contains(joined, "-d 10.214.0.2") {

		t.Fatalf("rule does not pin both addresses: %s", joined)
	}
	if !strings.Contains(joined, "--dport 3128") {

		t.Fatalf("rule does not pin the proxy port: %s", joined)
	}
	// The grant id in the comment is what makes a rule traceable to the decision
	// that authorised it (§9.6).
	if !strings.Contains(joined, "grant=g-1") {

		t.Fatalf("rule carries no grant id: %s", joined)
	}
	if !strings.HasSuffix(joined, "-j ACCEPT") {

		t.Fatalf("the target must come last: %s", joined)
	}
}

// TestIntraNetworkRuleKeepsTheIngressPathOpen covers the failure found live in
// on the host: the §9.5 RFC1918 denies also match everything inside a tenant
// network, including the edge→tenant ingress path §9.2 depends on. Without this
// accept the tenant is up and serving while every request 502s.
func TestIntraNetworkRuleKeepsTheIngressPathOpen(t *testing.T) {

	r := IntraNetworkRule("demo", config.BridgeName("demo"), testIngress())
	joined := strings.Join(r.args("-I", 2), " ")

	// Both sides pinned to the SAME interface. A wildcard on either side would
	// permit cross-tenant traffic, which is escape route 3.
	if !strings.Contains(joined, "-i br-t-demo") || !strings.Contains(joined, "-o br-t-demo") {

		t.Fatalf("the accept is not pinned to the tenant's own bridge on both sides: %s", joined)
	}
	if strings.Contains(joined, "br-t-+") {

		t.Fatalf("the accept uses the bridge wildcard, which would permit tenant-to-tenant: %s", joined)
	}
	if !strings.HasSuffix(joined, "-j ACCEPT") {

		t.Fatalf("target must come last: %s", joined)
	}
	if !strings.Contains(joined, "tenant=demo") {

		t.Fatalf("rule is not attributable to a tenant: %s", joined)
	}
}

func testIngress() Ingress {

	return Ingress{EdgeIP: netip.MustParseAddr("10.213.1.2"), TenantIP: netip.MustParseAddr("10.213.1.3")}
}

// The edge listens on its address on every tenant bridge and routes by Host
// header, so a tenant that can open a connection to it reaches every other
// tenant. Only the edge's own new connections to PocketBase are accepted.
func TestIntraNetworkRuleOnlyAdmitsTheEdgeDiallingTheTenant(t *testing.T) {

	r := IntraNetworkRule("demo", config.BridgeName("demo"), testIngress())
	joined := strings.Join(r.Spec, " ")
	for _, want := range []string{"-s 10.213.1.2", "-d 10.213.1.3", "-p tcp --dport 8090", "--ctstate NEW"} {

		if !strings.Contains(joined, want) {

			t.Errorf("intra-network accept %q is missing %q", joined, want)
		}
	}
	// The old bidirectional accept carried a different comment, so the prune
	// removes it from hosts that still have it.
	if r.Comment == TenantTag("demo", "intra-network") {

		t.Fatal("the restricted accept reuses the old rule's comment; the prune would keep the old rule")
	}
}

// A tenant whose addresses cannot be parsed gets no accept at all, and
// EnsureTenantRules refuses rather than writing a rule with no addresses.
func TestTenantRulesWithoutAnIngressAreClosed(t *testing.T) {

	if rules := TenantRules("demo", "demo", Ingress{}, nil); len(rules) != 0 {

		t.Fatalf("rules for a tenant with no ingress: %v", rules)
	}
	if _, err := testManager(t, &fakeIpt{}).EnsureTenantRules("demo", "demo", Ingress{}, nil, nil, true); err == nil {

		t.Fatal("wrote tenant rules without an ingress path")
	}
}

func TestTenantRulesAreScopedToOneTenantsBridge(t *testing.T) {

	a := TenantRules("alpha", "alpha", testIngress(), nil)
	b := TenantRules("beta", "beta", testIngress(), nil)
	if len(a) != 1 || len(b) != 1 {

		t.Fatalf("expected one rule per tenant, got %d and %d", len(a), len(b))
	}
	ja := strings.Join(a[0].args("-I", 2), " ")
	if strings.Contains(ja, "br-t-beta") {

		t.Fatalf("alpha's rule mentions beta's bridge: %s", ja)
	}
}

// TestEnsureTenantRulesLandsBelowConntrackAndAboveTheDenies pins the position.
func TestEnsureTenantRulesLandsBelowConntrackAndAboveTheDenies(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			denyLine("169.254.0.0/16"),
			denyLine("10.0.0.0/8"),
		),
	}}
	m := testManager(t, f)
	if _, err := m.EnsureTenantRules("demo", "demo", testIngress(), nil, nil, true); err != nil {

		t.Fatal(err)
	}
	var wrote string
	for _, w := range f.writes {

		if strings.Contains(w, " -I ") {

			wrote = w
		}
	}
	if wrote == "" {

		t.Fatal("no tenant rule was written")
	}
	// Position 2: immediately after the conntrack accept at line 1, and
	// therefore above the first deny at (now) line 3.
	if !strings.Contains(wrote, "-I DOCKER-USER 2 ") {

		t.Fatalf("tenant rule was inserted as %q, want position 2", wrote)
	}
}

func TestEnsureTenantRulesFallsBackToPositionOne(t *testing.T) {

	// No conntrack accept yet (a chain the platform pass has not touched):
	// position 1 is the only safe answer, and the platform pass will then
	// insert the conntrack rule above it on the same tick.
	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser),
	}}
	if _, err := testManager(t, f).EnsureTenantRules("demo", "demo", testIngress(), nil, nil, true); err != nil {

		t.Fatal(err)
	}
	found := false
	for _, w := range f.writes {

		if strings.Contains(w, "-I DOCKER-USER 1 ") {

			found = true
		}
	}
	if !found {

		t.Fatalf("expected an insert at position 1, got %v", f.writes)
	}
}

// testBinding is the egress side of a tenant, as the reconciler derives it from
// the active grant set.
func testBinding(grants ...string) *EgressBinding {

	return &EgressBinding{
		TenantIP: netip.MustParseAddr("10.214.0.3"),
		ProxyIP:  netip.MustParseAddr("10.214.0.2"),
		Port:     3128,
		GrantIDs: grants,
	}
}

// TestTenantRulesCarryOneAcceptPerGrant: the packet match is identical for every
// grant, and the rules are still written one per grant, because §9.6 requires a
// rule to name the decision that authorised it. That tag is what internal/attest
// reads off the host, and what makes an unbacked rule detectable at all.
func TestTenantRulesCarryOneAcceptPerGrant(t *testing.T) {

	rules := TenantRules("demo", "demo", testIngress(), testBinding("g-1", "g-2"))

	// intra-network accept + two grant accepts + one default deny.
	if len(rules) != 4 {

		t.Fatalf("expected 4 rules, got %d: %v", len(rules), rules)
	}
	for _, want := range []string{"grant=g-1", "grant=g-2"} {

		found := false
		for _, r := range rules {

			if strings.Contains(r.Comment, want) {

				found = true
			}
		}
		if !found {

			t.Fatalf("no rule carries %s: %v", want, rules)
		}
	}
	// The deny must be last in the slice, because EnsureTenantRules relies on
	// the slice order matching the chain order.
	if !rules[len(rules)-1].IsDrop() {

		t.Fatalf("the default deny is not the last rule: %v", rules)
	}
	// An accept with no deny below it grants everything.
	drops := 0
	for _, r := range rules {

		if r.IsDrop() {

			drops++
		}
	}
	if drops != 1 {

		t.Fatalf("expected exactly one default deny, got %d", drops)
	}
}

// TestTenantRulesWithoutGrantsAreUnchanged: the default posture writes no
// egress rule at all, which is what deny-by-default means in practice.
func TestTenantRulesWithoutGrantsAreUnchanged(t *testing.T) {

	for _, eg := range []*EgressBinding{nil, testBinding()} {

		rules := TenantRules("demo", "demo", testIngress(), eg)
		if len(rules) != 1 {

			t.Fatalf("a tenant with no active grant got %d rules: %v", len(rules), rules)
		}
		if rules[0].IsDrop() {

			t.Fatalf("the only rule is a deny, which would break the ingress path: %v", rules)
		}
	}
}

// TestEnsureTenantRulesPutsAcceptsAboveEveryDeny is the ordering assertion
// §9.5 demands be made programmatically rather than by reading the chain.
//
// Accepts go just below the conntrack rule; the tenant's own deny goes just
// above the platform's unconditional denies. Get it wrong in either direction
// and the failure is silent: an accept below a deny never matches (egress
// breaks with an opaque timeout), and a deny among the accepts shadows another
// tenant's accept.
func TestEnsureTenantRulesPutsAcceptsAboveEveryDeny(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			denyLine("169.254.0.0/16"),
			denyLine("10.0.0.0/8"),
			denyLine("192.168.0.0/16"),
			denyLine("172.16.0.0/12"),
		),
	}}
	m := testManager(t, f)
	if _, err := m.EnsureTenantRules("demo", "demo", testIngress(), testBinding("g-1", "g-2"), map[string]bool{"g-1": true, "g-2": true}, true); err != nil {

		t.Fatal(err)
	}

	// Assert the RESULTING chain, not the positions that were asked for.
	final := parseListing(f.listings["iptables DOCKER-USER"])
	// 5 seeded (conntrack + 4 platform denies) + 3 accepts + 1 tenant deny.
	if len(final) != 9 {

		t.Fatalf("expected 9 rules after the writes, got %d: %v", len(final), final)
	}
	if !strings.Contains(final[0], tagConntrack) {

		t.Fatalf("the conntrack accept is no longer first; reply traffic would be swallowed: %v", final)
	}

	firstDeny, lastAccept, tenantDeny := -1, -1, -1
	for i, line := range final {

		switch {

		case strings.HasPrefix(line, "ACCEPT"):
			lastAccept = i
		case strings.Contains(line, "egress-default-deny"):
			tenantDeny = i
			if firstDeny < 0 {

				firstDeny = i
			}
		case strings.HasPrefix(line, "DROP"):
			if firstDeny < 0 {

				firstDeny = i
			}
		}
	}
	if lastAccept > firstDeny {

		t.Fatalf("an ACCEPT at %d sits below the first DROP at %d; it can never match:\n%v",
			lastAccept, firstDeny, final)
	}
	// The tenant's own deny must be ABOVE the platform's unconditional denies:
	// below them it is unreachable, and among the accepts it would shadow
	// another tenant's.
	for i := tenantDeny + 1; i < len(final); i++ {

		if !strings.Contains(final[i], "deny=") {

			t.Fatalf("rule %d is below the tenant deny but is not a platform deny:\n%v", i, final)
		}
	}
	if err := m.AssertOrder(); err != nil {

		t.Fatalf("the chain this package just wrote does not satisfy its own ordering rule: %v", err)
	}
}

// TestEnsureTenantRulesPrunesALapsedGrantsAccept is the bug found by
// running: revoking a grant regenerated the proxy allowlist and detached the
// tenant from the egress network, but left the accept in the chain — the
// platform manufacturing the exact enforcement_without_grant condition §14.5
// exists to detect.
func TestEnsureTenantRulesPrunesALapsedGrantsAccept(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			acceptLine("demo"), // tagged grant=g-1
			denyLine("10.0.0.0/8"),
		),
	}}
	m := testManager(t, f)

	// g-1 exists but is no longer active: no binding, so it is not in the
	// desired set. The grant ROW still exists, so the platform knows it wrote
	// this rule and may collect it.
	if _, err := m.EnsureTenantRules("demo", "demo", testIngress(), nil, map[string]bool{"g-1": true}, false); err != nil {

		t.Fatal(err)
	}
	if strings.Contains(f.listings["iptables DOCKER-USER"], "grant=g-1") {

		t.Fatalf("a revoked grant's accept survived the rewrite:\n%s", f.listings["iptables DOCKER-USER"])
	}

	// The intra-network accept must NOT have been swept along with it: it is in
	// the desired set, and without it the ingress path 502s.
	if !strings.Contains(f.listings["iptables DOCKER-USER"], "intra-network") {

		t.Fatalf("the ingress accept was pruned too:\n%s", f.listings["iptables DOCKER-USER"])
	}
}

// TestEnsureTenantRulesKeepsTheDenyWhenGivenTheBinding is the restart bug: the
// reconciler's Materialise passed no binding for a tenant that already held a
// grant, and the prune took the egress-default-deny out from under a live proxy
// accept. With the real binding and grant set, an intact chain is a no-op.
func TestEnsureTenantRulesKeepsTheDenyWhenGivenTheBinding(t *testing.T) {

	intra := TenantTag("demo", "intra-network=edge")
	grant := TenantTag("demo", "grant=g-1")
	deny := TenantTag("demo", "egress-default-deny")
	chain := func() map[string]string {

		return map[string]string{
			"iptables DOCKER-USER": listing(ChainDockerUser,
				conntrackLine(),
				acceptLine("demo"), // tagged grant=g-1
				`ACCEPT     all  --  br-t-demo br-t-demo  0.0.0.0/0            0.0.0.0/0            /* `+intra+` */`,
				`DROP       all  --  *      *       10.213.1.3           0.0.0.0/0            /* `+deny+` */`,
				denyLine("10.0.0.0/8"),
			),
		}
	}
	present := map[string]bool{intra: true, grant: true, deny: true}
	known := map[string]bool{"g-1": true}

	// The hazard: no binding means the deny is not desired, so it is pruned
	// while the accept stays.
	f := &fakeIpt{listings: chain(), present: present}
	if _, err := testManager(t, f).EnsureTenantRules("demo", "demo", testIngress(), nil, nil, true); err != nil {

		t.Fatal(err)
	}
	if strings.Contains(f.listings["iptables DOCKER-USER"], deny) {

		t.Fatal("expected the no-binding call to prune the deny; the premise of this test changed")
	}

	// The fix: with the binding, nothing is written and nothing is removed.
	f = &fakeIpt{listings: chain(), present: present}
	changes, err := testManager(t, f).EnsureTenantRules("demo", "demo", testIngress(), testBinding("g-1"), known, true)
	if err != nil {

		t.Fatal(err)
	}
	if len(changes) != 0 {

		t.Fatalf("an intact chain produced changes: %v", changes)
	}
	if !strings.Contains(f.listings["iptables DOCKER-USER"], deny) {

		t.Fatalf("the default deny was removed:\n%s", f.listings["iptables DOCKER-USER"])
	}
}

// TestEnsureTenantRulesNeverPrunesAForgedGrant is the other side of the same
// boundary. A rule tagged with a grant id that has no row was authorised by
// nothing; collecting it would destroy the evidence.
func TestEnsureTenantRulesNeverPrunesAForgedGrant(t *testing.T) {

	forged := `ACCEPT     tcp  --  *      *       10.214.0.9           10.214.0.2           tcp dpt:3128 /* ` +
		TenantTag("demo", "grant=g-forged") + ` */`
	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser, conntrackLine(), forged, denyLine("10.0.0.0/8")),
	}}
	m := testManager(t, f)

	// No grant row named g-forged.
	if _, err := m.EnsureTenantRules("demo", "demo", testIngress(), nil, map[string]bool{"g-1": true}, false); err != nil {

		t.Fatal(err)
	}
	if !strings.Contains(f.listings["iptables DOCKER-USER"], "grant=g-forged") {

		t.Fatal("a rule with no grant row was garbage-collected; that destroys the evidence")
	}
	for _, w := range f.writes {

		if strings.Contains(w, " -D ") && strings.Contains(w, "g-forged") {

			t.Fatalf("the forged rule was deleted: %s", w)
		}
	}
}

// TestUnbackedRulesReportsARuleWithNoGrant proves the §9.6 tag does what it
// exists for: a rule whose grant is gone is reported, and never removed.
func TestUnbackedRulesReportsARuleWithNoGrant(t *testing.T) {

	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			acceptLine("demo"), // tagged grant=g-1
		),
	}}
	m := testManager(t, f)

	// g-1 still active: nothing to report.
	out, err := m.UnbackedRules(map[string]bool{"demo": true},
		map[string]map[string]bool{"demo": {"g-1": true}}, nil)
	if err != nil {

		t.Fatal(err)
	}
	if len(out) != 0 {

		t.Fatalf("a rule backed by an active grant was reported: %v", out)
	}

	// g-1 revoked or expired: the rule is enforcement with nothing behind it.
	out, err = m.UnbackedRules(map[string]bool{"demo": true},
		map[string]map[string]bool{"demo": {}}, nil)
	if err != nil {

		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Fields["grant"] != "g-1" {

		t.Fatalf("a rule with no matching grant was not reported: %v", out)
	}
	for _, w := range f.writes {

		if strings.Contains(w, " -D ") {

			t.Fatalf("the unbacked rule was deleted, destroying the evidence: %s", w)
		}
	}
}

// TestTenantDropRuleShape covers the default-deny that pairs with
// EgressAcceptRule. The two are written together — an accept with no deny below
// it grants everything — so the shape is pinned here alongside it.
func TestTenantDropRuleShape(t *testing.T) {

	r := TenantDropRule("demo", netip.MustParseAddr("10.213.1.3"))
	joined := strings.Join(r.args("-A", 0), " ")
	if !strings.Contains(joined, "-s 10.213.1.3") {

		t.Fatalf("the deny is not scoped to the tenant's own address: %s", joined)
	}
	if strings.Contains(joined, "-d ") {

		t.Fatalf("the deny must not be scoped to a destination, or it is not a default deny: %s", joined)
	}
	if !strings.HasSuffix(joined, "-j DROP") {

		t.Fatalf("target must come last: %s", joined)
	}
	if !strings.Contains(joined, "tenant=demo") {

		t.Fatalf("rule is not attributable to a tenant: %s", joined)
	}
}

func egressConfig() config.Config {

	return config.Config{EdgeHTTPPort: 80, EgressBridge: "br-v2p-egr", EgressSubnet: "10.214.0.0/24"}
}

// TestEgressBypassRuleDropsEverythingButTheProxy is the hole netprobe 08 and 11
// found: an address on the egress bridge that is not an allocated tenant had
// no deny at all, and Docker's MASQUERADE took it straight to the internet.
func TestEgressBypassRuleDropsEverythingButTheProxy(t *testing.T) {

	rules, err := dockerUserRules(egressConfig())
	if err != nil {

		t.Fatal(err)
	}
	bypass, ingress, firstCIDR := -1, -1, -1
	for i, r := range rules {

		switch {

		case r.Comment == tagEgressBypass:
			bypass = i
		case r.Comment == tagIngress:
			ingress = i
		case strings.Contains(r.Comment, "deny=") && firstCIDR < 0:
			firstCIDR = i
		}
	}
	if bypass < 0 {

		t.Fatalf("no egress bypass deny: %v", rules)
	}
	want := "-i br-v2p-egr ! -o br-v2p-egr ! -s 10.214.0.2 -j DROP"
	if got := strings.Join(rules[bypass].Spec, " "); got != want {

		t.Fatalf("bypass rule is %q, want %q", got, want)
	}
	if bypass < ingress || bypass > firstCIDR {

		t.Fatalf("bypass deny at %d, want below the ingress accept (%d) and above the CIDR denies (%d)",
			bypass, ingress, firstCIDR)
	}
	// Tagged as a platform deny, so a tenant's own default deny lands above it.
	if fields, _ := ParseTag(rules[bypass].Comment); fields["deny"] == "" {

		t.Fatalf("bypass rule %q is not tagged as a platform deny", rules[bypass].Comment)
	}

	bad := egressConfig()
	bad.EgressSubnet = "nonsense"
	if _, err := dockerUserRules(bad); err == nil {

		t.Fatal("an unparseable egress subnet produced a rule set")
	}
}

// TestMissingPlatformDenyLandsAboveTheDenies covers a chain that is complete
// except for one deny — drift, or a host upgraded to a release that added the
// bypass rule. Position 1 would put that DROP above the conntrack accept and
// every grant accept.
func TestMissingPlatformDenyLandsAboveTheDenies(t *testing.T) {

	ingressLine := `ACCEPT     tcp  --  !br-t-+ *       0.0.0.0/0            0.0.0.0/0            /* ` + tagIngress + ` */`
	lines := []string{conntrackLine(), ingressLine, acceptLine("demo")}
	present := map[string]bool{tagConntrack: true, tagIngress: true}
	for _, cidr := range DeniedRanges {

		lines = append(lines, denyLine(cidr))
		present[tagDeny(cidr)] = true
	}
	for _, cidr := range DeniedRangesV6 {

		present[tagDeny(cidr)] = true
	}
	f := &fakeIpt{
		listings: map[string]string{"iptables DOCKER-USER": listing(ChainDockerUser, lines...)},
		present:  present,
	}
	f.present[tagHostProtect] = true
	f.present[tagHostProtectEgress] = true
	m := testManager(t, f)
	m.cfg = egressConfig()

	changes, err := m.EnsurePlatformRules(false)
	if err != nil {

		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Rule.Comment != tagEgressBypass {

		t.Fatalf("want exactly the bypass deny written, got %v", changes)
	}
	final := parseListing(f.listings["iptables DOCKER-USER"])
	want := []string{tagConntrack, tagIngress, "grant=g-1", tagEgressBypass, tagDeny(DeniedRanges[0])}
	for i, w := range want {

		if !strings.Contains(final[i], w) {

			t.Fatalf("line %d is %q, want %q:\n%v", i+1, final[i], w, strings.Join(final, "\n"))
		}
	}
	if err := m.AssertOrder(); err != nil {

		t.Fatalf("the repaired chain fails the ordering check: %v", err)
	}
}

// The egress bridge is outside br-t-+ and its gateway is the host, so without
// a drop of its own a granted tenant reaches every host service.
func TestEgressBridgeHasItsOwnHostProtection(t *testing.T) {

	f := &fakeIpt{}
	m := testManager(t, f)
	m.cfg = egressConfig()
	if _, err := m.EnsurePlatformRules(true); err != nil {

		t.Fatal(err)
	}
	var v4, v6 bool
	for _, w := range f.writes {

		if !strings.Contains(w, " -I INPUT") || !strings.Contains(w, tagHostProtectEgress) {

			continue
		}
		switch {

		case strings.HasPrefix(w, "iptables ") && strings.Contains(w, "-i br-v2p-egr ! -s 10.214.0.2 ") &&
			strings.HasSuffix(w, "-j DROP"):
			v4 = true
		case strings.HasPrefix(w, "ip6tables ") && strings.Contains(w, "-i br-v2p-egr ") &&
			!strings.Contains(w, " -s ") && strings.HasSuffix(w, "-j DROP"):
			v6 = true
		default:
			t.Errorf("unexpected egress host-protection rule %q", w)
		}
	}
	if !v4 || !v6 {

		t.Fatalf("egress bridge host protection written for v4=%v v6=%v; both are required", v4, v6)
	}
}

// A granted tenant hair-pinning to the edge through the host address arrives
// DNATed from the egress bridge; the ingress accept must not take it.
func TestIngressAcceptExcludesTheEgressSubnet(t *testing.T) {

	rules, err := dockerUserRules(egressConfig())
	if err != nil {

		t.Fatal(err)
	}
	for _, r := range rules {

		if r.Comment != tagIngress {

			continue
		}
		spec := strings.Join(r.Spec, " ")
		if !strings.Contains(spec, "! -i br-t-+") || !strings.Contains(spec, "! -s 10.214.0.0/24") {

			t.Fatalf("ingress accept %q admits the egress subnet", spec)
		}
		return
	}
	t.Fatal("no ingress accept")
}

// A release that changes the ingress accept's spec finds the old one still in
// the chain under the same comment. It must be replaced, not joined, and the
// replacement must land below the conntrack accept.
func TestStaleIngressAcceptIsReplaced(t *testing.T) {

	oldIngress := `ACCEPT     tcp  --  !br-t-+ *       0.0.0.0/0            0.0.0.0/0            /* ` + tagIngress + ` */`
	lines := []string{conntrackLine(), oldIngress, acceptLine("demo")}
	present := map[string]bool{tagConntrack: true, tagHostProtect: true, tagHostProtectEgress: true, tagEgressBypass: true}
	for _, cidr := range DeniedRanges {

		lines = append(lines, denyLine(cidr))
		present[tagDeny(cidr)] = true
	}
	for _, cidr := range DeniedRangesV6 {

		present[tagDeny(cidr)] = true
	}
	f := &fakeIpt{
		listings: map[string]string{"iptables DOCKER-USER": listing(ChainDockerUser, lines...)},
		present:  present, // the ingress accept's new spec is not installed
	}
	m := testManager(t, f)
	m.cfg = egressConfig()
	if _, err := m.EnsurePlatformRules(false); err != nil {

		t.Fatal(err)
	}
	final := parseListing(f.listings["iptables DOCKER-USER"])
	count := 0
	for _, l := range final {

		if strings.Contains(l, tagIngress) {

			count++
		}
	}
	if count != 1 {

		t.Fatalf("%d ingress accepts in the chain, want 1:\n%s", count, strings.Join(final, "\n"))
	}
	if !strings.Contains(final[0], tagConntrack) || !strings.Contains(final[1], tagIngress) {

		t.Fatalf("chain order after repair:\n%s", strings.Join(final, "\n"))
	}
	if err := m.AssertOrder(); err != nil {

		t.Fatalf("the repaired chain fails the ordering check: %v", err)
	}
}

// failV6 is a runner whose ip6tables cannot write, the state of a host where
// the v6 filter table failed to load or a rule was rejected.
type failV6 struct{ fakeIpt }

func (f *failV6) run(bin string, args ...string) (string, error) {

	if bin == ipt6 && len(args) > 0 && args[0] == "-I" {

		return "", &iptError{bin: bin, args: args, code: 4}
	}
	return f.fakeIpt.run(bin, args...)
}

// On a kernel with IPv6, a v6 host-protection rule that could not be written
// leaves every service on the host reachable over v6 from tenant bridges, and
// a v6 DOCKER-USER deny that could not be written leaves the metadata address
// routable (INV-7). Both are errors, not warnings; only a kernel without IPv6
// (or, for DOCKER-USER, no v6 chain at all) makes them moot.
func TestV6HostProtectionFailsClosedWhenTheKernelHasIPv6(t *testing.T) {

	for _, hasV6 := range []bool{true, false} {

		f := &failV6{}
		m := &Manager{ipt: &ipt{r: f}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			hostHasIPv6: func() bool { return hasV6 }}
		_, err := m.EnsurePlatformRules(true)
		if hasV6 && err == nil {

			t.Fatal("a failed v6 host-protection rule was only logged on a kernel with IPv6")
		}
		if !hasV6 && err != nil {

			t.Fatalf("a kernel without IPv6 failed the platform pass: %v", err)
		}
	}
}

// A network found under a platform name is only adopted if it is the network
// the platform would have created.
func TestCheckNetworkRefusesAnImpostor(t *testing.T) {

	good := network.Inspect{
		Name: "t-demo", Internal: true,
		Options: map[string]string{"com.docker.network.bridge.name": "br-t-demo"},
		Labels:  map[string]string{LabelManaged: "true"},
		IPAM:    network.IPAM{Config: []network.IPAMConfig{{Subnet: "10.213.1.0/29"}}},
	}
	if err := checkNetwork(good, true, "br-t-demo", "10.213.1.0/29"); err != nil {

		t.Fatalf("the platform's own network was refused: %v", err)
	}
	for name, mutate := range map[string]func(*network.Inspect){
		"not internal":   func(n *network.Inspect) { n.Internal = false },
		"other bridge":   func(n *network.Inspect) { n.Options = map[string]string{"com.docker.network.bridge.name": "docker1"} },
		"unlabelled":     func(n *network.Inspect) { n.Labels = nil },
		"ipv6":           func(n *network.Inspect) { n.EnableIPv6 = true },
		"another subnet": func(n *network.Inspect) { n.IPAM.Config = []network.IPAMConfig{{Subnet: "172.30.0.0/16"}} },
	} {

		n := good
		mutate(&n)
		if err := checkNetwork(n, true, "br-t-demo", "10.213.1.0/29"); !errors.Is(err, ErrNetworkMismatch) {

			t.Errorf("%s: err = %v, want ErrNetworkMismatch", name, err)
		}
	}
}

// An older release re-adds the ingress accept under its old spec, above the
// current one. -C finds the current spec and is satisfied, so without a
// duplicate check the old copy keeps accepting what the new one refuses.
func TestDuplicatePlatformRuleIsCollapsed(t *testing.T) {

	oldIngress := `ACCEPT     tcp  --  !br-t-+ *       0.0.0.0/0            0.0.0.0/0            /* ` + tagIngress + ` */`
	lines := []string{conntrackLine(), oldIngress, oldIngress, acceptLine("demo")}
	present := map[string]bool{tagConntrack: true, tagHostProtect: true, tagHostProtectEgress: true,
		tagEgressBypass: true}
	for _, cidr := range DeniedRanges {

		lines = append(lines, denyLine(cidr))
		present[tagDeny(cidr)] = true
	}
	for _, cidr := range DeniedRangesV6 {

		present[tagDeny(cidr)] = true
	}
	f := &fakeIpt{listings: map[string]string{"iptables DOCKER-USER": listing(ChainDockerUser, lines...)}, present: present}
	m := testManager(t, f)
	m.cfg = egressConfig()
	if _, err := m.EnsurePlatformRules(false); err != nil {

		t.Fatal(err)
	}
	final := parseListing(f.listings["iptables DOCKER-USER"])
	n := 0
	for _, l := range final {

		if strings.Contains(l, tagIngress) {

			n++
		}
	}
	if n != 1 {

		t.Fatalf("%d ingress accepts after the pass, want 1:\n%s", n, strings.Join(final, "\n"))
	}
	if err := m.AssertOrder(); err != nil {

		t.Fatalf("the repaired chain fails the ordering check: %v", err)
	}
}

// A second copy of a platform DROP above the conntrack accept is an ordering
// violation to report, not a duplicate to remove quietly.
func TestDuplicatePlatformDropIsLeftForTheOrderCheck(t *testing.T) {

	lines := []string{denyLine("10.0.0.0/8"), conntrackLine(), acceptLine("demo")}
	present := map[string]bool{tagConntrack: true, tagIngress: true, tagHostProtect: true}
	for _, cidr := range DeniedRanges {

		lines = append(lines, denyLine(cidr))
		present[tagDeny(cidr)] = true
	}
	for _, cidr := range DeniedRangesV6 {

		present[tagDeny(cidr)] = true
	}
	f := &fakeIpt{listings: map[string]string{"iptables DOCKER-USER": listing(ChainDockerUser, lines...)}, present: present}
	m := testManager(t, f)
	if _, err := m.EnsurePlatformRules(false); err != nil {

		t.Fatal(err)
	}
	var violation OrderViolation
	if err := m.AssertOrder(); !errors.As(err, &violation) {

		t.Fatalf("the misplaced deny was not reported: %v", err)
	}
}

// A rule tagged for a tenant but in no shape the platform writes is foreign:
// it must be reported as unbacked and never pruned as if it were the
// platform's own (INV-19).
func TestPlatformShapedRecognisesOnlyPlatformRules(t *testing.T) {

	obs := func(comment string) Observed {

		f, _ := ParseTag(comment)
		return Observed{Comment: comment, Fields: f}
	}
	in := Ingress{EdgeIP: netip.MustParseAddr("10.0.0.2"), TenantIP: netip.MustParseAddr("10.0.0.3")}
	for _, r := range TenantRules("demo", "demo", in, &EgressBinding{
		TenantIP: in.TenantIP, ProxyIP: netip.MustParseAddr("10.1.0.2"), Port: 3128, GrantIDs: []string{"g-1"},
	}) {

		if !PlatformShaped("demo", obs(r.Comment)) {

			t.Errorf("the platform's own rule %q was not recognised", r.Comment)
		}
	}
	for _, c := range []string{TenantTag("demo", "allow-all"), TenantTag("demo"), TenantTag("other", "egress-default-deny")} {

		if PlatformShaped("demo", obs(c)) {

			t.Errorf("foreign rule %q was taken for the platform's", c)
		}
	}
}

// failV6DockerUser cannot write v6 DOCKER-USER rules, but can write INPUT.
type failV6DockerUser struct{ fakeIpt }

func (f *failV6DockerUser) run(bin string, args ...string) (string, error) {

	if bin == ipt6 && len(args) > 1 && args[0] == "-I" && args[1] == ChainDockerUser {

		return "", &iptError{bin: bin, args: args, code: 4}
	}
	return f.fakeIpt.run(bin, args...)
}

// Where the v6 DOCKER-USER chain exists, container IPv6 is being forwarded,
// and a metadata deny that cannot be written is an INV-7 gap, not a warning.
func TestV6MetadataDenyFailsClosedWhereTheChainExists(t *testing.T) {

	f := &failV6DockerUser{}
	m := &Manager{ipt: &ipt{r: f}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		hostHasIPv6: func() bool { return true }}
	if _, err := m.EnsurePlatformRules(true); err == nil {

		t.Fatal("a v6 DOCKER-USER deny that could not be written was only logged")
	}
}
