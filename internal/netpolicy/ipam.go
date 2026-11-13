package netpolicy

import (
	"errors"
	"fmt"
	"net/netip"
)

// TenantPrefixBits is the size of a tenant's subnet.
//
// A /29 gives 8 addresses: network, gateway, edge proxy, the tenant container,
// three spare, broadcast. Small on purpose — firewall rules and egress-proxy
// ACLs are written against these addresses, so a tenant should not have room to
// acquire an address the control plane did not assign.
const TenantPrefixBits = 29

// Offsets within a tenant's /29. These are explicit rather than
// Docker-assigned: netfilter rules and proxy ACLs are written against them, and
// letting Docker pick means the rules and the reality can drift (design §8.1).
const (
	gatewayOffset = 1 // the bridge, on the host
	edgeOffset    = 2 // the Caddy edge, joined to the tenant network
	tenantOffset  = 3 // the PocketBase container
)

// Offsets within the shared egress subnet (§9.4). The proxy sits at a fixed
// address so the per-grant DOCKER-USER accept has a stable destination; tenants
// start above it.
const (
	egressProxyOffset  = 2
	egressTenantOffset = 3
)

// ErrPoolExhausted means the configured pool has no free /29 left.
var ErrPoolExhausted = errors.New("netpolicy: subnet pool exhausted")

// ErrEgressPoolExhausted means every address in the egress subnet is held.
var ErrEgressPoolExhausted = errors.New("netpolicy: egress subnet exhausted")

// EgressProxyIP is the forward proxy's fixed address on the egress subnet.
func EgressProxyIP(pool netip.Prefix) (netip.Addr, error) {

	if !pool.Addr().Is4() {

		return netip.Addr{}, fmt.Errorf("netpolicy: egress subnet %s is not IPv4", pool)
	}
	addr := addOffset(pool.Masked().Addr(), egressProxyOffset)
	if !pool.Contains(addr) {

		return netip.Addr{}, fmt.Errorf("netpolicy: egress subnet %s is too small for the proxy", pool)
	}
	return addr, nil
}

// EgressGatewayIP is the host's own address on the egress bridge.
//
// It is the source address the control plane presents when it dials the proxy
// from the host, which is what the proxy's manager ACL is written against
// (§14.5). Derived with prefix arithmetic for the same reason every other
// address here is: ${SUBNET%.*}.1 lands outside any subnet not aligned on a .0.
func EgressGatewayIP(pool netip.Prefix) (netip.Addr, error) {

	if !pool.Addr().Is4() {

		return netip.Addr{}, fmt.Errorf("netpolicy: egress subnet %s is not IPv4", pool)
	}
	addr := addOffset(pool.Masked().Addr(), gatewayOffset)
	if !pool.Contains(addr) {

		return netip.Addr{}, fmt.Errorf("netpolicy: egress subnet %s is too small for a gateway", pool)
	}
	return addr, nil
}

// AllocateEgressIP returns the lowest free tenant address in the egress subnet.
//
// `taken` is every address any tenant currently records, including tenants whose
// grants have all lapsed: the address is not released when the last grant goes,
// so a proxy log line written moments before a revocation can never be
// attributed to whichever tenant picked the address up next.
//
// Run inside the transaction that persists the result, or two concurrent
// deploys can be handed the same address — and then one tenant's accept rule
// matches the other's traffic.
func AllocateEgressIP(pool netip.Prefix, taken []netip.Addr) (netip.Addr, error) {

	proxy, err := EgressProxyIP(pool)
	if err != nil {

		return netip.Addr{}, err
	}
	held := map[netip.Addr]bool{proxy: true}
	for _, a := range taken {

		held[a] = true
	}
	pool = pool.Masked()
	// The last address of an IPv4 subnet is the broadcast address.
	last := addOffset(pool.Addr(), (1<<(32-pool.Bits()))-1)
	for candidate := addOffset(pool.Addr(), egressTenantOffset); pool.Contains(candidate); candidate = addOffset(candidate, 1) {

		if candidate == last {

			break
		}
		if !held[candidate] {

			return candidate, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %s", ErrEgressPoolExhausted, pool)
}

// ParseAddrs parses a slice of address strings, skipping empties.
func ParseAddrs(in []string) ([]netip.Addr, error) {

	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {

		if s == "" {

			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {

			return nil, fmt.Errorf("netpolicy: %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// Allocation is one tenant's addressing.
type Allocation struct {
	Subnet    netip.Prefix
	GatewayIP netip.Addr
	EdgeIP    netip.Addr
	TenantIP  netip.Addr
}

// Addresses derives a tenant's fixed addresses from its subnet.
//
// Real prefix arithmetic, not string surgery: deriving the gateway with
// ${SUBNET%.*}.1 silently produces an address outside the subnet for any /29
// not aligned on a .0 third octet (10.213.1.8/29 → 10.213.1.1).
func Addresses(subnet netip.Prefix) (Allocation, error) {

	if !subnet.Addr().Is4() {

		return Allocation{}, fmt.Errorf("netpolicy: %s is not IPv4", subnet)
	}
	if subnet.Bits() != TenantPrefixBits {

		return Allocation{}, fmt.Errorf("netpolicy: %s is not a /%d", subnet, TenantPrefixBits)
	}
	base := subnet.Masked().Addr()
	alloc := Allocation{Subnet: subnet.Masked()}
	for _, spec := range []struct {
		off int
		dst *netip.Addr
	}{
		{gatewayOffset, &alloc.GatewayIP},
		{edgeOffset, &alloc.EdgeIP},
		{tenantOffset, &alloc.TenantIP},
	} {

		addr := addOffset(base, spec.off)
		if !subnet.Contains(addr) {

			return Allocation{}, fmt.Errorf("netpolicy: offset %d escapes %s", spec.off, subnet)
		}
		*spec.dst = addr
	}
	return alloc, nil
}

// AllocateSubnet returns the lowest free /29 in pool.
//
// taken is every subnet already held by a tenant and reserved is the
// never-allocate list (test/netprobe owns 10.213.0.0/29). The caller runs this
// inside the tenant-create transaction, so two concurrent creates cannot be
// handed the same prefix.
func AllocateSubnet(pool netip.Prefix, taken, reserved []netip.Prefix) (Allocation, error) {

	if !pool.Addr().Is4() {

		return Allocation{}, fmt.Errorf("netpolicy: pool %s is not IPv4", pool)
	}
	if pool.Bits() > TenantPrefixBits {

		return Allocation{}, fmt.Errorf("netpolicy: pool %s is smaller than a /%d", pool, TenantPrefixBits)
	}
	pool = pool.Masked()
	blocked := append(append([]netip.Prefix{}, taken...), reserved...)

	candidate := netip.PrefixFrom(pool.Addr(), TenantPrefixBits)
	for pool.Contains(candidate.Addr()) {

		if !overlapsAny(candidate, blocked) {

			return Addresses(candidate)
		}
		next := addOffset(candidate.Addr(), 1<<(32-TenantPrefixBits))
		if !next.IsValid() {

			break
		}
		candidate = netip.PrefixFrom(next, TenantPrefixBits)
	}
	return Allocation{}, fmt.Errorf("%w: %s", ErrPoolExhausted, pool)
}

func overlapsAny(p netip.Prefix, others []netip.Prefix) bool {

	for _, o := range others {

		if p.Overlaps(o) {

			return true
		}
	}
	return false
}

// addOffset adds n to an IPv4 address.
func addOffset(a netip.Addr, n int) netip.Addr {

	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	sum := uint64(v) + uint64(n)
	if sum > 0xffffffff {

		return netip.Addr{}
	}
	v = uint32(sum)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ParsePrefixes parses a slice of CIDR strings.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {

	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {

		p, err := netip.ParsePrefix(s)
		if err != nil {

			return nil, fmt.Errorf("netpolicy: %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
