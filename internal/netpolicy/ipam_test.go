package netpolicy

import (
	"errors"
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, in ...string) []netip.Prefix {

	t.Helper()
	out, err := ParsePrefixes(in)
	if err != nil {

		t.Fatal(err)
	}
	return out
}

func TestAllocateSubnetTakesTheLowestFreeBlock(t *testing.T) {

	pool := netip.MustParsePrefix("10.213.0.0/16")
	reserved := mustPrefixes(t, "10.213.0.0/29") // test/netprobe owns this

	alloc, err := AllocateSubnet(pool, nil, reserved)
	if err != nil {

		t.Fatal(err)
	}
	if alloc.Subnet.String() != "10.213.0.8/29" {

		t.Fatalf("first allocation = %s, want 10.213.0.8/29 (0.0/29 is reserved)", alloc.Subnet)
	}

	taken := mustPrefixes(t, "10.213.0.8/29", "10.213.0.16/29")
	alloc, err = AllocateSubnet(pool, taken, reserved)
	if err != nil {

		t.Fatal(err)
	}
	if alloc.Subnet.String() != "10.213.0.24/29" {

		t.Fatalf("next allocation = %s, want 10.213.0.24/29", alloc.Subnet)
	}
}

// TestAddressesUsesRealPrefixArithmetic is the bug a naive implementation has:
// deriving the gateway with derived the gateway with ${SUBNET%.*}.1, which for
// any /29 not aligned on a .0 third octet produces an address outside the
// subnet.
func TestAddressesUsesRealPrefixArithmetic(t *testing.T) {

	cases := []struct {
		subnet                  string
		gateway, edge, tenantIP string
	}{
		{"10.213.1.0/29", "10.213.1.1", "10.213.1.2", "10.213.1.3"},
		// The case the string trick got wrong: it would have said 10.213.1.1.
		{"10.213.1.8/29", "10.213.1.9", "10.213.1.10", "10.213.1.11"},
		{"10.213.1.248/29", "10.213.1.249", "10.213.1.250", "10.213.1.251"},
		{"10.213.255.240/29", "10.213.255.241", "10.213.255.242", "10.213.255.243"},
	}
	for _, tc := range cases {

		alloc, err := Addresses(netip.MustParsePrefix(tc.subnet))
		if err != nil {

			t.Errorf("Addresses(%s): %v", tc.subnet, err)
			continue
		}
		if alloc.GatewayIP.String() != tc.gateway ||
			alloc.EdgeIP.String() != tc.edge ||
			alloc.TenantIP.String() != tc.tenantIP {

			t.Errorf("Addresses(%s) = %s/%s/%s, want %s/%s/%s",
				tc.subnet, alloc.GatewayIP, alloc.EdgeIP, alloc.TenantIP,
				tc.gateway, tc.edge, tc.tenantIP)
		}
		if !alloc.Subnet.Contains(alloc.GatewayIP) || !alloc.Subnet.Contains(alloc.TenantIP) {

			t.Errorf("Addresses(%s) produced addresses outside the subnet", tc.subnet)
		}
	}
}

func TestAddressesRejectsTheWrongPrefixSize(t *testing.T) {

	for _, p := range []string{"10.213.1.0/24", "10.213.1.0/30", "fd00::/29"} {

		if _, err := Addresses(netip.MustParsePrefix(p)); err == nil {

			t.Errorf("Addresses(%s) succeeded; only IPv4 /29 is valid", p)
		}
	}
}

func TestAllocateSubnetReportsExhaustion(t *testing.T) {

	// A /29 pool holds exactly one tenant block.
	pool := netip.MustParsePrefix("10.213.7.0/29")
	if _, err := AllocateSubnet(pool, mustPrefixes(t, "10.213.7.0/29"), nil); !errors.Is(err, ErrPoolExhausted) {

		t.Fatalf("got %v, want ErrPoolExhausted", err)
	}
}

func TestAllocateSubnetSkipsOverlappingReservations(t *testing.T) {

	pool := netip.MustParsePrefix("10.213.0.0/24")
	// A /27 reservation covers four candidate /29s; the allocator must step
	// past all of them rather than stopping at the first non-identical block.
	alloc, err := AllocateSubnet(pool, nil, mustPrefixes(t, "10.213.0.0/27"))
	if err != nil {

		t.Fatal(err)
	}
	if alloc.Subnet.String() != "10.213.0.32/29" {

		t.Fatalf("allocation = %s, want 10.213.0.32/29", alloc.Subnet)
	}
}

func TestAllocateSubnetRejectsAPoolSmallerThanATenantBlock(t *testing.T) {

	if _, err := AllocateSubnet(netip.MustParsePrefix("10.213.0.0/30"), nil, nil); err == nil {

		t.Fatal("a /30 pool was accepted; it cannot hold a /29")
	}
}

// TestSequentialAllocationsNeverCollide walks the allocator the way the
// provisioning transaction does: allocate, record, allocate again.
func TestSequentialAllocationsNeverCollide(t *testing.T) {

	pool := netip.MustParsePrefix("10.213.0.0/22")
	var taken []netip.Prefix
	seen := map[string]bool{}
	for i := range 64 {

		alloc, err := AllocateSubnet(pool, taken, nil)
		if err != nil {

			t.Fatalf("allocation %d: %v", i, err)
		}
		if seen[alloc.Subnet.String()] {

			t.Fatalf("allocation %d reissued %s", i, alloc.Subnet)
		}
		seen[alloc.Subnet.String()] = true
		taken = append(taken, alloc.Subnet)
	}
}
