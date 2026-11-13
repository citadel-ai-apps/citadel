package netpolicy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

// The rehearsal bridge MUST match br-t-+ and MUST fit IFNAMSIZ, and those two
// pull in opposite directions. A rehearsal runs the tenant's own hooks, so a
// bridge outside the wildcard would hand hostile code the container→host path
// the wildcard closes; a bridge over 15 characters is silently truncated by the
// kernel and stops matching anything.
func TestRehearsalBridgeFitsAndMatchesTheWildcard(t *testing.T) {

	for _, job := range []string{"uj-deadbeef", "uj-0123456789abcdef", "uj-a", "plain"} {

		slug := RehearsalSlug(job)
		if len(slug) > config.MaxSlugLen {

			t.Fatalf("slug %q for job %q is %d chars, past MaxSlugLen %d",
				slug, job, len(slug), config.MaxSlugLen)
		}
		bridge := config.BridgeName(slug)
		if len(bridge) > 15 {

			t.Fatalf("bridge %q is %d chars, past IFNAMSIZ", bridge, len(bridge))
		}
		if !strings.HasPrefix(bridge, strings.TrimSuffix(config.BridgeWildcard, "+")) {

			t.Fatalf("bridge %q does not match %q, so the host-protection INPUT drop misses it",
				bridge, config.BridgeWildcard)
		}
	}
}

func TestRehearsalSlugsAreDistinct(t *testing.T) {

	a, b := RehearsalSlug("uj-11111111"), RehearsalSlug("uj-22222222")
	if a == b {

		t.Fatalf("two jobs share the slug %q, so their networks would collide", a)
	}
}

// internal/attest filters rules on the `tenant` field to build a tenant's
// report. A rehearsal rule carrying that field would show up as enforcement the
// tenant holds no grant for — an attestation mismatch the platform
// manufactured itself.
func TestRehearsalRuleCarriesNoTenantField(t *testing.T) {

	rules := RehearsalRules("uj-deadbeef", rehearsalIngress)
	if len(rules) != 1 {

		t.Fatalf("a rehearsal has %d rules, want exactly the intra-network accept", len(rules))
	}
	fields, ours := ParseTag(rules[0].Comment)
	if !ours {

		t.Fatalf("the rule comment %q is not a platform tag", rules[0].Comment)
	}
	if _, ok := fields["tenant"]; ok {

		t.Fatal("a rehearsal rule carries a tenant field")
	}
	if fields["rehearsal"] != "uj-deadbeef" {

		t.Fatalf("rehearsal field is %q, want the job id", fields["rehearsal"])
	}
	if _, ok := fields["grant"]; ok {

		t.Fatal("a rehearsal rule carries a grant: a rehearsal is granted nothing")
	}
	if rules[0].IsDrop() || !strings.Contains(strings.Join(rules[0].Spec, " "), "ACCEPT") {

		t.Fatal("the intra-network rule is not an ACCEPT")
	}
}

// A rehearsal rule is backed by its JOB being in flight, not by a grant. One
// that outlives its job is reported — and, like every other unbacked rule,
// never removed.
func TestUnbackedRulesClassifiesRehearsalRulesByJob(t *testing.T) {

	rule := RehearsalRules("uj-deadbeef", rehearsalIngress)[0]
	f := &fakeIpt{listings: map[string]string{
		"iptables DOCKER-USER": listing(ChainDockerUser,
			conntrackLine(),
			`ACCEPT     all  --  br-t-rhdeadbeef br-t-rhdeadbeef  0.0.0.0/0            0.0.0.0/0            /* `+
				rule.Comment+` */`,
		),
	}}
	m := testManager(t, f)

	out, err := m.UnbackedRules(nil, nil, map[string]bool{"uj-deadbeef": true})
	if err != nil {

		t.Fatal(err)
	}
	if len(out) != 0 {

		t.Fatalf("a rule whose job is in flight was reported: %v", out)
	}

	out, err = m.UnbackedRules(nil, nil, nil)
	if err != nil {

		t.Fatal(err)
	}
	if len(out) != 1 {

		t.Fatalf("a leaked rehearsal rule was not reported: %v", out)
	}
	if out[0].Fields["rehearsal"] != "uj-deadbeef" {

		t.Fatalf("the report names %v, want the job", out[0].Fields)
	}
}

var rehearsalIngress = Ingress{EdgeIP: netip.MustParseAddr("10.213.9.2"), TenantIP: netip.MustParseAddr("10.213.9.3")}

// The instance under rehearsal runs the tenant's hooks (INV-1). The accept lets
// the probe reach PocketBase and nothing else: one source, one destination,
// one port, new connections only.
func TestRehearsalRuleIsOneDirectionOnePort(t *testing.T) {

	spec := strings.Join(RehearsalRules("uj-deadbeef", rehearsalIngress)[0].Spec, " ")
	for _, want := range []string{"-s 10.213.9.2", "-d 10.213.9.3", "--dport " + config.PocketBasePort, "--ctstate NEW"} {

		if !strings.Contains(spec, want) {

			t.Errorf("rehearsal accept %q lacks %q", spec, want)
		}
	}
}
