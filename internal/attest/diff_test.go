package attest

import (
	"testing"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func grant(id, kind, subject string, tier int, expires time.Duration) store.Grant {

	now := time.Now().UTC()
	return store.Grant{
		ID: id, TenantID: "t-1", Kind: kind, Subject: subject, Tier: tier,
		Decision: store.DecisionApproved, DecidedBy: "person:dana",
		RequestedAt: now.Add(-time.Hour), ExpiresAt: now.Add(expires),
	}
}

func rule(tenant, grantID string) netpolicy.Observed {

	return netpolicy.Observed{
		Chain: "DOCKER-USER", Line: 3, Target: "ACCEPT",
		Comment: "v2p tenant=" + tenant + " grant=" + grantID,
		Fields:  map[string]string{"tenant": tenant, "grant": grantID},
	}
}

func fullyObserved(hosts []string, rules []netpolicy.Observed) Observed {

	return Observed{
		Reachable: hosts, ProxyReadable: true, RulesReadable: true, Rules: rules,
	}
}

func TestMatchWhenTheHostAgreesWithTheGrants(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	obs := fullyObserved([]string{"api.stripe.com"}, []netpolicy.Observed{rule("t-1", "g-1")})

	rows, findings, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeMatch {

		t.Fatalf("outcome = %s, want match (findings %+v)", outcome, findings)
	}
	if !rows[0].Enforced {

		t.Fatal("a grant the proxy is enforcing reads as not enforced")
	}
}

// Approved and not in effect is a reliability problem: the reconciler repairs
// it on the next tick, so it must not read as an incident.
func TestApprovedButNotInTheProxyIsGrantWithoutEnforcement(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	obs := fullyObserved(nil, []netpolicy.Observed{rule("t-1", "g-1")})

	_, findings, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeGrantWithoutEnforcement {

		t.Fatalf("outcome = %s, want grant_without_enforcement", outcome)
	}
	if len(findings) != 1 || findings[0].Security {

		t.Fatalf("a missing rule was graded as a security finding: %+v", findings)
	}
}

// A rule tagged with a grant id that has no row is somebody operating outside
// the control plane. This is the outcome the whole package exists for.
func TestAFabricatedGrantTagIsEnforcementWithoutGrant(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	obs := fullyObserved([]string{"api.stripe.com"},
		[]netpolicy.Observed{rule("t-1", "g-1"), rule("t-1", "g-forged")})

	_, findings, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeEnforcementWithoutGrant {

		t.Fatalf("outcome = %s, want enforcement_without_grant", outcome)
	}
	var found bool
	for _, f := range findings {

		if f.GrantID == "g-forged" && f.Security {

			found = true
		}
	}
	if !found {

		t.Fatalf("the forged tag is not named as a security finding: %+v", findings)
	}
}

// A host the running proxy allows with no grant behind it is the same class of
// problem as a fabricated rule, even though nothing in the ruleset is wrong.
func TestAnUnbackedProxyEntryIsEnforcementWithoutGrant(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	obs := fullyObserved([]string{"api.stripe.com", "evil.example.com"},
		[]netpolicy.Observed{rule("t-1", "g-1")})

	_, _, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeEnforcementWithoutGrant {

		t.Fatalf("outcome = %s, want enforcement_without_grant", outcome)
	}
}

// A security finding beats everything else. Grading on the majority would let
// an intrusion hide behind ordinary noise.
func TestSecurityFindingWinsOverAMissingRule(t *testing.T) {

	live := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	missing := grant("g-2", store.GrantEgressHost, "hooks.slack.com", 1, time.Hour)
	obs := fullyObserved([]string{"api.stripe.com"},
		[]netpolicy.Observed{rule("t-1", "g-1"), rule("t-1", "g-ghost")})

	_, _, outcome := diff([]store.Grant{live, missing}, nil, obs, expectation{})
	if outcome != store.OutcomeEnforcementWithoutGrant {

		t.Fatalf("outcome = %s, want enforcement_without_grant", outcome)
	}
}

func TestAPublishedPortIsAlwaysASecurityFinding(t *testing.T) {

	obs := fullyObserved(nil, nil)
	obs.PublishedPort = []string{"0.0.0.0:8090->8090/tcp"}

	_, findings, outcome := diff(nil, nil, obs, expectation{})
	if outcome != store.OutcomeEnforcementWithoutGrant {

		t.Fatalf("outcome = %s, want enforcement_without_grant", outcome)
	}
	if findings[0].Kind != FindPublishedPort {

		t.Fatalf("finding kind = %s, want %s", findings[0].Kind, FindPublishedPort)
	}
}

// An expired grant simply stops being an input. Nothing rewrote the row, so the
// report must not claim it is still authorising anything.
func TestAnExpiredGrantIsNotEnforced(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, -time.Minute)
	obs := fullyObserved(nil, nil)

	rows, _, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeMatch {

		t.Fatalf("outcome = %s, want match: an expired grant is not a divergence", outcome)
	}
	if rows[0].State != store.DecisionExpired || rows[0].Enforced {

		t.Fatalf("expired grant reads as %+v", rows[0])
	}
}

// §14.7: a Tier-2 grant inherited through a transfer and never re-affirmed
// stops being an input, exactly like an expired one.
func TestALapsedReaffirmationTakesAGrantOutOfEffect(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 2, time.Hour)
	obs := fullyObserved(nil, nil)

	rows, _, outcome := diff([]store.Grant{g}, map[string]bool{"g-1": true}, obs, expectation{})
	if outcome != store.OutcomeMatch {

		t.Fatalf("outcome = %s, want match", outcome)
	}
	if rows[0].State != "awaiting re-affirmation" {

		t.Fatalf("lapsed grant state = %q", rows[0].State)
	}
}

// D5 is open, so nothing generates a relay ACL or a scoped credential. Saying
// so is the honest answer; grading it as a bug would page somebody about a
// capability that was never built.
func TestANonEnforcibleKindIsReportedWithoutFailingTheOutcome(t *testing.T) {

	g := grant("g-1", store.GrantSMTPRelay, "smtp.example.com", 2, time.Hour)
	obs := fullyObserved(nil, nil)

	rows, findings, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeMatch {

		t.Fatalf("outcome = %s, want match", outcome)
	}
	if len(findings) != 1 || findings[0].Kind != FindNoEnforcement {

		t.Fatalf("findings = %+v, want one no_enforcement_path", findings)
	}
	if rows[0].Enforcible {

		t.Fatal("smtp_relay reads as enforcible; this platform cannot enforce one yet")
	}
}

// A source that could not be read must never be mistaken for a source that said
// "nothing". Otherwise an unreachable proxy silently reports every grant as
// unenforced, and an unreadable ruleset hides a rule nobody granted.
func TestAnUnreadableSourceProducesNoFindings(t *testing.T) {

	g := grant("g-1", store.GrantEgressHost, "api.stripe.com", 1, time.Hour)
	obs := Observed{ObserveErrors: []string{"egress proxy: connection refused"}}

	_, findings, outcome := diff([]store.Grant{g}, nil, obs, expectation{})
	if outcome != store.OutcomeMatch || len(findings) != 0 {

		t.Fatalf("outcome = %s, findings = %+v; an unreadable source is not evidence", outcome, findings)
	}
}

func TestSummariseDropsHostTopologyAndKeepsAccountability(t *testing.T) {

	full := Report{
		TenantID: "t-1", Slug: "acme", Outcome: store.OutcomeEnforcementWithoutGrant,
		Grants: []Granted{{ID: "g-1", Subject: "api.stripe.com", DecidedBy: "person:dana"}},
		Observed: Observed{
			Reachable: []string{"api.stripe.com"}, ProxyReadable: true,
			Networks: []string{"tenant_acme"}, BindMounts: []string{"/srv/x:/pb/pb_data:rw"},
			Rules: []netpolicy.Observed{rule("t-1", "g-1")}, ImageDigest: "sha256:abc",
			ContainerID: "deadbeef",
		},
		Findings: []Finding{{Kind: FindFirewallRule, Subject: "x", Where: "DOCKER-USER line 3",
			Detail: "no grant", Security: true}},
	}
	got := Summarise(full)

	if len(got.Observed.Networks) != 0 || len(got.Observed.Rules) != 0 ||
		len(got.Observed.BindMounts) != 0 || got.Observed.ContainerID != "" ||
		got.Observed.ImageDigest != "" {

		t.Fatalf("summary leaks platform topology: %+v", got.Observed)
	}
	if len(got.Findings) != 1 || got.Findings[0].Where != "" {

		t.Fatalf("summary keeps the finding LOCATION: %+v", got.Findings)
	}
	if !got.Findings[0].Security || got.Outcome != store.OutcomeEnforcementWithoutGrant {

		t.Fatal("summary dropped the finding itself; the tenant is owed that")
	}
	if got.Grants[0].DecidedBy != "person:dana" {

		t.Fatal("summary dropped who authorised the access")
	}
}

// A host the proxy admits through a granted wildcard is in effect, even though
// the running ACL lists only the wildcard.
func TestInEffectThroughAWildcard(t *testing.T) {

	reach := map[string]bool{"*.example.com": true, "other.org": true}
	for host, want := range map[string]bool{
		"other.org":          true,
		"*.example.com":      true,
		"api.example.com":    true,
		"a.b.example.com":    true,
		"example.com":        true, // Squid's .example.com matches the apex
		"*.deep.example.com": true,
		"example.org":        false,
		"notexample.com":     false,
		"*.other.org":        false,
	} {

		if got := inEffect(host, reach); got != want {

			t.Errorf("inEffect(%q) = %v, want %v", host, got, want)
		}
	}
}

// A rule tagged with an expired grant, a tenant-tagged rule of no platform
// shape, a network no grant justifies and an extra mount are all enforcement
// with nothing behind it (INV-19).
func TestEnforcementWithoutAnActiveGrantIsASecurityFinding(t *testing.T) {

	exp := expectation{
		TenantID: "t-1", Network: "t-t-1", EgressNetwork: "v2p-egress",
		Mounts: map[string]string{"/pb/pb_data": "rw", "/pb/app": "ro"},
	}
	clean := fullyObserved(nil, nil)
	clean.Networks = []string{"t-t-1"}
	clean.BindMounts = []string{"/srv/t-1/data:/pb/pb_data:rw", "/srv/t-1/app:/pb/app:ro"}
	if _, f, outcome := diff(nil, nil, clean, exp); outcome != store.OutcomeMatch {

		t.Fatalf("a clean tenant: outcome %s, findings %+v", outcome, f)
	}

	expired := grant("g-old", store.GrantEgressHost, "api.example.com", 1, -time.Hour)
	foreign := netpolicy.Observed{Chain: "DOCKER-USER", Comment: netpolicy.TenantTag("t-1", "allow-all")}
	foreign.Fields, _ = netpolicy.ParseTag(foreign.Comment)
	cases := map[string]Observed{}

	o := clean
	o.Rules = []netpolicy.Observed{rule("t-1", "g-old")}
	cases["rule for an expired grant"] = o

	o = clean
	o.Rules = []netpolicy.Observed{foreign}
	cases["foreign tenant rule"] = o

	o = clean
	o.Networks = []string{"t-t-1", "v2p-egress"}
	cases["egress network with no active grant"] = o

	o = clean
	o.BindMounts = append([]string{"/var/run/docker.sock:/run/docker.sock:rw"}, clean.BindMounts...)
	cases["extra mount"] = o

	o = clean
	o.BindMounts = []string{"/srv/t-1/data:/pb/pb_data:rw", "/srv/t-1/app:/pb/app:rw"}
	cases["app mounted read-write"] = o

	for name, obs := range cases {

		if _, f, outcome := diff([]store.Grant{expired}, nil, obs, exp); outcome != store.OutcomeEnforcementWithoutGrant {

			t.Errorf("%s: outcome %s, want enforcement_without_grant (findings %+v)", name, outcome, f)
		}
	}
}
