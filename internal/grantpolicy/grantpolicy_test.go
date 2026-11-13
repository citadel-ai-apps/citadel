package grantpolicy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// One case per tier, per §14.3. The reason string is asserted too: it is shown
// to the tenant verbatim in the portal, so an empty or generic one is a product
// bug, not a cosmetic one.
func TestClassifyPlacesEachRequestInItsTier(t *testing.T) {

	platform := []string{"apps.localhost"}

	cases := []struct {
		name     string
		req      grantpolicy.Request
		tc       grantpolicy.TenantContext
		wantTier int
		mentions string
	}{
		{
			name:     "concrete host is auto-granted",
			req:      grantpolicy.Request{Kind: store.GrantEgressHost, Subject: "api.stripe.com"},
			wantTier: grantpolicy.TierAuto,
			mentions: "api.stripe.com",
		},
		{
			name:     "wildcard needs a human",
			req:      grantpolicy.Request{Kind: store.GrantEgressHost, Subject: "*.stripe.com"},
			wantTier: grantpolicy.TierHuman,
			mentions: "wildcard",
		},
		{
			name:     "metadata endpoint is never grantable",
			req:      grantpolicy.Request{Kind: store.GrantEgressHost, Subject: "169.254.169.254"},
			wantTier: grantpolicy.TierDenied,
			mentions: "169.254.169.254",
		},
		{
			name:     "platform domain is never grantable",
			req:      grantpolicy.Request{Kind: store.GrantEgressHost, Subject: "victim.apps.localhost"},
			tc:       grantpolicy.TenantContext{PlatformDomains: platform},
			wantTier: grantpolicy.TierDenied,
			mentions: "platform domain",
		},
		{
			name:     "a previously revoked host cannot be auto-granted again",
			req:      grantpolicy.Request{Kind: store.GrantEgressHost, Subject: "api.stripe.com"},
			tc:       grantpolicy.TenantContext{PreviouslyRefused: true},
			wantTier: grantpolicy.TierHuman,
			mentions: "re-granting it needs a human",
		},
		{
			name:     "smtp relay needs a human",
			req:      grantpolicy.Request{Kind: store.GrantSMTPRelay, Subject: "smtp.example.com"},
			wantTier: grantpolicy.TierHuman,
			mentions: "Tier 2",
		},
		{
			name:     "operator data access is break-glass",
			req:      grantpolicy.Request{Kind: store.GrantOperatorDataAccess, Subject: "pb_data"},
			wantTier: grantpolicy.TierBreakGlass,
			mentions: "Tier 3",
		},
		{
			name:     "an unknown kind is refused rather than guessed at",
			req:      grantpolicy.Request{Kind: "root_shell", Subject: "please"},
			wantTier: grantpolicy.TierDenied,
			mentions: "root_shell",
		},
	}

	for _, c := range cases {

		t.Run(c.name, func(t *testing.T) {

			d := grantpolicy.Classify(c.req, c.tc)
			if d.Tier != c.wantTier {

				t.Fatalf("tier = %d, want %d (reason %q)", d.Tier, c.wantTier, d.Reason)
			}
			if !strings.Contains(d.Reason, c.mentions) {

				t.Errorf("reason %q does not mention %q", d.Reason, c.mentions)
			}
			if d.PolicyVersion != grantpolicy.PolicyVersion {

				t.Errorf("policy version = %q, want %q", d.PolicyVersion, grantpolicy.PolicyVersion)
			}
		})
	}
}

// §14.2: every grant expires, and the TTL differs by kind. A zero TTL would
// write a grant that never lapses, which is the failure this table prevents.
func TestEveryKindHasAFiniteTTL(t *testing.T) {

	kinds := []string{
		store.GrantEgressHost, store.GrantSMTPRelay, store.GrantObjectStorage,
		store.GrantCustomDomain, store.GrantOAuthProvider, store.GrantOperatorDataAccess,
		store.GrantBackupExport, store.GrantLogAccess, store.GrantSupportImpersonate,
	}
	for _, k := range kinds {

		if ttl := grantpolicy.DefaultTTL(k); ttl <= 0 {

			t.Errorf("DefaultTTL(%q) = %v", k, ttl)
		}
	}
	if got := grantpolicy.DefaultTTL(store.GrantOperatorDataAccess); got != time.Hour {

		t.Errorf("break-glass TTL = %v, want 60m hard", got)
	}
}

func TestInboundKindsAreRecognisedAsInbound(t *testing.T) {

	if grantpolicy.Direction(store.GrantEgressHost) != store.DirectionOutbound {

		t.Error("egress_host is not outbound")
	}
	for _, k := range []string{store.GrantOperatorDataAccess, store.GrantBackupExport,
		store.GrantLogAccess, store.GrantSupportImpersonate} {

		if grantpolicy.Direction(k) != store.DirectionInbound {

			t.Errorf("%s is not inbound; the inbound half of the grant model is the one platforms forget", k)
		}
	}
}
