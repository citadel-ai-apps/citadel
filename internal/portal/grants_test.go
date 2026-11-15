package portal

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// insertGrant writes an approved egress_host grant on demo for subject, at tier.
func insertGrant(t *testing.T, f adminFixture, id, subject string, tier int, revoked bool) {

	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	g := store.Grant{
		ID: id, TenantID: "demo", Kind: store.GrantEgressHost,
		Direction: grantpolicy.Direction(store.GrantEgressHost), Subject: subject, Tier: tier,
		Decision: store.DecisionApproved, RequestedBy: "person:owner", RequestedAt: now,
		DecidedBy: "person:owner", DecidedAt: &now, PolicyVersion: grantpolicy.PolicyVersion,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if revoked {

		g.RevokedBy, g.RevokedAt = "person:owner", &now
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error { return store.InsertGrant(ctx, tx, g) }); err != nil {

		t.Fatal(err)
	}
}

// A transfer accepted in the portal carries the §14.7 rule exactly as one
// accepted over the API: the inherited Tier-2 grant gets a re-affirmation clock.
func TestPortalTransferAcceptPutsAClockOnInheritedGrants(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	insertGrant(t, f, "g-t2", "*.example.com", grantpolicy.TierHuman, false)
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		owner := identity.Actor{ID: "person:owner", Kind: identity.KindPerson}
		_, err := f.srv.ident.OfferTransfer(ctx, tx, owner, "demo", "person:admin", "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	postAs(f, "person:admin", "/t/demo/owner/accept", nil, true)
	if owner, err := f.srv.ident.CurrentOwner(ctx, "demo"); err != nil || owner != "person:admin" {

		t.Fatalf("after accepting in the portal the owner is %q (%v), want person:admin", owner, err)
	}
	pending, err := store.PendingReaffirmations(ctx, f.db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].GrantID != "g-t2" {

		t.Fatalf("pending re-affirmations after a portal accept = %v, want one for g-t2", pending)
	}
}

// A frozen tenant's access does not move (§14.5). The portal's re-enable files
// a grant request and its re-affirm is a grant decision, so both wait out the
// freeze; lifting it is the control that shows each path works otherwise.
func TestPortalGrantChangesWaitOutAFreeze(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	insertGrant(t, f, "g-rev", "api.example.com", grantpolicy.TierAuto, true)
	insertGrant(t, f, "g-aff", "*.example.org", grantpolicy.TierHuman, false)
	freeze := func(reason string) {

		if err := f.db.Tx(ctx, func(tx bun.Tx) error { return store.SetFrozen(ctx, tx, "demo", reason) }); err != nil {

			t.Fatal(err)
		}
	}
	// A real transfer gives g-aff its re-affirmation row; person:admin is the
	// owner from here on.
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		owner := identity.Actor{ID: "person:owner", Kind: identity.KindPerson}
		_, err := f.srv.ident.OfferTransfer(ctx, tx, owner, "demo", "person:admin", "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	postAs(f, "person:admin", "/t/demo/owner/accept", nil, true)
	requests := func() int {

		gs, err := store.ListGrants(ctx, f.db.Reader(), store.GrantFilter{
			TenantID: "demo", Kind: store.GrantEgressHost, Subject: "api.example.com",
		})
		if err != nil {

			t.Fatal(err)
		}
		return len(gs)
	}
	unaffirmed := func() int {

		p, err := store.PendingReaffirmations(ctx, f.db.Reader(), "demo")
		if err != nil {

			t.Fatal(err)
		}
		return len(p)
	}
	reason := url.Values{"reason": {"needed again"}}

	freeze("attestation/at-1: enforcement without grant")
	postAs(f, "person:admin", "/t/demo/grants/g-rev/reenable", reason, true)
	postAs(f, "person:admin", "/t/demo/grants/g-aff/reaffirm", nil, true)
	if n := requests(); n != 1 {

		t.Errorf("re-enable on a frozen tenant filed a request: %d rows for the subject, want 1", n)
	}
	if n := unaffirmed(); n != 1 {

		t.Errorf("re-affirm on a frozen tenant went through: %d unaffirmed, want 1", n)
	}

	freeze("")
	postAs(f, "person:admin", "/t/demo/grants/g-rev/reenable", url.Values{"reason": {"needed again"}}, true)
	postAs(f, "person:admin", "/t/demo/grants/g-aff/reaffirm", nil, true)
	if n := requests(); n != 2 {

		t.Errorf("re-enable after the freeze lifted: %d rows for the subject, want 2", n)
	}
	if n := unaffirmed(); n != 0 {

		t.Errorf("re-affirm after the freeze lifted: %d unaffirmed, want 0", n)
	}
}
