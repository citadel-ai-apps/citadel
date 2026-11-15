package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func actorFor(p identity.Principal) identity.Actor {

	return identity.Actor{ID: p.ID, Kind: p.Kind}
}

// The two-party rule (§14.1) in one test: the offer changes nothing,
// only the target can accept, and acceptance is what moves ownership.
func TestOwnershipMovesOnlyWhenTheTargetAccepts(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	bob := mustCreate(t, db, s, "person:bob")

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", bob.ID, "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	owner, err := s.CurrentOwner(ctx, "demo")
	if err != nil || owner != alice.ID {

		t.Fatalf("after the offer the owner is %q, want %q — an offer is not a transfer", owner, alice.ID)
	}
	if _, ok, _ := s.PendingTransfer(ctx, "demo"); !ok {

		t.Fatal("the offer was not recorded")
	}

	// Anyone other than the target is refused, including the current owner
	// accepting on the target's behalf.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, _, err := s.AcceptTransfer(ctx, tx, actorFor(alice), "demo")
		return err
	}); !errors.Is(err, identity.ErrNotTransferee) {

		t.Fatalf("err = %v, want ErrNotTransferee", err)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, _, err := s.AcceptTransfer(ctx, tx, actorFor(bob), "demo")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	owner, err = s.CurrentOwner(ctx, "demo")
	if err != nil || owner != bob.ID {

		t.Fatalf("after acceptance the owner is %q, want %q", owner, bob.ID)
	}
	if _, ok, _ := s.PendingTransfer(ctx, "demo"); ok {

		t.Error("the offer is still open after acceptance")
	}
	// The one-owner rule survives: exactly one active owner row, enforced by
	// the partial unique index. A second grant without a revoke would have
	// failed above.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err == nil {

		t.Error("a second active owner was accepted")
	}
}

// An operator may reassign a tenant they do not own — the departed-owner case —
// but not quietly (§14.1).
func TestAnOperatorForcedTransferNeedsAReason(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	bob := mustCreate(t, db, s, "person:bob")
	carol := mustCreate(t, db, s, "person:carol")

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(carol), "demo", bob.ID, "")
		return err
	}); !errors.Is(err, identity.ErrReasonRequired) {

		t.Fatalf("err = %v, want ErrReasonRequired", err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(carol), "demo", bob.ID, "alice left the company")
		return err
	}); err != nil {

		t.Fatalf("a forced transfer with a reason was refused: %v", err)
	}
	tr, ok, _ := s.PendingTransfer(ctx, "demo")
	if !ok || tr.Reason == "" {

		t.Error("the reason was not recorded, so the tenant cannot see why")
	}
}

func TestTransferOfferRefusesNonsense(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	bob := mustCreate(t, db, s, "person:bob")

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", alice.ID, "")
		return err
	}); !errors.Is(err, identity.ErrSelfTransfer) {

		t.Errorf("offering to the current owner: err = %v, want ErrSelfTransfer", err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", "person:nobody", "")
		return err
	}); !errors.Is(err, identity.ErrNotFound) {

		t.Errorf("offering to an unknown principal: err = %v, want ErrNotFound", err)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", bob.ID, "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", bob.ID, "")
		return err
	}); !errors.Is(err, identity.ErrTransferConflict) {

		t.Errorf("a second open offer: err = %v, want ErrTransferConflict", err)
	}

	// Declining closes the offer and leaves ownership alone.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.CloseTransfer(ctx, tx, actorFor(bob), "demo", store.TransferDeclined)
	}); err != nil {

		t.Fatal(err)
	}
	if owner, _ := s.CurrentOwner(ctx, "demo"); owner != alice.ID {

		t.Errorf("owner = %q after a decline, want %q", owner, alice.ID)
	}
}

// §14.1's role table is the first thing in the platform that authorises by
// role rather than by "you can reach the socket".
func TestRolesCarryTheCapabilitiesTheTableSays(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	dev := mustCreate(t, db, s, "person:dev")
	viewer := mustCreate(t, db, s, "person:viewer")

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := s.GrantRole(ctx, tx, identity.Platform(), "demo", dev.ID, identity.RoleDeployer); err != nil {

			return err
		}
		return s.GrantRole(ctx, tx, identity.Platform(), "demo", viewer.ID, identity.RoleViewer)
	}); err != nil {

		t.Fatal(err)
	}

	if _, err := s.Require(ctx, "demo", dev.ID, identity.CapDeploy); err != nil {

		t.Errorf("a deployer cannot deploy: %v", err)
	}
	if _, err := s.Require(ctx, "demo", dev.ID, identity.CapTransfer); !errors.Is(err, identity.ErrForbidden) {

		t.Errorf("a deployer can transfer ownership: %v", err)
	}
	if _, err := s.Require(ctx, "demo", viewer.ID, identity.CapDeploy); !errors.Is(err, identity.ErrForbidden) {

		t.Errorf("a viewer can deploy: %v", err)
	}
	if _, err := s.Role(ctx, "demo", "person:stranger"); !errors.Is(err, identity.ErrForbidden) {

		t.Errorf("a principal with no role resolved one: %v", err)
	}

	rows, err := s.TenantsFor(ctx, dev.ID)
	if err != nil || len(rows) != 1 || rows[0].Role != identity.RoleDeployer {

		t.Fatalf("TenantsFor = %+v, %v", rows, err)
	}
}

// Suspending a principal cancels every open offer to or from it: an offer to a
// suspended principal would otherwise make it an owner on reinstatement
// (INV-17).
func TestSuspendCancelsOpenOffers(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	bob := mustCreate(t, db, s, "person:bob")
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", bob.ID, "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.Suspend(ctx, tx, identity.Platform(), bob.ID, false)
	}); err != nil {

		t.Fatal(err)
	}
	if _, ok, _ := s.PendingTransfer(ctx, "demo"); ok {

		t.Fatal("an offer to a suspended principal is still open")
	}
	owner, err := s.CurrentOwner(ctx, "demo")
	if err != nil || owner != alice.ID {

		t.Fatalf("owner is %q (%v), want %q", owner, err, alice.ID)
	}
}

// Reassigning custody keeps exactly one owner and audits the revocation.
func TestSuspendWithReassignKeepsExactlyOneOwner(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.Suspend(ctx, tx, identity.Platform(), alice.ID, true)
	}); err != nil {

		t.Fatal(err)
	}
	owner, err := s.CurrentOwner(ctx, "demo")
	if err != nil || owner != identity.PlatformPrincipal {

		t.Fatalf("owner is %q (%v), want the platform", owner, err)
	}
	var n int
	if err := db.Reader().NewRaw("SELECT count(*) FROM audit_event WHERE action = ?", "tenant.owner.revoked").Scan(ctx, &n); err != nil {

		t.Fatal(err)
	}
	if n != 1 {

		t.Fatalf("%d owner.revoked events, want 1", n)
	}
}

// A transfer does not silently carry grants (§14.7). Accepting is the one path
// that moves a seat by transfer, so the inherited Tier-2 set gets its
// re-affirmation clock and its audit row there, whichever surface (API or
// portal) called it. Tier-1 grants are left alone.
func TestAcceptingATransferPutsAClockOnInheritedTier2Grants(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	bob := mustCreate(t, db, s, "person:bob")
	now := time.Now().UTC()
	grant := func(id, kind string, tier int) store.Grant {

		return store.Grant{
			ID: id, TenantID: "demo", Kind: kind, Direction: grantpolicy.Direction(kind),
			Subject: id + ".example.com", Tier: tier, Decision: store.DecisionApproved,
			RequestedBy: alice.ID, RequestedAt: now, DecidedBy: alice.ID, DecidedAt: &now,
			PolicyVersion: grantpolicy.PolicyVersion, ExpiresAt: now.Add(24 * time.Hour),
		}
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner); err != nil {

			return err
		}
		if err := store.InsertGrant(ctx, tx, grant("g-t2", store.GrantEgressHost, grantpolicy.TierHuman)); err != nil {

			return err
		}
		return store.InsertGrant(ctx, tx, grant("g-t1", store.GrantEgressHost, grantpolicy.TierAuto))
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.OfferTransfer(ctx, tx, actorFor(alice), "demo", bob.ID, "")
		return err
	}); err != nil {

		t.Fatal(err)
	}

	var inherited []store.Grant
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		_, inherited, err = s.AcceptTransfer(ctx, tx, actorFor(bob), "demo")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	if len(inherited) != 1 || inherited[0].ID != "g-t2" {

		t.Fatalf("inherited = %v, want only the Tier-2 grant g-t2", inherited)
	}
	pending, err := store.PendingReaffirmations(ctx, db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].GrantID != "g-t2" {

		t.Fatalf("pending re-affirmations = %v, want one for g-t2", pending)
	}
	if due := pending[0].DueAt.Sub(now); due < store.ReaffirmWindow-time.Minute || due > store.ReaffirmWindow+time.Minute {

		t.Errorf("re-affirmation due in %v, want %v", due, store.ReaffirmWindow)
	}
	n, err := db.Reader().NewSelect().Table("audit_event").
		Where("action = ?", auditlog.ActionGrantsInherited).Where("tenant_id = ?", "demo").Count(ctx)
	if err != nil || n != 1 {

		t.Fatalf("%s events = %d (%v), want 1", auditlog.ActionGrantsInherited, n, err)
	}
}
