package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

// fixture opens a database with one runtime version and one tenant, which is
// the precondition for every row these tests add.
func fixture(t *testing.T) (*store.DB, store.Tenant) {

	t.Helper()
	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	tn := tenant("demo")
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertTenant(ctx, tx, tn) }); err != nil {

		t.Fatal(err)
	}
	return db, tn
}

func TestReleaseHistoryAndRollbackTarget(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()

	first := store.Release{ID: "rel-1", TenantID: tn.ID, Sha256: "aaa", Manifest: `{"name":"x"}`, Status: store.ReleaseValidated}
	second := store.Release{ID: "rel-2", TenantID: tn.ID, Sha256: "bbb", Manifest: `{"name":"x"}`, Status: store.ReleaseValidated}
	err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertRelease(ctx, tx, first); err != nil {

			return err
		}
		if err := store.InsertRelease(ctx, tx, second); err != nil {

			return err
		}
		if err := store.SetReleaseStatus(ctx, tx, first.ID, store.ReleaseDeployed); err != nil {

			return err
		}
		return store.SetCurrentRelease(ctx, tx, tn.ID, first.ID)
	})
	if err != nil {

		t.Fatal(err)
	}

	got, err := store.GetRelease(ctx, db.Reader(), first.ID)
	if err != nil {

		t.Fatal(err)
	}
	if got.DeployedAt == nil {

		t.Error("deployed_at was not stamped on the transition into deployed")
	}
	rows, err := store.ListReleases(ctx, db.Reader(), tn.ID)
	if err != nil || len(rows) != 2 {

		t.Fatalf("ListReleases = %d rows, %v; want 2, nil", len(rows), err)
	}

	// The rollback target is the newest deployed release other than the current
	// one, which is what a bare `citadel rollback` uses.
	if _, err := store.PreviousDeployedRelease(ctx, db.Reader(), tn.ID, first.ID); !errors.Is(err, store.ErrReleaseNotFound) {

		t.Errorf("with one deployed release, PreviousDeployedRelease err = %v, want ErrReleaseNotFound", err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetReleaseStatus(ctx, tx, second.ID, store.ReleaseDeployed)
	}); err != nil {

		t.Fatal(err)
	}
	prev, err := store.PreviousDeployedRelease(ctx, db.Reader(), tn.ID, second.ID)
	if err != nil || prev.ID != first.ID {

		t.Fatalf("PreviousDeployedRelease = %q, %v; want rel-1", prev.ID, err)
	}
}

// §14.2: expiry is evaluated where enforcement reads the row, not swept by a
// cleanup job, so an approved-but-lapsed grant must stop being active without
// anything having rewritten it.
func TestGrantActivityFollowsExpiryAndRevocation(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	live := store.Grant{
		ID: "g-live", TenantID: tn.ID, Kind: store.GrantEgressHost, Direction: store.DirectionOutbound,
		Subject: "api.stripe.com", Tier: 1, Decision: store.DecisionAutoApproved,
		RequestedBy: "platform", RequestedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	lapsed := live
	lapsed.ID, lapsed.Subject, lapsed.ExpiresAt = "g-old", "old.example.com", now.Add(-time.Hour)
	pending := live
	pending.ID, pending.Subject, pending.Tier, pending.Decision = "g-wait", "*.slack.com", 2, store.DecisionPending

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		for _, g := range []store.Grant{live, lapsed, pending} {

			if err := store.InsertGrant(ctx, tx, g); err != nil {

				return err
			}
		}
		return nil
	}); err != nil {

		t.Fatal(err)
	}

	active, err := store.ActiveGrants(ctx, db.Reader(), tn.ID, store.GrantEgressHost, now)
	if err != nil || len(active) != 1 || active[0].ID != "g-live" {

		t.Fatalf("ActiveGrants = %+v, %v; want only g-live", active, err)
	}
	if got := lapsed.State(now); got != store.DecisionExpired {

		t.Errorf("a lapsed grant reads as %q, want expired", got)
	}
	if got := pending.State(now); got != store.DecisionPending {

		t.Errorf("a pending grant reads as %q", got)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.RevokeGrant(ctx, tx, live.ID, "platform")
	}); err != nil {

		t.Fatal(err)
	}
	active, _ = store.ActiveGrants(ctx, db.Reader(), tn.ID, store.GrantEgressHost, now)
	if len(active) != 0 {

		t.Errorf("a revoked grant is still active: %+v", active)
	}
	// A second revoke is refused rather than silently rewriting revoked_at,
	// which would move the timestamp on the record of the decision.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.RevokeGrant(ctx, tx, live.ID, "platform")
	}); !errors.Is(err, store.ErrGrantNotFound) {

		t.Errorf("double revoke err = %v, want ErrGrantNotFound", err)
	}
}

// §14.7: "revoke, then roll back" must not silently re-grant. The store
// remembers refusals so grantpolicy can send the subject to a human.
func TestSubjectWasRefusedRemembersDenialsAndRevocations(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	base := store.Grant{
		TenantID: tn.ID, Kind: store.GrantEgressHost, Direction: store.DirectionOutbound,
		Tier: 1, RequestedBy: "platform", RequestedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	fine, denied, revoked := base, base, base
	fine.ID, fine.Subject, fine.Decision = "g-1", "ok.example.com", store.DecisionAutoApproved
	denied.ID, denied.Subject, denied.Decision = "g-2", "no.example.com", store.DecisionDenied
	revoked.ID, revoked.Subject, revoked.Decision = "g-3", "gone.example.com", store.DecisionAutoApproved

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		for _, g := range []store.Grant{fine, denied, revoked} {

			if err := store.InsertGrant(ctx, tx, g); err != nil {

				return err
			}
		}
		return store.RevokeGrant(ctx, tx, revoked.ID, "platform")
	}); err != nil {

		t.Fatal(err)
	}

	cases := map[string]bool{"ok.example.com": false, "no.example.com": true, "gone.example.com": true}
	for subject, want := range cases {

		got, err := store.SubjectWasRefused(ctx, db.Reader(), tn.ID, store.GrantEgressHost, subject)
		if err != nil {

			t.Fatal(err)
		}
		if got != want {

			t.Errorf("SubjectWasRefused(%s) = %v, want %v", subject, got, want)
		}
	}
}

func TestBackupRoundTripKeepsThePBVersion(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	until := time.Now().UTC().Add(48 * time.Hour)

	b := store.Backup{
		ID: "bk-1", TenantID: tn.ID, Kind: store.BackupPreDeploy,
		Path: "/srv/citadel/backups/demo/pre_deploy/x.img.zst", SizeBytes: 4096,
		PBVersion: "0.40.4", RetainUntil: &until,
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertBackup(ctx, tx, b) }); err != nil {

		t.Fatal(err)
	}
	got, err := store.LatestBackup(ctx, db.Reader(), tn.ID, store.BackupPreDeploy)
	if err != nil {

		t.Fatal(err)
	}
	// the restore path reads this before it touches anything, so an
	// empty value here would silently disable the one-way-migration gate.
	if got.PBVersion != "0.40.4" {

		t.Errorf("pb_version = %q, want 0.40.4", got.PBVersion)
	}
	if _, err := store.LatestBackup(ctx, db.Reader(), tn.ID, store.BackupPreUpgrade); !errors.Is(err, store.ErrBackupNotFound) {

		t.Errorf("err = %v, want ErrBackupNotFound", err)
	}
}

func TestTokenLifecycle(t *testing.T) {

	db, _ := fixture(t)
	ctx := context.Background()

	row := store.APIToken{
		ID: "tk-1", PrincipalID: "platform", Name: "ci", Hash: "deadbeef",
		CreatedBy: "platform", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertToken(ctx, tx, row) }); err != nil {

		t.Fatal(err)
	}
	if err := store.TouchToken(ctx, db, row.ID); err != nil {

		t.Fatal(err)
	}
	got, err := store.TokenByID(ctx, db.Reader(), row.ID)
	if err != nil {

		t.Fatal(err)
	}
	if got.LastUsedAt == nil {

		t.Error("last_used_at was not recorded")
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.RevokeToken(ctx, tx, row.ID, "platform") }); err != nil {

		t.Fatal(err)
	}
	got, _ = store.TokenByID(ctx, db.Reader(), row.ID)
	if got.RevokedAt == nil {

		t.Error("revoked_at was not recorded")
	}
	if _, err := store.TokenByID(ctx, db.Reader(), "tk-nope"); !errors.Is(err, store.ErrTokenNotFound) {

		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

// The partial unique index is what stops a second offer racing the first, the
// same way one_owner_per_tenant stops a second owner.
func TestOnlyOneTransferOfferIsOpenAtATime(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	first := store.OwnerTransfer{
		ID: "tr-1", TenantID: tn.ID, FromPrincipal: "platform", ToPrincipal: "platform",
		OfferedBy: "platform", OfferedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertTransfer(ctx, tx, first) }); err != nil {

		t.Fatal(err)
	}
	second := first
	second.ID = "tr-2"
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertTransfer(ctx, tx, second) }); err == nil {

		t.Fatal("a second open offer was accepted")
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.CloseTransfer(ctx, tx, first.ID, store.TransferDeclined)
	}); err != nil {

		t.Fatal(err)
	}
	if _, err := store.OpenTransfer(ctx, db.Reader(), tn.ID); !errors.Is(err, store.ErrTransferNotFound) {

		t.Errorf("err = %v, want ErrTransferNotFound after the offer closed", err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertTransfer(ctx, tx, second) }); err != nil {

		t.Errorf("a new offer after the previous one closed: %v", err)
	}
}

// TestTenantsWithoutOneOwner is the INV-17 detector: a live tenant with no
// active owner is reported; a deleted one is not.
func TestTenantsWithoutOneOwner(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	seedVersion(t, db)
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertTenant(ctx, tx, tenant("demo")); err != nil {

			return err
		}
		gone := tenant("gone")
		gone.DesiredState = store.DesiredDeleted
		gone.Subnet = "10.213.9.0/29"
		return store.InsertTenant(ctx, tx, gone)
	}); err != nil {

		t.Fatal(err)
	}
	got, err := store.TenantsWithoutOneOwner(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "demo" {

		t.Fatalf("ownerless tenants = %v, want [demo]", got)
	}
}
