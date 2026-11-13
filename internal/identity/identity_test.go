package identity_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func setup(t *testing.T) (*store.DB, *identity.Service) {

	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, identity.New(db.Reader(), auditlog.New())
}

const testDigest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

// seedTenant inserts a tenant row directly, so ownership behaviour can be
// tested without a Docker daemon.
func seedTenant(t *testing.T, db *store.DB, id string) {

	t.Helper()
	ctx := context.Background()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1,
			ImageDigest: testDigest,
			State:       store.VersionCurrent,
		}); err != nil {

			return err
		}
		return store.InsertTenant(ctx, tx, store.Tenant{
			ID: id, Slug: id, Hostname: id + ".apps.localhost",
			DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4",
			ImageDigest: testDigest,
			NetworkName: "t-" + id, Subnet: "10.213.1.0/29",
			GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
			CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB",
			EncKeyRef: id + ".key", CreatedAt: time.Now().UTC(),
		})
	})
	if err != nil {

		t.Fatal(err)
	}
}

func mustCreate(t *testing.T, db *store.DB, s *identity.Service, id string) identity.Principal {

	t.Helper()
	ctx := context.Background()
	var p identity.Principal
	err := db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		p, err = s.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: id})
		return err
	})
	if err != nil {

		t.Fatalf("create %s: %v", id, err)
	}
	return p
}

func TestPlatformPrincipalIsSeeded(t *testing.T) {

	_, s := setup(t)
	p, err := s.Get(context.Background(), identity.PlatformPrincipal)
	if err != nil {

		t.Fatalf("the platform principal must exist from migration 001: %v", err)
	}
	if p.Kind != identity.KindPlatform || p.Status != identity.StatusActive {

		t.Fatalf("platform principal is %+v", p)
	}
}

// TestOneOwnerPerTenantIsEnforcedInSQL is the one-owner rule. The partial
// unique index is the backstop that holds for code paths nobody thought about,
// so the test goes through raw SQL rather than the service.
func TestOneOwnerPerTenantIsEnforcedInSQL(t *testing.T) {

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
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", bob.ID, identity.RoleOwner)
	})
	if err == nil {

		t.Fatal("a second active owner was accepted; one owner per tenant must be enforced by the index")
	}

	// Non-owner roles are unbounded (§14.1).
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", bob.ID, identity.RoleAdmin)
	}); err != nil {

		t.Fatalf("a second admin should be allowed: %v", err)
	}
}

func TestCurrentOwnerAndHistory(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}
	got, err := s.CurrentOwner(ctx, "demo")
	if err != nil {

		t.Fatal(err)
	}
	if got != alice.ID {

		t.Fatalf("current owner = %s, want %s", got, alice.ID)
	}
	hist, err := s.History(ctx, "demo")
	if err != nil {

		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Role != identity.RoleOwner || hist[0].RevokedAt != nil {

		t.Fatalf("history = %+v", hist)
	}
}

// TestCurrentOwnerOnAnUnownedTenantIsAnError: a tenant always has an
// owner, so the absence of one is a violation to surface rather than a nil to
// paper over.
func TestCurrentOwnerOnAnUnownedTenantIsAnError(t *testing.T) {

	db, s := setup(t)
	seedTenant(t, db, "demo")
	if _, err := s.CurrentOwner(context.Background(), "demo"); err == nil {

		t.Fatal("an unowned tenant returned an owner")
	}
}

// TestSuspendRefusesWhileTheyOwnATenant, and TestSuspendReassignsToPlatform,
// together are the orphan-owner behaviour from §14.1: the one-owner rule is
// never broken, and an orphaned tenant becomes a visible backlog item.
func TestSuspendRefusesWhileTheyOwnATenant(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	seedTenant(t, db, "demo")
	alice := mustCreate(t, db, s, "person:alice")
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.GrantRole(ctx, tx, identity.Platform(), "demo", alice.ID, identity.RoleOwner)
	}); err != nil {

		t.Fatal(err)
	}

	err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.Suspend(ctx, tx, identity.Platform(), alice.ID, false)
	})
	if !errors.Is(err, identity.ErrOwnsTenants) {

		t.Fatalf("got %v, want ErrOwnsTenants", err)
	}
}

func TestSuspendReassignsToPlatformAndFlagsOrphaned(t *testing.T) {

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

		t.Fatalf("reassigning to the platform: %v", err)
	}

	owner, err := s.CurrentOwner(ctx, "demo")
	if err != nil {

		t.Fatalf("the tenant lost its owner; every tenant must always have one: %v", err)
	}
	if owner != identity.PlatformPrincipal {

		t.Fatalf("custody went to %s, want the platform principal", owner)
	}
	tn, err := store.GetTenant(ctx, db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if !tn.OwnerOrphaned {

		t.Fatal("the tenant was not flagged owner_orphaned, so it would not show up in the fleet view")
	}
	// The previous owner's row is revoked, not deleted: "who owned this in
	// March" must stay answerable (§14.1).
	hist, err := s.History(ctx, "demo")
	if err != nil {

		t.Fatal(err)
	}
	var sawRevokedAlice bool
	for _, h := range hist {

		if h.PrincipalID == alice.ID && h.RevokedAt != nil {

			sawRevokedAlice = true
		}
	}
	if !sawRevokedAlice {

		t.Fatalf("alice's ownership row is not in the history as revoked: %+v", hist)
	}
}

func TestPlatformPrincipalCannotBeSuspended(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.Suspend(ctx, tx, identity.Platform(), identity.PlatformPrincipal, true)
	})
	if err == nil {

		t.Fatal("the platform principal was suspended; orphaned tenants would have nowhere to land")
	}
}

func TestParseID(t *testing.T) {

	cases := []struct {
		in            string
		wantKind      string
		wantName      string
		wantCanonical string
		wantErr       bool
	}{
		{in: "alice", wantKind: identity.KindPerson, wantName: "alice", wantCanonical: "person:alice"},
		{in: "person:alice", wantKind: identity.KindPerson, wantName: "alice", wantCanonical: "person:alice"},
		{in: "svc:ci", wantKind: identity.KindServiceAccount, wantName: "ci", wantCanonical: "service_account:ci"},
		{in: "service_account:ci", wantKind: identity.KindServiceAccount, wantName: "ci", wantCanonical: "service_account:ci"},
		{in: "platform", wantKind: identity.KindPlatform, wantName: "platform", wantCanonical: "platform"},
		{in: "platform:platform", wantKind: identity.KindPlatform, wantName: "platform", wantCanonical: "platform"},
		{in: "platform:root", wantErr: true},
		{in: "robot:hal", wantErr: true},
		{in: "person:Alice", wantErr: true},
		{in: "person:", wantErr: true},
		{in: "person:a b", wantErr: true},
	}
	for _, tc := range cases {

		kind, name, err := identity.ParseID(tc.in)
		if tc.wantErr {

			if err == nil {

				t.Errorf("ParseID(%q) succeeded, want an error", tc.in)
			}
			continue
		}
		if err != nil {

			t.Errorf("ParseID(%q): %v", tc.in, err)
			continue
		}
		if kind != tc.wantKind || name != tc.wantName {

			t.Errorf("ParseID(%q) = %s/%s, want %s/%s", tc.in, kind, name, tc.wantKind, tc.wantName)
		}
		if got := identity.CanonicalID(kind, name); got != tc.wantCanonical {

			t.Errorf("CanonicalID for %q = %s, want %s", tc.in, got, tc.wantCanonical)
		}
	}
}

func TestResolveActorRejectsSuspendedPrincipals(t *testing.T) {

	db, s := setup(t)
	ctx := context.Background()
	alice := mustCreate(t, db, s, "person:alice")
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return s.Suspend(ctx, tx, identity.Platform(), alice.ID, false)
	}); err != nil {

		t.Fatal(err)
	}
	if _, err := s.ResolveActor(ctx, alice.ID); err == nil {

		t.Fatal("a suspended principal resolved as an actor")
	}
}

func TestResolveActorRejectsAnEmptyPrincipal(t *testing.T) {

	_, s := setup(t)
	_, err := s.ResolveActor(context.Background(), "")
	if !errors.Is(err, identity.ErrNoActor) {

		t.Fatalf("got %v, want ErrNoActor — never a silent fall back to the platform", err)
	}
}
