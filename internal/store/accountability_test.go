package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

// newDB gives the accountability tests a real tenant and the principals the
// foreign keys demand. Grants, notifications and re-affirmations all reference
// rows that must exist, which is the schema enforcing §14's own rule that
// nothing crossing the boundary is attributable to nobody.
func newDB(t *testing.T) *store.DB {

	t.Helper()
	ctx := context.Background()
	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	err := db.Tx(ctx, func(tx bun.Tx) error {

		for _, id := range []string{"person:dana", "person:sam", "person:new"} {

			if _, err := tx.NewInsert().
				Model(&map[string]any{
					"id": id, "kind": "person", "display_name": id,
					"status": "active", "created_at": time.Now().UTC(),
				}).
				TableExpr("principal").Exec(ctx); err != nil {

				return err
			}
		}
		if err := store.InsertTenant(ctx, tx, tenant("t-demo")); err != nil {

			return err
		}
		return store.InsertTransfer(ctx, tx, store.OwnerTransfer{
			ID: "tr-1", TenantID: "t-demo", FromPrincipal: "person:dana",
			ToPrincipal: "person:new", OfferedBy: "person:dana",
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		})
	})
	if err != nil {

		t.Fatalf("seed: %v", err)
	}
	return db
}

func seedGrantRow(t *testing.T, db *store.DB, id string) {

	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertGrant(ctx, tx, store.Grant{
			ID: id, TenantID: "t-demo", Kind: store.GrantEgressHost,
			Direction: store.DirectionOutbound, Subject: id + ".example.com", Tier: 2,
			Decision: store.DecisionApproved, RequestedBy: "person:dana", RequestedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		})
	})
	if err != nil {

		t.Fatalf("seed grant %s: %v", id, err)
	}
}

func seedBreakglass(t *testing.T, db *store.DB, id, principal string, age time.Duration) store.Grant {

	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	at := now.Add(-age)
	g := store.Grant{
		ID: id, TenantID: "t-demo", Kind: store.GrantOperatorDataAccess,
		Direction: store.DirectionInbound, Subject: "pb_data", Tier: 3,
		Decision: store.DecisionApproved, RequestedBy: principal, RequestedAt: at,
		DecidedBy: principal, DecidedAt: &at, Justification: "incident",
		ExpiresAt: at.Add(store.BreakglassTTL),
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertGrant(ctx, tx, g) }); err != nil {

		t.Fatalf("insert %s: %v", id, err)
	}
	return g
}

// An unreviewed session past its window blocks the operator who opened it from
// opening another. The requester cannot clear it themselves — the review must
// come from somebody else, which is what makes the block more than a formality.
func TestUnreviewedBreakglassBlocksTheSameRequester(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	seedBreakglass(t, db, "g-old", "person:dana", 48*time.Hour)
	seedBreakglass(t, db, "g-fresh", "person:dana", time.Minute)
	seedBreakglass(t, db, "g-other", "person:sam", 48*time.Hour)

	now := time.Now().UTC()
	blocked, err := store.UnreviewedBreakglass(ctx, db.Reader(), "person:dana", now)
	if err != nil {

		t.Fatal(err)
	}
	if len(blocked) != 1 || blocked[0].ID != "g-old" {

		t.Fatalf("blocked = %+v, want only g-old (g-fresh is inside its window)", blocked)
	}

	err = db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertReview(ctx, tx, store.BreakglassReview{
			GrantID: "g-old", ReviewedBy: "person:sam",
			Outcome: store.ReviewJustified, Notes: "checked the incident ticket",
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	blocked, err = store.UnreviewedBreakglass(ctx, db.Reader(), "person:dana", now)
	if err != nil {

		t.Fatal(err)
	}
	if len(blocked) != 0 {

		t.Fatalf("still blocked after somebody else reviewed it: %+v", blocked)
	}
}

func TestOpenBreakglassIsBoundByTheHardTimeBox(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	seedBreakglass(t, db, "g-open", "person:dana", time.Minute)
	seedBreakglass(t, db, "g-lapsed", "person:dana", 2*store.BreakglassTTL)

	open, err := store.OpenBreakglass(ctx, db.Reader(), time.Now().UTC())
	if err != nil {

		t.Fatal(err)
	}
	if len(open) != 1 || open[0].ID != "g-open" {

		t.Fatalf("open = %+v; the box is hard and not extendable", open)
	}
}

// §14.7: a grant inherited through a transfer and never re-affirmed stops being
// an input at its due date. Nothing revokes it — it simply is not returned.
func TestLapsedGrantIDsReportsOnlyOverdueReaffirmations(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	now := time.Now().UTC()
	for _, id := range []string{"g-due", "g-later", "g-done"} {

		seedGrantRow(t, db, id)
	}

	err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertReaffirmation(ctx, tx, store.Reaffirmation{
			GrantID: "g-due", TransferID: "tr-1", DueAt: now.Add(-time.Hour),
		}); err != nil {

			return err
		}
		if err := store.InsertReaffirmation(ctx, tx, store.Reaffirmation{
			GrantID: "g-later", TransferID: "tr-1", DueAt: now.Add(24 * time.Hour),
		}); err != nil {

			return err
		}
		return store.InsertReaffirmation(ctx, tx, store.Reaffirmation{
			GrantID: "g-done", TransferID: "tr-1", DueAt: now.Add(-time.Hour),
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	err = db.Tx(ctx, func(tx bun.Tx) error {

		return store.Affirm(ctx, tx, "g-done", "person:new", now)
	})
	if err != nil {

		t.Fatalf("affirm: %v", err)
	}

	lapsed, err := store.LapsedGrantIDs(ctx, db.Reader(), now)
	if err != nil {

		t.Fatal(err)
	}
	if !lapsed["g-due"] || lapsed["g-later"] || lapsed["g-done"] {

		t.Fatalf("lapsed = %v, want only g-due", lapsed)
	}
}

func TestAffirmRefusesTwice(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	seedGrantRow(t, db, "g-1")
	now := time.Now().UTC()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertReaffirmation(ctx, tx, store.Reaffirmation{
			GrantID: "g-1", TransferID: "tr-1", DueAt: now.Add(time.Hour),
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.Affirm(ctx, tx, "g-1", "person:new", now)
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.Affirm(ctx, tx, "g-1", "person:new", now)
	}); err == nil {

		t.Fatal("re-affirming an already-affirmed grant succeeded")
	}
}

func TestNotificationsAreScopedByAudience(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: "t-demo", Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassOpened, Body: "someone opened your data",
		}); err != nil {

			return err
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: "t-demo", Audience: store.AudienceOperator,
			Kind: store.NotifyBreakglassOpened, Body: "review within 24h",
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	// The tenant's feed must never carry the operator-side copy: the two say
	// different things to different people about the same event.
	tenant, err := store.ListNotifications(ctx, db.Reader(), store.NotificationFilter{
		TenantID: "t-demo", Audience: store.AudienceTenant,
	})
	if err != nil {

		t.Fatal(err)
	}
	if len(tenant) != 1 || tenant[0].Body != "someone opened your data" {

		t.Fatalf("tenant feed = %+v", tenant)
	}
}

// Mismatches is the fleet's §15 row. Latest-per-tenant, not every mismatch
// ever: a tenant whose rule was repaired on the next tick should leave the
// list, while one whose extra rule is still there must not scroll away behind
// its own history.
func TestMismatchesReturnsTheLatestPerTenantSecurityFirst(t *testing.T) {

	ctx := context.Background()
	db := newDB(t)
	base := time.Now().UTC().Add(-time.Hour)

	write := func(id, tenant, outcome string, at time.Time) {

		t.Helper()
		err := db.Tx(ctx, func(tx bun.Tx) error {

			return store.InsertAttestation(ctx, tx, store.Attestation{
				ID: id, TenantID: tenant, GeneratedAt: at, Outcome: outcome,
				ObservedJSON: "{}", Signature: "sig",
			})
		})
		if err != nil {

			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// t-demo: was broken, then repaired. Must NOT appear.
	write("at-1", "t-demo", store.OutcomeEnforcementWithoutGrant, base)
	write("at-2", "t-demo", store.OutcomeMatch, base.Add(time.Minute))

	// A second tenant, still broken, with an older clean report behind it.
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertTenant(ctx, tx, tenant("t-other"))
	})
	if err != nil {

		t.Fatal(err)
	}
	write("at-3", "t-other", store.OutcomeMatch, base)
	write("at-4", "t-other", store.OutcomeEnforcementWithoutGrant, base.Add(time.Minute))

	got, err := store.Mismatches(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "at-4" {

		t.Fatalf("mismatches = %+v, want only at-4", got)
	}
}
