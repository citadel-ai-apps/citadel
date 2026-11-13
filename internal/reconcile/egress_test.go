package reconcile

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// A quarantined tenant keeps its grants on paper but loses its outbound path:
// quarantine is the instant stop, and a tenant under investigation must not
// keep talking to the hosts it was granted.
func TestQuarantineTakesGrantsOutOfEnforcement(t *testing.T) {

	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	tenant := store.Tenant{
		ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
		DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: "x@sha256:00",
		NetworkName: "t-demo", Subnet: "10.213.1.0/29",
		GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
		CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB", EncKeyRef: "demo.key", CreatedAt: now,
	}
	err = db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: "x@sha256:00", State: store.VersionCurrent,
		}); err != nil {

			return err
		}
		if err := store.InsertTenant(ctx, tx, tenant); err != nil {

			return err
		}
		decided := now
		return store.InsertGrant(ctx, tx, store.Grant{
			ID: "g-1", TenantID: "demo", Kind: store.GrantEgressHost, Direction: "outbound",
			Subject: "api.example.com", Tier: 1, Decision: store.DecisionApproved,
			RequestedBy: "platform", DecidedBy: "platform", DecidedAt: &decided,
			ExpiresAt: now.Add(time.Hour),
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	r := &Reconciler{db: db}
	got, err := r.egressGrants(ctx, tenant, now)
	if err != nil || len(got) != 1 {

		t.Fatalf("active grant not enforced: %v, %v", got, err)
	}
	tenant.Quarantined = true
	got, err = r.egressGrants(ctx, tenant, now)
	if err != nil || len(got) != 0 {

		t.Fatalf("a quarantined tenant still has %d enforced grants (%v)", len(got), err)
	}
}

// A caller holding a row read before the tenant's egress address was assigned
// must get that address back, not a second one: the tenant's rules and its
// container are built on the first (found by the egress acceptance suite).
func TestEnsureEgressIPIgnoresAStaleRow(t *testing.T) {

	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tenant := store.Tenant{
		ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
		DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: "x@sha256:00",
		NetworkName: "t-demo", Subnet: "10.213.1.0/29",
		GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
		CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB", EncKeyRef: "demo.key", CreatedAt: time.Now().UTC(),
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: "x@sha256:00", State: store.VersionCurrent,
		}); err != nil {

			return err
		}
		return store.InsertTenant(ctx, tx, tenant)
	}); err != nil {

		t.Fatal(err)
	}
	cfg := config.Default()
	r := &Reconciler{db: db, cfg: cfg, audit: auditlog.New()}
	first, err := r.ensureEgressIP(ctx, tenant)
	if err != nil {

		t.Fatal(err)
	}
	// tenant is now stale: its EgressIP is still empty.
	second, err := r.ensureEgressIP(ctx, tenant)
	if err != nil {

		t.Fatal(err)
	}
	if first != second {

		t.Fatalf("a stale row was handed a second egress address: %s, then %s", first, second)
	}
}
