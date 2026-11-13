package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

// A hardening-rev bump within one PocketBase version is an image change, so it
// goes through the upgrade ladder (INV-11) rather than being refused as "the
// same version"; the exact image a tenant already runs is still refused, and
// so is going back a PocketBase version (INV-4).
func TestUpgradeGatesHardeningRevBump(t *testing.T) {

	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tenant := store.Tenant{
		ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
		DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: "x@sha256:h1",
		NetworkName: "t-demo", Subnet: "10.213.1.0/29",
		GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
		CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB", EncKeyRef: "demo.key", CreatedAt: time.Now().UTC(),
	}
	upsert := func(v string, rev int, digest, state string) {

		t.Helper()
		if err := db.Tx(ctx, func(tx bun.Tx) error {

			return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
				Version: v, HardeningRev: rev, ImageDigest: digest, State: state,
			})
		}); err != nil {

			t.Fatal(err)
		}
	}
	upsert("0.40.4", 1, "x@sha256:h1", store.VersionCurrent)
	upsert("0.38.2", 1, "x@sha256:old", store.VersionSupported)
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertTenant(ctx, tx, tenant) }); err != nil {

		t.Fatal(err)
	}
	r := &Reconciler{db: db}

	if _, _, _, err := r.upgradeGates(ctx, tenant, UpgradeRequest{To: "0.40.4"}); !errors.Is(err, ErrSameVersion) {

		t.Fatalf("the image already running returned %v, want ErrSameVersion", err)
	}
	if _, _, _, err := r.upgradeGates(ctx, tenant, UpgradeRequest{To: "0.38.2"}); !errors.Is(err, ErrDowngrade) {

		t.Fatalf("an older version returned %v, want ErrDowngrade", err)
	}

	// h2 of the same version, on a line that is already deprecated: a patch a
	// deprecated line still takes.
	upsert("0.40.4", 2, "x@sha256:h2", store.VersionDeprecated)
	target, _, blocked, err := r.upgradeGates(ctx, tenant, UpgradeRequest{To: "0.40.4"})
	if err != nil || blocked != "" {

		t.Fatalf("a hardening-rev bump was refused: err=%v blocked=%q", err, blocked)
	}
	if target.ImageDigest != "x@sha256:h2" {

		t.Fatalf("target digest %s, want the h2 image", target.ImageDigest)
	}
}
