package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

const digest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

func open(t *testing.T, path string) *store.DB {

	t.Helper()
	db, err := store.Open(context.Background(), path)
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrationsAreIdempotentAcrossReopens(t *testing.T) {

	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()

	db := open(t, path)
	if n := appliedMigrations(t, db); n != migrationCount {

		t.Fatalf("bun_migrations holds %d rows after the first open, want %d", n, migrationCount)
	}
	seedVersion(t, db)
	_ = db.Close()

	// Reopening must not re-run 001, which would fail on the duplicate platform
	// principal insert.
	again, err := store.Open(ctx, path)
	if err != nil {

		t.Fatalf("reopening an already-migrated database: %v", err)
	}
	defer again.Close()
	if n := appliedMigrations(t, again); n != migrationCount {

		t.Fatalf("bun_migrations holds %d rows after reopening, want %d", n, migrationCount)
	}
}

// migrationCount is the number of files in internal/store/migrations. It is
// asserted rather than derived so adding a migration is a deliberate edit here
// too: a migration that silently re-runs would fail on 001's platform-principal
// insert, and this test is what catches that.
const migrationCount = 8

func appliedMigrations(t *testing.T, db *store.DB) int {

	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(context.Background(),
		"SELECT count(*) FROM bun_migrations WHERE migrated_at IS NOT NULL").Scan(&n); err != nil {

		t.Fatal(err)
	}
	return n
}

// TestTimestampsAreStoredAsRFC3339Text pins the on-disk shape of every
// TIMESTAMP column. The acceptance suite reads state.db with the sqlite3 CLI
// and internal/auditlog parses occurred_at itself, so bun's default
// "2006-01-02 15:04:05.999999-07:00" would be a silent break.
func TestTimestampsAreStoredAsRFC3339Text(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()

	health := time.Date(2026, 9, 18, 14, 5, 6, 0, time.UTC)
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertTenant(ctx, tx, tenant("demo")); err != nil {

			return err
		}
		return store.UpdateInstance(ctx, tx, "demo", store.InstanceUpdate{
			LastHealthAt: new(health),
		})
	}); err != nil {

		t.Fatal(err)
	}

	var typ, raw string
	if err := db.Reader().QueryRowContext(ctx,
		"SELECT typeof(created_at), created_at FROM tenant WHERE id = 'demo'").Scan(&typ, &raw); err != nil {

		t.Fatal(err)
	}
	if typ != "text" {

		t.Fatalf("tenant.created_at is stored as %q, want text", typ)
	}
	if _, err := time.Parse(time.RFC3339, raw); err != nil {

		t.Fatalf("tenant.created_at = %q, which is not RFC3339: %v", raw, err)
	}

	// And the round trip preserves the instant, not just the format.
	in, err := store.GetInstance(ctx, db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if in.LastHealthAt == nil || !in.LastHealthAt.Equal(health) {

		t.Fatalf("last_health_at round-tripped as %v, want %v", in.LastHealthAt, health)
	}
}

func TestWALModeIsOn(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	var mode string
	if err := db.Reader().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {

		t.Fatal(err)
	}
	if mode != "wal" {

		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

func seedVersion(t *testing.T, db *store.DB) {

	t.Helper()
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: digest, State: store.VersionCurrent,
		})
	}); err != nil {

		t.Fatal(err)
	}
}

func tenant(id string) store.Tenant {

	return store.Tenant{
		ID: id, Slug: id, Hostname: id + ".apps.localhost",
		DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: digest,
		NetworkName: "t-" + id, Subnet: "10.213.1.0/29",
		GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
		CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB", EncKeyRef: id + ".key",
	}
}

func TestInsertTenantCreatesItsInstanceRow(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertTenant(ctx, tx, tenant("demo"))
	}); err != nil {

		t.Fatal(err)
	}
	in, err := store.GetInstance(ctx, db.Reader(), "demo")
	if err != nil {

		t.Fatalf("no instance row after insert: %v", err)
	}
	if in.ObservedState != store.ObservedStopped {

		t.Fatalf("observed state = %q, want stopped", in.ObservedState)
	}
}

func TestTenantLookupBySlugAndID(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertTenant(ctx, tx, tenant("demo"))
	}); err != nil {

		t.Fatal(err)
	}
	if _, err := store.GetTenant(ctx, db.Reader(), "demo"); err != nil {

		t.Fatal(err)
	}
	if _, err := store.GetTenantBySlug(ctx, db.Reader(), "demo"); err != nil {

		t.Fatal(err)
	}
	if _, err := store.GetTenant(ctx, db.Reader(), "nope"); !errors.Is(err, store.ErrTenantNotFound) {

		t.Fatalf("got %v, want ErrTenantNotFound", err)
	}
}

// TestDeleteTenantRetainsAuditRows asserts the audit log outlives its tenant:
// audit_event.tenant_id has no foreign key and no cascade, because the record
// of who authorised access must survive the data it describes.
func TestDeleteTenantRetainsAuditRows(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertTenant(ctx, tx, tenant("demo")); err != nil {

			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO audit_event (seq, id, occurred_at, actor_id, actor_kind, tenant_id,
			                         action, prev_hash, hash)
			VALUES (1,'ae-1','2026-09-18T00:00:00Z','platform','platform','demo',
			        'tenant.provisioned','0','1')`)
		return err
	}); err != nil {

		t.Fatal(err)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.DeleteTenant(ctx, tx, "demo")
	}); err != nil {

		t.Fatalf("deleting the tenant: %v", err)
	}

	var n int
	if err := db.Reader().QueryRowContext(ctx,
		`SELECT count(*) FROM audit_event WHERE tenant_id = 'demo'`).Scan(&n); err != nil {

		t.Fatal(err)
	}
	if n != 1 {

		t.Fatalf("%d audit rows survived the tenant, want 1", n)
	}
}

func TestAllocatedSubnetsIsTheIPAMExclusionSet(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()

	a, b := tenant("a"), tenant("b")
	b.Subnet, b.GatewayIP, b.EdgeIP, b.ContainerIP = "10.213.2.0/29", "10.213.2.1", "10.213.2.2", "10.213.2.3"
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertTenant(ctx, tx, a); err != nil {

			return err
		}
		return store.InsertTenant(ctx, tx, b)
	}); err != nil {

		t.Fatal(err)
	}

	got, err := store.AllocatedSubnets(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 2 {

		t.Fatalf("allocated subnets = %v, want 2", got)
	}
}

func TestUpdateInstanceLeavesUnsetFieldsAlone(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	seedVersion(t, db)
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertTenant(ctx, tx, tenant("demo"))
	}); err != nil {

		t.Fatal(err)
	}

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, "demo", store.InstanceUpdate{
			RestartCount: new(3),
			LastError:    new("boom"),
		})
	}); err != nil {

		t.Fatal(err)
	}
	// A partial write must not clobber what it did not look at, so the
	// reconciler can record what it learned without inventing the rest.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpdateInstance(ctx, tx, "demo", store.InstanceUpdate{
			ObservedState: new(store.ObservedHealthy),
		})
	}); err != nil {

		t.Fatal(err)
	}
	in, err := store.GetInstance(ctx, db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if in.RestartCount != 3 || in.LastError != "boom" {

		t.Fatalf("a partial update clobbered other fields: %+v", in)
	}
	if in.ObservedState != store.ObservedHealthy {

		t.Fatalf("observed state = %q", in.ObservedState)
	}
}

// TestUpsertRuntimeVersionRejectsATag asserts the rule that only digests are
// ever scheduled, never tags.
func TestUpsertRuntimeVersionRejectsATag(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1,
			ImageDigest: "127.0.0.1:5000/pb-hardened:0.40.4-h1",
		})
	})
	if err == nil {

		t.Fatal("a tag reference was registered as a runtime version")
	}
}

// TestUpsertRuntimeVersionUpdatesInPlace exercises the ON CONFLICT branch,
// which controlplaned takes on every start when it re-registers digests.txt.
func TestUpsertRuntimeVersionUpdatesInPlace(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	seedVersion(t, db)

	rebuilt := strings.Replace(digest, "c84a", "d95b", 1)
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 2, ImageDigest: rebuilt,
			State: store.VersionDeprecated,
		})
	}); err != nil {

		t.Fatal(err)
	}

	got, err := store.GetRuntimeVersion(ctx, db.Reader(), "0.40.4")
	if err != nil {

		t.Fatal(err)
	}
	if got.ImageDigest != rebuilt || got.HardeningRev != 2 || got.State != store.VersionDeprecated {

		t.Fatalf("upsert left %+v", got)
	}

	versions, err := store.ListRuntimeVersions(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if len(versions) != 1 {

		t.Fatalf("upsert inserted a second row: %+v", versions)
	}
}

// TestUpsertRuntimeVersionKeepsLifecycleState is the start-up re-seed: it
// passes no state, and must not move a deprecated version back to supported.
func TestUpsertRuntimeVersionKeepsLifecycleState(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	seedVersion(t, db)
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: digest, State: store.VersionEOL,
		})
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: digest,
		})
	}); err != nil {

		t.Fatal(err)
	}
	got, err := store.GetRuntimeVersion(ctx, db.Reader(), "0.40.4")
	if err != nil {

		t.Fatal(err)
	}
	if got.State != store.VersionEOL {

		t.Fatalf("a re-seed with no state moved the version to %q", got.State)
	}
}

// TestUpsertRuntimeVersionRefusesAnOlderRev: a tenant whose digest differs
// from the row's is offered the row's image as an upgrade, so the row must
// never move to an older hardening rev.
func TestUpsertRuntimeVersionRefusesAnOlderRev(t *testing.T) {

	db := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	seedVersion(t, db)
	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 0, ImageDigest: digest,
		})
	})
	if !errors.Is(err, store.ErrHardeningRegress) {

		t.Fatalf("an older hardening rev returned %v, want ErrHardeningRegress", err)
	}
}

func TestParseDigestsFileAndSelect(t *testing.T) {

	path := filepath.Join(t.TempDir(), "digests.txt")
	body := `# comment, ignored

0.22.55 h1 arm64 127.0.0.1:5000/pb-hardened@sha256:5b6a
0.40.4 h1 arm64 127.0.0.1:5000/pb-hardened@sha256:old
0.40.4 h1 arm64 127.0.0.1:5000/pb-hardened@sha256:new
0.40.4 h1 amd64 127.0.0.1:5000/pb-hardened@sha256:amd
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {

		t.Fatal(err)
	}
	entries, err := store.ParseDigestsFile(path)
	if err != nil {

		t.Fatal(err)
	}
	if len(entries) != 4 {

		t.Fatalf("parsed %d entries, want 4", len(entries))
	}

	// A rebuilt image appends a new line; the last match wins, matching the
	// `grep … | tail -1` semantics.
	ref, err := store.SelectDigest(entries, "0.40.4", 1, "arm64")
	if err != nil {

		t.Fatal(err)
	}
	if ref != "127.0.0.1:5000/pb-hardened@sha256:new" {

		t.Fatalf("selected %s, want the last matching entry", ref)
	}

	if _, err := store.SelectDigest(entries, "0.40.4", 2, "arm64"); err == nil {

		t.Fatal("a missing hardening rev was resolved")
	}
	if _, err := store.SelectDigest(entries, "0.99.0", 1, "arm64"); err == nil {

		t.Fatal("an unbuilt version was resolved")
	}
}

func TestParseDigestsFileRejectsATagLine(t *testing.T) {

	path := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(path, []byte("0.40.4 h1 arm64 127.0.0.1:5000/pb-hardened:0.40.4-h1\n"), 0o644); err != nil {

		t.Fatal(err)
	}
	if _, err := store.ParseDigestsFile(path); err == nil {

		t.Fatal("a tag line was accepted from digests.txt")
	}
}

func TestParseDigestsFileReportsTheOffendingLine(t *testing.T) {

	path := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(path, []byte("0.40.4 h1 arm64\n"), 0o644); err != nil {

		t.Fatal(err)
	}
	_, err := store.ParseDigestsFile(path)
	if err == nil {

		t.Fatal("a malformed line was accepted")
	}
	if !strings.Contains(err.Error(), ":1:") {

		t.Fatalf("error %q does not name the line number", err)
	}
}
