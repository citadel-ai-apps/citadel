package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

func job(t *testing.T, db *store.DB, tenantID string, mutate func(*store.UpgradeJob)) store.UpgradeJob {

	t.Helper()
	j := store.UpgradeJob{
		ID: store.NewID("uj"), TenantID: tenantID,
		FromVersion: "0.38.2", ToVersion: "0.40.4", State: store.UpgradePending,
	}
	if mutate != nil {

		mutate(&j)
	}
	ctx := context.Background()
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertUpgradeJob(ctx, tx, j) }); err != nil {

		t.Fatal(err)
	}
	return j
}

// The row is the durable half of INV-6, so "is one in flight?" has to be exact
// at both ends of the state list.
func TestActiveUpgradeSeesEveryNonTerminalState(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()

	if _, err := store.ActiveUpgrade(ctx, db.Reader(), tn.ID); !errors.Is(err, store.ErrNoActiveUpgrade) {

		t.Fatalf("a tenant with no job reported one: %v", err)
	}
	j := job(t, db, tn.ID, nil)

	for _, state := range []string{
		store.UpgradePending, store.UpgradeRehearsing, store.UpgradeSnapshotting,
		store.UpgradeApplying, store.UpgradeVerifying, store.UpgradeRollingBack,
	} {

		if err := db.Tx(ctx, func(tx bun.Tx) error {

			return store.SetUpgradeState(ctx, tx, j.ID, state)
		}); err != nil {

			t.Fatal(err)
		}
		if _, err := store.ActiveUpgrade(ctx, db.Reader(), tn.ID); err != nil {

			t.Fatalf("state %q did not read as in flight: %v", state, err)
		}
	}
	for _, state := range store.UpgradeTerminal {

		if err := db.Tx(ctx, func(tx bun.Tx) error {

			return store.SetUpgradeState(ctx, tx, j.ID, state)
		}); err != nil {

			t.Fatal(err)
		}
		if _, err := store.ActiveUpgrade(ctx, db.Reader(), tn.ID); !errors.Is(err, store.ErrNoActiveUpgrade) {

			t.Fatalf("terminal state %q still read as in flight", state)
		}
	}
}

func TestTerminalStateStampsFinishedAt(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	j := job(t, db, tn.ID, nil)

	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetUpgradeState(ctx, tx, j.ID, store.UpgradeApplying)
	}); err != nil {

		t.Fatal(err)
	}
	got, err := store.GetUpgradeJob(ctx, db.Reader(), j.ID)
	if err != nil {

		t.Fatal(err)
	}
	if got.FinishedAt != nil {

		t.Fatal("a non-terminal state stamped finished_at")
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetUpgradeState(ctx, tx, j.ID, store.UpgradeFailed)
	}); err != nil {

		t.Fatal(err)
	}
	got, _ = store.GetUpgradeJob(ctx, db.Reader(), j.ID)
	if got.FinishedAt == nil {

		t.Fatal("a terminal state did not stamp finished_at")
	}
}

// INV-4: a snapshot an in-flight job names is the only way back from a one-way
// migration, so retention must never be able to take it.
func TestBackupsReferencedByJobsOnlyCountsLiveOnes(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()

	b := store.Backup{ID: store.NewID("bk"), TenantID: tn.ID, Kind: store.BackupPreUpgrade,
		Path: "/tmp/x.img.zst", PBVersion: "0.38.2"}
	if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertBackup(ctx, tx, b) }); err != nil {

		t.Fatal(err)
	}
	j := job(t, db, tn.ID, func(j *store.UpgradeJob) { j.SnapshotID = b.ID; j.State = store.UpgradeApplying })

	refs, err := store.BackupsReferencedByJobs(ctx, db.Reader())
	if err != nil {

		t.Fatal(err)
	}
	if !refs[b.ID] {

		t.Fatal("a snapshot an applying job depends on was not protected")
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetUpgradeState(ctx, tx, j.ID, store.UpgradeSucceeded)
	}); err != nil {

		t.Fatal(err)
	}
	refs, _ = store.BackupsReferencedByJobs(ctx, db.Reader())
	if refs[b.ID] {

		t.Fatal("a finished job still held its snapshot back from retention")
	}
}

func TestExpiredBackupsIgnoresRowsWithNoRetention(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	rows := []store.Backup{
		{ID: "bk-past", TenantID: tn.ID, Kind: store.BackupRoutine, Path: "a", PBVersion: "0.40.4", RetainUntil: &past},
		{ID: "bk-future", TenantID: tn.ID, Kind: store.BackupRoutine, Path: "b", PBVersion: "0.40.4", RetainUntil: &future},
		{ID: "bk-forever", TenantID: tn.ID, Kind: store.BackupManual, Path: "c", PBVersion: "0.40.4"},
	}
	for _, b := range rows {

		if err := db.Tx(ctx, func(tx bun.Tx) error { return store.InsertBackup(ctx, tx, b) }); err != nil {

			t.Fatal(err)
		}
	}
	got, err := store.ExpiredBackups(ctx, db.Reader(), now)
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "bk-past" {

		t.Fatalf("expired set is %v, want only bk-past", got)
	}
}

// §12 publishes the EOL date on entry to `deprecated`. A deprecation with no
// date is a nag nobody can plan around, and the platform has no trigger for the
// forced upgrade that eventually follows.
func TestDeprecatingRequiresAnEOLDate(t *testing.T) {

	db, _ := fixture(t)
	ctx := context.Background()

	err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetVersionState(ctx, tx, "0.40.4", store.VersionDeprecated, nil)
	})
	if !errors.Is(err, store.ErrEOLDateRequired) {

		t.Fatalf("deprecating without a date returned %v, want ErrEOLDateRequired", err)
	}
	when := time.Now().UTC().AddDate(0, 0, 30)
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetVersionState(ctx, tx, "0.40.4", store.VersionDeprecated, &when)
	}); err != nil {

		t.Fatal(err)
	}
	rv, err := store.GetRuntimeVersion(ctx, db.Reader(), "0.40.4")
	if err != nil {

		t.Fatal(err)
	}
	if rv.EOLAt == nil {

		t.Fatal("the EOL date was not stored")
	}
	if rv.Upgradable() {

		t.Fatal("a deprecated version is still offered as an upgrade target")
	}
	// Moving on to eol must not need the date repeated: it is already published.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetVersionState(ctx, tx, "0.40.4", store.VersionEOL, nil)
	}); err != nil {

		t.Fatalf("moving a dated version to eol: %v", err)
	}
}

// INV-11's drift alert compares the running digest against tenant.image_digest.
// A row whose version and digest disagree is a state that check cannot read, so
// the two always move together.
func TestSetRuntimeVersionMovesBothColumns(t *testing.T) {

	db, tn := fixture(t)
	ctx := context.Background()
	const newDigest = "127.0.0.1:5000/pb-hardened@sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"

	// tenant.runtime_version is a foreign key into the registry, so the target
	// has to be registered before a tenant can be moved onto it — which is the
	// schema saying the same thing the upgrade gate says.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.41.0", HardeningRev: 1, ImageDigest: newDigest, State: store.VersionCurrent,
		})
	}); err != nil {

		t.Fatal(err)
	}
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetRuntimeVersion(ctx, tx, tn.ID, "0.41.0", newDigest)
	}); err != nil {

		t.Fatal(err)
	}
	got, err := store.GetTenant(ctx, db.Reader(), tn.ID)
	if err != nil {

		t.Fatal(err)
	}
	if got.RuntimeVersion != "0.41.0" || got.ImageDigest != newDigest {

		t.Fatalf("row is %s/%s, want 0.41.0/%s", got.RuntimeVersion, got.ImageDigest, newDigest)
	}
	// A tag would let somebody retag the image out from under a pinned tenant.
	if err := db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetRuntimeVersion(ctx, tx, tn.ID, "0.41.0", "pb-hardened:latest")
	}); err == nil {

		t.Fatal("a tag reference was accepted as an image digest")
	}
}
