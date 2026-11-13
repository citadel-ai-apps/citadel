package backup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// busyDB creates a WAL database with an open write in flight, which is the
// state §11 cares about: `cp` of this is a corrupt backup, VACUUM INTO of it is
// not.
func busyDB(t *testing.T, path string) *sql.DB {

	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`); err != nil {

		t.Fatal(err)
	}
	for i := range 200 {

		if _, err := db.Exec(`INSERT INTO notes (body) VALUES (?)`, i); err != nil {

			t.Fatal(err)
		}
	}
	return db
}

func TestVacuumIntoCopiesALiveWALDatabase(t *testing.T) {

	dir := t.TempDir()
	src := filepath.Join(dir, "data.db")
	db := busyDB(t, src)
	ctx := context.Background()

	// The WAL and shm files exist and are NOT part of the copy: carrying them
	// next to a vacuumed database would hand PocketBase a journal that does not
	// match it, which is a corrupt restore that looks fine until the first
	// write.
	if _, err := os.Stat(src + "-wal"); err != nil {

		t.Skipf("no -wal sidecar on this platform: %v", err)
	}
	dst := filepath.Join(dir, "copy.db")
	if err := vacuumInto(ctx, src, dst); err != nil {

		t.Fatalf("vacuum into: %v", err)
	}
	// The source keeps being written while the copy exists, which is the whole
	// point: the tenant is still serving.
	if _, err := db.Exec(`INSERT INTO notes (body) VALUES ('after the copy')`); err != nil {

		t.Fatal(err)
	}

	out, err := sql.Open("sqlite", "file:"+dst+"?mode=ro")
	if err != nil {

		t.Fatal(err)
	}
	defer out.Close()

	var check string
	if err := out.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil {

		t.Fatal(err)
	}
	if check != "ok" {

		t.Fatalf("integrity_check on the copy is %q, want ok", check)
	}
	var n int
	if err := out.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&n); err != nil {

		t.Fatal(err)
	}
	if n != 200 {

		t.Fatalf("copy holds %d rows, want the 200 committed before it", n)
	}
	if _, err := os.Stat(dst + "-wal"); err == nil {

		t.Fatal("the copy has its own -wal; it was not a clean serialisation")
	}
}

func TestVacuumIntoRefusesToOverwrite(t *testing.T) {

	dir := t.TempDir()
	src := filepath.Join(dir, "data.db")
	busyDB(t, src)
	dst := filepath.Join(dir, "copy.db")
	if err := os.WriteFile(dst, []byte("existing"), 0o600); err != nil {

		t.Fatal(err)
	}
	if err := vacuumInto(context.Background(), src, dst); err == nil {

		t.Fatal("an existing destination was overwritten")
	}
}

// pb_data holds tenant-uploaded storage. An archiver that follows a symlink out
// of it is walking a path the tenant chose, so the copy refuses rather than
// resolving.
func TestCopyPlainRefusesASymlink(t *testing.T) {

	src, dst := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("fine"), 0o600); err != nil {

		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "escape")); err != nil {

		t.Skipf("cannot create a symlink here: %v", err)
	}
	if err := copyPlain(src, dst, nil, newBudget(1<<30)); err == nil {

		t.Fatal("a symlink in pb_data was copied instead of refused")
	}
	if _, err := os.Stat(filepath.Join(dst, "escape")); err == nil {

		t.Fatal("the symlink was written to the destination")
	}
}

// The set has changed across PocketBase lines (logs.db on older ones,
// auxiliary.db from 0.23), so it is enumerated. A backup that silently misses a
// database is worse than one that fails.
func TestSqliteFilesEnumeratesAndExcludesSidecars(t *testing.T) {

	dir := t.TempDir()
	for _, name := range []string{"data.db", "auxiliary.db", "data.db-wal", "data.db-shm", "storage"} {

		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {

			t.Fatal(err)
		}
	}
	got, err := sqliteFiles(dir)
	if err != nil {

		t.Fatal(err)
	}
	want := map[string]bool{"data.db": true, "auxiliary.db": true}
	if len(got) != len(want) {

		t.Fatalf("found %v, want exactly %v", got, want)
	}
	for _, name := range got {

		if !want[name] {

			t.Fatalf("%q is not a database file", name)
		}
	}
}

// A tenant that leaves data.db-shm as a symlink to a host file, then crashes
// its instance so the backup takes the stopped path. The host must neither
// touch the link's target nor fail the backup over a sidecar it never needed,
// and committed rows in -wal must survive into the copy.
func TestStoppedCopyNeverTouchesPlantedSidecars(t *testing.T) {

	ctx := context.Background()
	src, dst, outside := t.TempDir(), t.TempDir(), t.TempDir()
	sentinel := filepath.Join(outside, "state.db")
	const keep = "host file the tenant must not reach"
	if err := os.WriteFile(sentinel, []byte(keep), 0o600); err != nil {

		t.Fatal(err)
	}

	// A WAL database with committed rows still in -wal: the state a crashed
	// instance leaves behind.
	db := busyDB(t, filepath.Join(src, "data.db"))
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {

		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notes (body) VALUES ('only in the wal')`); err != nil {

		t.Fatal(err)
	}
	walCopy := filepath.Join(outside, "wal")
	copyRaw(t, filepath.Join(src, "data.db-wal"), walCopy)
	_ = db.Close()
	// Closing checkpointed and removed the sidecars; put the crash state back.
	copyRaw(t, walCopy, filepath.Join(src, "data.db-wal"))
	_ = os.Remove(filepath.Join(src, "data.db-shm"))
	if err := os.Symlink(sentinel, filepath.Join(src, "data.db-shm")); err != nil {

		t.Fatal(err)
	}

	if err := stoppedCopy(ctx, src, dst, 1<<30); err != nil {

		t.Fatalf("stopped copy: %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != keep {

		t.Fatalf("host file changed: %q, %v", got, err)
	}
	if fi, err := os.Lstat(filepath.Join(src, "data.db-shm")); err != nil || fi.Mode()&os.ModeSymlink == 0 {

		t.Fatalf("the planted sidecar was touched: %v", err)
	}
	copied, err := sql.Open("sqlite", "file:"+filepath.Join(dst, "data.db")+"?mode=ro")
	if err != nil {

		t.Fatal(err)
	}
	defer copied.Close()
	var n int
	if err := copied.QueryRow(`SELECT count(*) FROM notes WHERE body = 'only in the wal'`).Scan(&n); err != nil {

		t.Fatal(err)
	}
	if n != 1 {

		t.Fatal("the backup lost a transaction committed only to -wal")
	}
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {

		if e.Name() != "data.db" {

			t.Errorf("staging left %s behind", e.Name())
		}
	}
}

// The live path: between WalkDir listing a directory and opening what is in
// it, the tenant replaces the directory with a symlink to the host.
func TestCopyPlainRefusesADirectorySwappedForASymlink(t *testing.T) {

	src, dst, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "audit-signing.key"), []byte("secret"), 0o600); err != nil {

		t.Fatal(err)
	}
	// The swapped state, as copyPlain finds it.
	if err := os.Symlink(outside, filepath.Join(src, "storage")); err != nil {

		t.Fatal(err)
	}
	if err := copyPlain(src, dst, nil, newBudget(1<<30)); err == nil {

		t.Fatal("copied through a symlinked directory")
	}
	if _, err := os.Stat(filepath.Join(dst, "storage", "audit-signing.key")); err == nil {

		t.Fatal("a host file reached the backup")
	}
	// And the open itself, for the window after the listing.
	root, err := os.OpenRoot(src)
	if err != nil {

		t.Fatal(err)
	}
	defer root.Close()
	if err := copyFrom(root, "storage/audit-signing.key", filepath.Join(dst, "k"), newBudget(1<<30)); err == nil {

		t.Fatal("opened a host file through a symlinked parent")
	}
}

// A sparse file: one truncate(2) in a hook, a size the quota never saw. The copy
// must refuse it on its claimed size, before writing a byte to the host.
func TestCopyPlainRefusesAFileLargerThanTheImage(t *testing.T) {

	src, dst := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "storage"), 0o700); err != nil {

		t.Fatal(err)
	}
	big := filepath.Join(src, "storage", "sparse.bin")
	f, err := os.Create(big)
	if err != nil {

		t.Fatal(err)
	}
	// 1 TiB apparent, nothing allocated.
	if err := f.Truncate(1 << 40); err != nil {

		_ = f.Close()
		t.Skipf("cannot create a sparse file here: %v", err)
	}
	_ = f.Close()

	err = copyPlain(src, dst, nil, newBudget(64<<20))
	if !errors.Is(err, ErrOverBudget) {

		t.Fatalf("a 1 TiB sparse file in a 64 MiB image: got %v, want ErrOverBudget", err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "storage", "sparse.bin")); err == nil && fi.Size() > 0 {

		t.Fatalf("%d bytes of it were written to the host before the refusal", fi.Size())
	}
}

// The budget is for everything in pb_data together, not per file: many files
// each under the image add up past it just the same.
func TestCopyPlainChargesEveryFileAgainstOneBudget(t *testing.T) {

	src, dst := t.TempDir(), t.TempDir()
	chunk := make([]byte, 40<<10)
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {

		if err := os.WriteFile(filepath.Join(src, name), chunk, 0o600); err != nil {

			t.Fatal(err)
		}
	}
	if err := copyPlain(src, t.TempDir(), nil, newBudget(120<<10)); err != nil {

		t.Fatalf("three 40 KiB files in a 120 KiB budget: %v", err)
	}
	if err := copyPlain(src, dst, nil, newBudget(100<<10)); !errors.Is(err, ErrOverBudget) {

		t.Fatalf("three 40 KiB files in a 100 KiB budget: got %v, want ErrOverBudget", err)
	}
}

// The stopped path copies the databases and their journals out raw before
// SQLite touches them; a sparse -wal is the same attack through a different
// door, and shares the same budget.
func TestStoppedCopyRefusesASparseJournal(t *testing.T) {

	ctx := context.Background()
	src, dst := t.TempDir(), t.TempDir()
	db := busyDB(t, filepath.Join(src, "data.db"))
	_ = db.Close()
	wal, err := os.Create(filepath.Join(src, "data.db-wal"))
	if err != nil {

		t.Fatal(err)
	}
	if err := wal.Truncate(1 << 40); err != nil {

		_ = wal.Close()
		t.Skipf("cannot create a sparse file here: %v", err)
	}
	_ = wal.Close()

	if err := stoppedCopy(ctx, src, dst, 64<<20); !errors.Is(err, ErrOverBudget) {

		t.Fatalf("a 1 TiB sparse -wal: got %v, want ErrOverBudget", err)
	}
}

func copyRaw(t *testing.T, from, to string) {

	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {

		t.Fatal(err)
	}
}
