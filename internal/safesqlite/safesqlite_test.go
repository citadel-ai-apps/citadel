package safesqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func makeDB(t *testing.T, path string, stmts ...string) {

	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {

		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {

		if _, err := db.Exec(q); err != nil {

			t.Fatal(err)
		}
	}
}

func TestReadsThroughTheHandle(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	makeDB(t, path, `CREATE TABLE t (v TEXT)`, `INSERT INTO t VALUES ('first')`)

	f, err := os.Open(path)
	if err != nil {

		t.Fatal(err)
	}
	defer f.Close()

	// Re-point the path at a different database after the open. A by-path
	// open would now read "second"; the handle still names the first file.
	other := filepath.Join(dir, "other.db")
	makeDB(t, other, `CREATE TABLE t (v TEXT)`, `INSERT INTO t VALUES ('second')`)
	if err := os.Rename(path, filepath.Join(dir, "moved.db")); err != nil {

		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {

		t.Fatal(err)
	}

	db, err := Open(f, "")
	if err != nil {

		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {

		t.Fatal(err)
	}
	if v != "first" {

		t.Fatalf("read %q through the handle, want the file that was opened", v)
	}
}

// Read-only and nothing beside the main file: no journal, no -wal, no -shm.
func TestCannotWriteOrCreateSidecars(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "data.db")
	makeDB(t, path, `PRAGMA journal_mode=WAL`, `CREATE TABLE t (v TEXT)`)
	for _, s := range []string{"-wal", "-shm"} {

		_ = os.Remove(path + s)
	}
	f, err := os.Open(path)
	if err != nil {

		t.Fatal(err)
	}
	defer f.Close()
	db, err := Open(f, "")
	if err != nil {

		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO t VALUES ('x')`); err == nil {

		t.Fatal("write succeeded on an untrusted database")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {

		t.Fatal(err)
	}
	for _, s := range []string{"-wal", "-shm", "-journal"} {

		if _, err := os.Lstat(path + s); err == nil {

			t.Errorf("%s was created next to the untrusted database", s)
		}
	}
}
