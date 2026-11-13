package pbauth

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"
)

// fileState is what "nothing was touched" means for one directory entry.
type fileState struct {
	ino   uint64
	size  int64
	mtime time.Time
}

func dirState(t *testing.T, dir string) map[string]fileState {

	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {

		t.Fatal(err)
	}
	out := make(map[string]fileState, len(entries))
	for _, e := range entries {

		fi, err := os.Lstat(filepath.Join(dir, e.Name()))
		if err != nil {

			t.Fatal(err)
		}
		st, _ := fi.Sys().(*syscall.Stat_t)
		var ino uint64
		if st != nil {

			ino = uint64(st.Ino)
		}
		out[e.Name()] = fileState{ino: ino, size: fi.Size(), mtime: fi.ModTime()}
	}
	return out
}

func names(m map[string]fileState) []string {

	var out []string
	for k := range m {

		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestReadLeavesALiveWALDatabaseAlone is the gVisor regression (design.md
// INV-20). Under runsc the host cannot see PocketBase's fcntl locks, so a
// host-side connection that thinks it is alone checkpoints and unlinks -wal
// and -shm on close, underneath the live instance. No lock test can model a
// sandbox boundary inside one process, so this asserts the stronger property
// immutable=1 gives: the read creates, removes and modifies nothing.
func TestReadLeavesALiveWALDatabaseAlone(t *testing.T) {

	dir := t.TempDir()
	modernDB(t, dir)

	// A "live instance": WAL mode, no auto-checkpoint, an open writer with
	// frames still in the WAL.
	live, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "data.db")+
		"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {

		t.Fatal(err)
	}
	defer live.Close()
	live.SetMaxOpenConns(1)
	if _, err := live.Exec(`INSERT INTO _superusers VALUES ('late', 'late@example.com', 'k', '2026-03-01')`); err != nil {

		t.Fatal(err)
	}
	before := dirState(t, dir)
	if _, ok := before["data.db-wal"]; !ok {

		t.Fatalf("test setup: no -wal beside data.db (%v)", names(before))
	}

	// Past one-second mtime granularity, so a write would show.
	time.Sleep(1100 * time.Millisecond)
	ok, err := Exists(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"}, BySeatEmail(SeatEmail("t1")))
	if err != nil || !ok {

		t.Fatalf("Exists = %v, %v", ok, err)
	}
	if _, err := Mint(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"}, AnySuperuser(), 0); err != nil {

		t.Fatal(err)
	}

	after := dirState(t, dir)
	if len(after) != len(before) {

		t.Fatalf("directory changed: before %v, after %v", names(before), names(after))
	}
	for name, b := range before {

		a, ok := after[name]
		if !ok {

			t.Fatalf("%s was removed by a read", name)
		}
		if a != b {

			t.Errorf("%s was modified by a read: before %+v, after %+v", name, b, a)
		}
	}
}

// TestReadNeedsNoWriteAccess pins the other half of immutable=1: a WAL
// database with no sidecars is readable from a directory the reader cannot
// write. A normal WAL connection has to create -shm and fails here.
func TestReadNeedsNoWriteAccess(t *testing.T) {

	if os.Geteuid() == 0 {

		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	modernDB(t, dir)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "data.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {

		t.Fatal(err)
	}
	if _, err := db.Exec(`SELECT 1`); err != nil {

		t.Fatal(err)
	}
	db.Close()
	if _, err := os.Stat(filepath.Join(dir, "data.db-wal")); !os.IsNotExist(err) {

		t.Fatalf("test setup: -wal still present after the last close (%v)", err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	ok, err := Exists(context.Background(), Source{DataDir: dir, PBVersion: "0.40.4"}, BySeatEmail(SeatEmail("t1")))
	if err != nil || !ok {

		t.Fatalf("Exists on a read-only directory = %v, %v", ok, err)
	}
}
