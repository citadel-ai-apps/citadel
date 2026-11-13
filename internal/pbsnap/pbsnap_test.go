package pbsnap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveDB builds a WAL database with an open writer whose last rows are still
// only in the WAL, the shape a running PocketBase leaves on disk.
func liveDB(t *testing.T, path string, rows int) *sql.DB {

	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)`); err != nil {

		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {

		t.Fatal(err)
	}
	for range rows {

		if _, err := db.Exec(`INSERT INTO users (email) VALUES (?)`, strings.Repeat("x", 200)); err != nil {

			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {

		t.Fatalf("test setup: no WAL content (%v)", err)
	}
	return db
}

func TestRoundTripIncludesUncheckpointedWAL(t *testing.T) {

	dir := t.TempDir()
	src := filepath.Join(dir, "data.db")
	liveDB(t, src, 500)

	var buf bytes.Buffer
	if err := Write(context.Background(), src, &buf); err != nil {

		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := Read(&buf, dst, 1<<30); err != nil {

		t.Fatal(err)
	}
	cp, err := sql.Open("sqlite", "file:"+dst+"?mode=ro")
	if err != nil {

		t.Fatal(err)
	}
	defer cp.Close()
	var check string
	if err := cp.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {

		t.Fatalf("integrity_check = %q, %v", check, err)
	}
	var n int
	if err := cp.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil || n != 500 {

		t.Fatalf("copy has %d rows (%v), want 500: the WAL frames were not included", n, err)
	}
	if _, err := os.Stat(src + "-wal"); err != nil {

		t.Fatalf("the source lost its -wal: %v", err)
	}
}

func TestReadRefusesHostileStreams(t *testing.T) {

	dir := t.TempDir()
	src := filepath.Join(dir, "data.db")
	liveDB(t, src, 10)
	var good bytes.Buffer
	if err := Write(context.Background(), src, &good); err != nil {

		t.Fatal(err)
	}
	header := func(size, count uint32) []byte {

		b := append([]byte("PBSNAP01"), make([]byte, 8)...)
		binary.BigEndian.PutUint32(b[8:], size)
		binary.BigEndian.PutUint32(b[12:], count)
		return b
	}
	cases := map[string]struct {
		stream []byte
		limit  int64
		want   string
	}{
		"bad magic":     {append([]byte("NOTSNAP!"), good.Bytes()[8:]...), 1 << 30, "not a pbsnap stream"},
		"odd page size": {header(1000, 1), 1 << 30, "power of two"},
		"zero pages":    {header(4096, 0), 1 << 30, "page count"},
		"over limit":    {good.Bytes(), int64(good.Len()) - 100, "over the"},
		"truncated":     {good.Bytes()[:good.Len()-10], 1 << 30, "stream ended"},
		"trailing":      {append(append([]byte{}, good.Bytes()...), 'x'), 1 << 30, "trailing data"},
	}
	for name, c := range cases {

		t.Run(name, func(t *testing.T) {

			dst := filepath.Join(t.TempDir(), "copy.db")
			err := Read(bytes.NewReader(c.stream), dst, c.limit)
			if err == nil || !strings.Contains(err.Error(), c.want) {

				t.Fatalf("Read = %v, want an error containing %q", err, c.want)
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {

				t.Fatalf("a refused stream left %s behind", dst)
			}
		})
	}
}

func TestWriteRefusesSymlink(t *testing.T) {

	dir := t.TempDir()
	src := filepath.Join(dir, "real.db")
	liveDB(t, src, 1)
	link := filepath.Join(dir, "data.db")
	if err := os.Symlink(src, link); err != nil {

		t.Fatal(err)
	}
	if err := Write(context.Background(), link, &bytes.Buffer{}); err == nil {

		t.Fatal("Write followed a symlink")
	}
}
