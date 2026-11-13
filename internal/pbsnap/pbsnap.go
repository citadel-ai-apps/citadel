// Package pbsnap copies a live SQLite database out of a gVisor sandbox.
//
// The host must never open a live tenant database itself (design.md INV-20):
// gVisor keeps fcntl locks inside the sandbox, so a host-side connection
// believes it is alone, and SQLite run that way checkpoints and unlinks the
// -wal and -shm of a database PocketBase still has open. So the copy is taken
// from INSIDE the sandbox, by cmd/pbsnap run with `docker exec`, where its locks
// and PocketBase's are the same locks.
//
// Write is the in-sandbox half. Under one read transaction it emits every page
// of the database as the transaction sees it (WAL content included) through
// the sqlite_dbpage virtual table, to stdout: no second copy is written to the
// tenant's quota image, which has no room for one.
//
// Read is the host half. The stream comes out of a tenant-controlled sandbox,
// so it is hostile input: bounded, shape-checked, and written to a private file
// nobody else has open, which the caller then integrity-checks and vacuums.
//
// Stream format, all integers big-endian:
//
//	magic     [8]byte  "PBSNAP01"
//	pageSize  uint32
//	pageCount uint32
//	pages     pageCount × pageSize bytes, page 1 first
package pbsnap

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	_ "modernc.org/sqlite" // built with SQLITE_ENABLE_DBPAGE_VTAB
)

var magic = [8]byte{'P', 'B', 'S', 'N', 'A', 'P', '0', '1'}

const (
	minPageSize = 512
	maxPageSize = 65536
)

// Write streams a consistent page image of the database at path to w.
func Write(ctx context.Context, path string, w io.Writer) error {

	fi, err := os.Lstat(path)
	if err != nil {

		return err
	}
	if !fi.Mode().IsRegular() {

		return fmt.Errorf("pbsnap: %s is not a regular file", path)
	}
	// A normal, locking connection: inside the sandbox that is correct, and
	// it is what makes the read transaction a real snapshot against a writer.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=query_only(1)")
	if err != nil {

		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {

		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {

		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK") //nolint:errcheck // read-only

	// BEGIN is deferred: the snapshot starts at the first read, so take it
	// before asking for the page count it has to agree with.
	var n int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&n); err != nil {

		return err
	}
	var pageSize, pageCount int64
	if err := conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {

		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {

		return err
	}
	if err := checkShape(pageSize, pageCount); err != nil {

		return err
	}

	bw := bufio.NewWriterSize(w, 1<<20)
	hdr := make([]byte, 16)
	copy(hdr, magic[:])
	binary.BigEndian.PutUint32(hdr[8:], uint32(pageSize))
	binary.BigEndian.PutUint32(hdr[12:], uint32(pageCount))
	if _, err := bw.Write(hdr); err != nil {

		return err
	}

	rows, err := conn.QueryContext(ctx, "SELECT pgno, data FROM sqlite_dbpage ORDER BY pgno")
	if err != nil {

		return err
	}
	defer rows.Close()
	var want int64 = 1
	for rows.Next() {

		var pgno int64
		var data []byte
		if err := rows.Scan(&pgno, &data); err != nil {

			return err
		}
		if pgno != want || int64(len(data)) != pageSize {

			return fmt.Errorf("pbsnap: page %d is %d bytes at position %d, want %d bytes", pgno, len(data), want, pageSize)
		}
		if _, err := bw.Write(data); err != nil {

			return err
		}
		want++
	}
	if err := rows.Err(); err != nil {

		return err
	}
	if want-1 != pageCount {

		return fmt.Errorf("pbsnap: read %d pages, page_count said %d", want-1, pageCount)
	}
	return bw.Flush()
}

// Read writes the page image from r into a new file at dst, refusing a stream
// larger than limit bytes. dst must not exist.
func Read(r io.Reader, dst string, limit int64) (err error) {

	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r, hdr); err != nil {

		return fmt.Errorf("pbsnap: header: %w", err)
	}
	if [8]byte(hdr[:8]) != magic {

		return errors.New("pbsnap: not a pbsnap stream")
	}
	pageSize := int64(binary.BigEndian.Uint32(hdr[8:]))
	pageCount := int64(binary.BigEndian.Uint32(hdr[12:]))
	if err := checkShape(pageSize, pageCount); err != nil {

		return err
	}
	if total := pageSize * pageCount; total > limit {

		return fmt.Errorf("pbsnap: database is %d bytes, over the %d-byte limit", total, limit)
	}

	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {

		return err
	}
	defer func() {

		if cerr := f.Close(); err == nil {

			err = cerr
		}
		if err != nil {

			_ = os.Remove(dst)
		}
	}()
	n, err := io.CopyN(f, r, pageSize*pageCount)
	if err != nil {

		return fmt.Errorf("pbsnap: stream ended after %d of %d bytes: %w", n, pageSize*pageCount, err)
	}
	// Exactly the announced size: trailing bytes mean the producer and the
	// header disagree, and that copy is not one to trust.
	var one [1]byte
	if k, _ := r.Read(one[:]); k != 0 {

		return errors.New("pbsnap: trailing data after the last page")
	}
	return f.Sync()
}

func checkShape(pageSize, pageCount int64) error {

	if pageSize < minPageSize || pageSize > maxPageSize || pageSize&(pageSize-1) != 0 {

		return fmt.Errorf("pbsnap: page size %d is not a power of two in [%d, %d]", pageSize, minPageSize, maxPageSize)
	}
	if pageCount < 1 || pageCount > 1<<31 {

		return fmt.Errorf("pbsnap: page count %d out of range", pageCount)
	}
	return nil
}
