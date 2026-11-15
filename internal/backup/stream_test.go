package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/pbsnap"
)

// TestStreamCopyProducesAVacuumedCopyAndNothingElse covers the live path: the
// database comes out through pbsnap (here in-process, standing in for
// `docker exec` into the sandbox), and dst ends up with exactly the vacuumed
// database — no private copy, no sidecars.
func TestStreamCopyProducesAVacuumedCopyAndNothingElse(t *testing.T) {

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "data.db")
	busyDB(t, src)
	stream := func(ctx context.Context, name string, w io.Writer) error {

		return pbsnap.Write(ctx, filepath.Join(srcDir, name), w)
	}

	dst := t.TempDir()
	if err := streamCopy(context.Background(), stream, "data.db", dst, newBudget(1<<30)); err != nil {

		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 1 || entries[0].Name() != "data.db" {

		var got []string
		for _, e := range entries {

			got = append(got, e.Name())
		}
		t.Fatalf("dst holds %v, want only data.db", got)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dst, "data.db")+"?mode=ro")
	if err != nil {

		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM notes`).Scan(&n); err != nil || n != 200 {

		t.Fatalf("copy has %d notes (%v), want 200", n, err)
	}
}

// TestStreamCopyReportsAMissingHelper pins the fallback signal: an image
// without pbsnap surfaces driver.ErrExecNotFound, not a stream error, and
// leaves dst empty for StoppedCopy.
func TestStreamCopyReportsAMissingHelper(t *testing.T) {

	stream := func(ctx context.Context, name string, w io.Writer) error {

		return fmt.Errorf("%w: /pb/pbsnap", driver.ErrExecNotFound)
	}
	dst := t.TempDir()
	err := streamCopy(context.Background(), stream, "data.db", dst, newBudget(1<<30))
	if !errors.Is(err, driver.ErrExecNotFound) {

		t.Fatalf("err = %v, want ErrExecNotFound", err)
	}
	if entries, _ := os.ReadDir(dst); len(entries) != 0 {

		t.Fatalf("dst is not empty after a missing helper: %v", entries)
	}
}

// TestStreamCopyRefusesACorruptStream: a well-formed stream whose pages are not
// a database (a hostile sandbox) never becomes a backup.
func TestStreamCopyRefusesACorruptStream(t *testing.T) {

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "data.db")
	busyDB(t, src)
	stream := func(ctx context.Context, name string, w io.Writer) error {

		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(pbsnap.Write(ctx, filepath.Join(srcDir, name), pw)) }()
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(pr, hdr); err != nil {

			return err
		}
		if _, err := w.Write(hdr); err != nil {

			return err
		}
		// Keep the shape, scramble every byte of every page after the header
		// page's first 100 bytes.
		buf := make([]byte, 4096)
		first := true
		for {

			k, err := pr.Read(buf)
			for i := range k {

				if !first || i >= 100 {

					buf[i] ^= 0xA5
				}
			}
			first = false
			if _, werr := w.Write(buf[:k]); werr != nil {

				return werr
			}
			if err == io.EOF {

				return nil
			}
			if err != nil {

				return err
			}
		}
	}
	dst := t.TempDir()
	if err := streamCopy(context.Background(), stream, "data.db", dst, newBudget(1<<30)); err == nil {

		t.Fatal("a scrambled database was accepted as a backup")
	}
	if _, err := os.Stat(filepath.Join(dst, "data.db")); !os.IsNotExist(err) {

		t.Fatal("a refused copy left data.db in dst")
	}
}

// TestLiveCopyChargesEveryDatabaseToOneBudget pins §11's bound on the live
// path: everything copied out of pb_data, databases included, is charged to
// one image-sized budget. A hardlink is a regular file that costs the quota
// nothing, so a per-database budget let a tenant stage the image once per name.
func TestLiveCopyChargesEveryDatabaseToOneBudget(t *testing.T) {

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "data.db")
	db := busyDB(t, src)
	size := checkpointedSize(t, db)
	for _, name := range []string{"a.db", "b.db"} {

		if err := os.Link(src, filepath.Join(srcDir, name)); err != nil {

			t.Fatal(err)
		}
	}
	stream := func(ctx context.Context, name string, w io.Writer) error {

		return pbsnap.Write(ctx, filepath.Join(srcDir, name), w)
	}

	// Room for two copies of the database, not three.
	if err := liveCopy(context.Background(), stream, srcDir, t.TempDir(), 2*size+size/2); err == nil {

		t.Fatal("three names for one database fit a budget of two and a half: want a refusal")
	}
	// The control: the same tree fits a budget that holds all three.
	if err := liveCopy(context.Background(), stream, srcDir, t.TempDir(), 3*size+size/2); err != nil {

		t.Fatalf("three databases in a budget of three and a half: %v", err)
	}
}

// TestLiveCopyLeavesPlainFilesOnlyTheRemainder: the plain files after the
// databases draw on what the databases left, not on a fresh image's worth.
func TestLiveCopyLeavesPlainFilesOnlyTheRemainder(t *testing.T) {

	srcDir := t.TempDir()
	db := busyDB(t, filepath.Join(srcDir, "data.db"))
	size := checkpointedSize(t, db)
	if err := os.WriteFile(filepath.Join(srcDir, "blob"), make([]byte, size), 0o600); err != nil {

		t.Fatal(err)
	}
	stream := func(ctx context.Context, name string, w io.Writer) error {

		return pbsnap.Write(ctx, filepath.Join(srcDir, name), w)
	}

	err := liveCopy(context.Background(), stream, srcDir, t.TempDir(), size+size/2)
	if !errors.Is(err, ErrOverBudget) {

		t.Fatalf("a database and a file of its size in one and a half budgets: got %v, want ErrOverBudget", err)
	}
	if err := liveCopy(context.Background(), stream, srcDir, t.TempDir(), 2*size+size/2); err != nil {

		t.Fatalf("the same tree in two and a half budgets: %v", err)
	}
}

// checkpointedSize folds db's WAL into its main file and returns the size a
// pbsnap stream of it declares.
func checkpointedSize(t *testing.T, db *sql.DB) int64 {

	t.Helper()
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {

		t.Fatal(err)
	}
	var pages, pageSize int64
	if err := db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {

		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {

		t.Fatal(err)
	}
	return pages * pageSize
}
