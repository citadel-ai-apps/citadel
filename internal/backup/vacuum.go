package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // the same pure-Go driver internal/store uses

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/pbsnap"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Streamer copies one live database out of the tenant's running instance: it
// runs cmd/pbsnap for dbName INSIDE the instance's sandbox and writes the
// stream to w. The reconciler provides it over driver.Snapshot.
type Streamer func(ctx context.Context, dbName string, w io.Writer) error

// LiveCopy writes a consistent copy of a tenant's pb_data into dst WITHOUT
// stopping the container.
//
// Every other path in this package stops the tenant first, which is how §11's
// "never cp a live WAL database" rule is kept structural rather than
// remembered. This one trades that away deliberately, within the exception
// §11 grants, and under INV-20: the host never opens a live tenant database
// through SQLite. Under gVisor the host cannot see PocketBase's locks, and a
// host-side connection that believes it is alone checkpoints and unlinks the
// -wal and -shm of a database PocketBase still has open. So each database is
// streamed out by stream — pbsnap, run inside the sandbox, reading under one
// read transaction — into a private file on the host that no other process
// has open. Only THAT copy is integrity-checked and serialised with VACUUM
// INTO, so the `files` artifact is what it always was.
//
// A stream that fails with driver.ErrExecNotFound (an image built before
// pbsnap shipped) is returned before anything is written to dst, so the
// caller can fall back to StoppedCopy.
//
// Everything in pb_data that is NOT a database is copied as a plain file, and a
// symlink is refused rather than followed: pb_data is tenant-writable, and an
// archiver that follows a symlink out of it walks a path the tenant chose.
//
// lock is still required. Not to exclude the PocketBase process — the whole
// point is that it keeps serving — but to exclude a concurrent deploy, snapshot
// or destroy from unmounting the image while this reads it.
func (s *Service) LiveCopy(ctx context.Context, t store.Tenant, dst string, lock *hostfs.Lock, stream Streamer) error {

	if lock == nil {

		return ErrNoLock
	}
	if stream == nil {

		return errors.New("backup: LiveCopy needs a Streamer")
	}
	src := s.fs.DataDir(t.ID)
	if err := s.fs.EnsureMounted(t.ID); err != nil {

		return err
	}
	if err := liveCopy(ctx, stream, src, dst, imageBytes(t)); err != nil {

		return fmt.Errorf("%w (tenant %s)", err, t.ID)
	}
	return nil
}

// liveCopy is LiveCopy below the mount: src is a running instance's pb_data,
// dst the staging directory, and limit the size of the image pb_data lives in.
//
// One budget covers the whole copy, databases and plain files together, as it
// does for stoppedCopy. The image bounds the blocks a tenant writes, not what
// the copy writes out: every top-level *.db is streamed, and a hardlink is a
// regular file that costs the quota nothing, so a budget per database would let
// a tenant multiply the staging directory's share of the host's disk by
// linking one database under many names.
func liveCopy(ctx context.Context, stream Streamer, src, dst string, limit int64) error {

	dbs, err := sqliteFiles(src)
	if err != nil {

		return err
	}
	if len(dbs) == 0 {

		return fmt.Errorf("backup: no database found in %s", src)
	}
	b := newBudget(limit)

	// Databases first, so an image without pbsnap fails before dst holds
	// anything a fallback would have to clear away.
	for _, name := range dbs {

		if err := streamCopy(ctx, stream, name, dst, b); err != nil {

			return fmt.Errorf("backup: live copy of %s: %w", name, err)
		}
	}
	return copyPlain(src, dst, dbSkip(dbs), b)
}

// StoppedCopy is LiveCopy's fallback for an instance with no PocketBase
// process running: the caller has stopped it, so nothing is writing pb_data
// (INV-3). Its contents are still the tenant's, so the databases are copied
// out before SQLite touches them (see copyDBFiles).
func (s *Service) StoppedCopy(ctx context.Context, t store.Tenant, dst string, lock *hostfs.Lock) error {

	if lock == nil {

		return ErrNoLock
	}
	src := s.fs.DataDir(t.ID)
	if err := s.fs.EnsureMounted(t.ID); err != nil {

		return err
	}
	if err := stoppedCopy(ctx, src, dst, imageBytes(t)); err != nil {

		return fmt.Errorf("%w (tenant %s)", err, t.ID)
	}
	return nil
}

// stoppedCopy is StoppedCopy below the mount: src is a stopped instance's
// pb_data, dst the staging directory, and limit the size of the image pb_data
// lives in — the most its databases, journals and files can hold together.
func stoppedCopy(ctx context.Context, src, dst string, limit int64) error {

	dbs, err := sqliteFiles(src)
	if err != nil {

		return err
	}
	if len(dbs) == 0 {

		return fmt.Errorf("backup: no database found in %s", src)
	}
	if err := clearDir(dst); err != nil {

		return err
	}
	root, err := os.OpenRoot(src)
	if err != nil {

		return fmt.Errorf("backup: %w", err)
	}
	defer root.Close()
	b := newBudget(limit)
	for _, name := range dbs {

		raw := filepath.Join(dst, ".stopped-"+name)
		if err := copyDBFiles(root, name, raw, b); err != nil {

			removeDB(raw)
			return fmt.Errorf("backup: copy %s: %w", name, err)
		}
		if err := finishPrivateCopy(ctx, raw, dst, name); err != nil {

			return fmt.Errorf("backup: vacuum %s: %w", name, err)
		}
	}
	return copyPlain(src, dst, dbSkip(dbs), b)
}

// copyDBFiles copies one database and the journals that hold its committed
// state out of pb_data into raw, through handles opened beneath root.
//
// SQLite is never pointed at pb_data itself, even with the instance stopped.
// Opening a database there makes root open its -wal, -shm and -journal by
// name in a directory the tenant writes, and makes the host the one to replay
// whatever journal the tenant left. Current SQLite refuses a symlinked sidecar
// on its own, but that is a property of the library version, not of this
// code; the private copy has sidecars only the host created, and its integrity
// is checked before anything else reads it. -wal and -journal are copied
// because they can hold committed transactions a crashed instance never
// checkpointed; -shm is a cache SQLite rebuilds and is never copied.
func copyDBFiles(root *os.Root, name, raw string, b *budget) error {

	if err := copyFrom(root, name, raw, b); err != nil {

		return err
	}
	for _, suffix := range []string{"-wal", "-journal"} {

		if _, err := root.Lstat(name + suffix); errors.Is(err, os.ErrNotExist) {

			continue
		}
		if err := copyFrom(root, name+suffix, raw+suffix, b); err != nil {

			return err
		}
	}
	return nil
}

// dbSkip lists the databases and their sidecars for copyPlain to leave out.
//
// The -wal and -shm sidecars belong to the ORIGINAL database. Copying them
// next to a vacuumed one would hand PocketBase a journal that does not match
// its database, which is a corrupt restore that looks fine until the first
// write.
func dbSkip(dbs []string) map[string]bool {

	skip := make(map[string]bool, len(dbs)*3)
	for _, name := range dbs {

		skip[name] = true
		skip[name+"-wal"] = true
		skip[name+"-shm"] = true
	}
	return skip
}

// streamCopy pulls one database out of the sandbox into dst/name, charging the
// private copy it streams to b.
func streamCopy(ctx context.Context, stream Streamer, name, dst string, b *budget) error {

	raw := filepath.Join(dst, ".pbsnap-"+name)
	defer removeDB(raw)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {

		err := stream(ctx, name, pw)
		pw.CloseWithError(err)
		done <- err
	}()
	readErr := pbsnap.Read(pr, raw, b.left)
	// Unblock the producer if Read stopped early, then take ITS error first:
	// "the image has no pbsnap" is the one the caller branches on.
	pr.CloseWithError(errors.New("backup: reader stopped"))
	streamErr := <-done
	switch {

	case errors.Is(streamErr, driver.ErrExecNotFound):
		return streamErr
	case readErr != nil:
		return readErr
	case streamErr != nil:
		return streamErr
	}
	// Charged on what was streamed, as copyDBFiles charges what it copied: the
	// private copy is the larger of the two files this leaves behind at once.
	fi, err := os.Stat(raw)
	if err != nil {

		return fmt.Errorf("backup: %w", err)
	}
	if fi.Size() > b.left {

		return fmt.Errorf("%w: %s is %d bytes, and only %d of the %d-byte image remain",
			ErrOverBudget, name, fi.Size(), b.left, b.total)
	}
	b.left -= fi.Size()
	return finishPrivateCopy(ctx, raw, dst, name)
}

// finishPrivateCopy turns a private copy of a tenant database into dst/name.
//
// The copy came out of a tenant sandbox or a tenant's pb_data. Before it
// becomes a backup, it has to be a database; then VACUUM INTO serialises it
// without its journals. raw is removed, with whatever sidecars opening it
// created, whatever the outcome.
func finishPrivateCopy(ctx context.Context, raw, dst, name string) error {

	defer removeDB(raw)
	if err := integrityCheck(ctx, raw); err != nil {

		return err
	}
	return vacuumInto(ctx, raw, filepath.Join(dst, name))
}

// untrustedSchema are the pragmas for opening a private copy of a tenant
// database. The copy is private, but its schema is tenant-written:
// integrity_check evaluates CHECK constraints and expression indexes, and
// VACUUM INTO rebuilds them, so functions with side effects stay off and
// malformed pages are caught rather than trusted.
const untrustedSchema = "&_pragma=trusted_schema(0)&_pragma=cell_size_check(1)"

// integrityCheck runs PRAGMA integrity_check on a private copy.
func integrityCheck(ctx context.Context, path string) error {

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)"+untrustedSchema)
	if err != nil {

		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check(1)").Scan(&res); err != nil {

		return fmt.Errorf("backup: integrity check: %w", err)
	}
	if res != "ok" {

		return fmt.Errorf("backup: copied database failed its integrity check: %.200s", res)
	}
	return nil
}

// removeDB removes a private database copy and whatever sidecars opening it
// left behind.
func removeDB(path string) {

	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {

		_ = os.Remove(p)
	}
}

// clearDir empties dir without removing it: dst may be a mount point.
func clearDir(dir string) error {

	entries, err := os.ReadDir(dir)
	if err != nil {

		return fmt.Errorf("backup: %w", err)
	}
	for _, e := range entries {

		if e.Name() == "lost+found" {

			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {

			return fmt.Errorf("backup: %w", err)
		}
	}
	return nil
}

// vacuumInto serialises src into a new database at dst.
//
// src is never a tenant's own pb_data (INV-20 and copyDBFiles): it is a private
// copy, from pbsnap or from a stopped instance's files. Opened read-write, because a
// reader of a WAL database has to be able to create the -shm shared-memory
// file; the only statement executed is the VACUUM. dst must not exist — SQLite
// refuses to overwrite, and that refusal is worth keeping rather than
// pre-deleting around.
func vacuumInto(ctx context.Context, src, dst string) error {

	if _, err := os.Stat(dst); err == nil {

		return fmt.Errorf("backup: %s already exists", dst)
	}
	dsn := "file:" + src + "?_pragma=busy_timeout(10000)" + untrustedSchema
	db, err := sql.Open("sqlite", dsn)
	if err != nil {

		return err
	}
	defer db.Close()

	// One connection: VACUUM INTO on a pooled handle could land on a different
	// connection than the one that opened the WAL.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {

		return err
	}
	return nil
}

// sqliteFiles lists the top-level database files in a pb_data directory.
//
// Enumerated rather than hard-coded: the set has changed across PocketBase
// lines (`data.db` + `logs.db` on older ones, `data.db` + `auxiliary.db` from
// 0.23), and a backup that silently misses a database is worse than one that
// fails.
func sqliteFiles(dir string) ([]string, error) {

	entries, err := os.ReadDir(dir)
	if err != nil {

		return nil, fmt.Errorf("backup: read %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {

		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {

			continue
		}
		if !e.Type().IsRegular() {

			return nil, fmt.Errorf("backup: %s is not a regular file", filepath.Join(dir, e.Name()))
		}
		out = append(out, e.Name())
	}
	return out, nil
}

// copyPlain copies srcDir into dstDir, skipping the named top-level entries.
//
// Symlinks, devices, sockets and anything else that is not a regular file or a
// directory are refused, not skipped: pb_data holds tenant-uploaded storage, and
// an unexpected file type there is either a tenant doing something the platform
// did not anticipate or a bug, and both deserve a loud stop rather than a
// quietly incomplete backup.
//
// The walk and every open go through os.Root. LiveCopy runs this while the
// tenant is still serving, so the tree can change between listing an entry and
// opening it: a directory swapped for a symlink to the host's key directory
// would otherwise be copied into the tenant's own backup, and handed back to
// the tenant on restore. Beneath the root, such a link is refused.
//
// Every byte written counts against b, which starts at the size of the image
// pb_data lives in (see budget).
func copyPlain(srcDir, dstDir string, skip map[string]bool, b *budget) error {

	root, err := os.OpenRoot(srcDir)
	if err != nil {

		return fmt.Errorf("backup: %w", err)
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {

		if err != nil {

			return err
		}
		if rel == "." {

			return nil
		}
		if skip[rel] {

			return nil
		}
		target := filepath.Join(dstDir, filepath.FromSlash(rel))
		switch {

		case d.IsDir():
			info, err := d.Info()
			if err != nil {

				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())

		case d.Type().IsRegular():
			return copyFrom(root, rel, target, b)

		default:
			return fmt.Errorf("backup: refusing to copy %s: not a regular file or directory", rel)
		}
	})
}

// ErrOverBudget is returned when pb_data holds more than the image it lives in
// could: a file whose SIZE the quota never saw.
var ErrOverBudget = errors.New("backup: pb_data claims more bytes than its image can hold")

// budget bounds the bytes one copy may write to the host.
//
// The quota image bounds the BLOCKS a tenant can write (D4), not the size a
// file claims. truncate(2) extends a file to any length without allocating
// anything — a sparse file, a terabyte that occupies nothing inside the image —
// and a plain copy writes every hole out as zeroes. The staging directory is on
// the host's own filesystem, outside every quota, so without this one call in a
// hook turns the next routine backup into a write of whatever size the tenant
// chose, onto the disk every other tenant and the control plane share.
//
// Nothing legitimate in pb_data can add up to more than the image it lives in,
// so that is the budget: a copy that would exceed it is refused, the way a
// symlink is, rather than truncated into a backup that silently lacks a file.
type budget struct {
	total, left int64
}

func newBudget(total int64) *budget { return &budget{total: total, left: total} }

// imageBytes is the size of a tenant's quota image.
func imageBytes(t store.Tenant) int64 { return int64(hostfs.QuotaImageSize(t.DiskMiB)) << 20 }

// copyFrom copies rel, opened beneath root, to the host path dst, charging b.
func copyFrom(root *os.Root, rel, dst string, b *budget) error {

	in, fi, err := hostfs.OpenRegularIn(root, filepath.FromSlash(rel))
	if err != nil {

		return fmt.Errorf("backup: %w", err)
	}
	defer in.Close()

	// Checked on the claimed size first, so a sparse terabyte is refused before
	// a single zero is written.
	if fi.Size() > b.left {

		return fmt.Errorf("%w: %s is %d bytes, and only %d of the %d-byte image remain",
			ErrOverBudget, rel, fi.Size(), b.left, b.total)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {

		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
	if err != nil {

		return err
	}
	defer out.Close()

	// And on what is actually read, because the tenant is still running during
	// a live copy and can extend the file after the size was checked.
	n, err := io.Copy(out, io.LimitReader(in, b.left+1))
	b.left -= n
	if err != nil {

		return err
	}
	if b.left < 0 {

		return fmt.Errorf("%w: %s grew past the remaining budget while it was copied", ErrOverBudget, rel)
	}
	return out.Sync()
}
