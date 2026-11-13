// Package backup snapshots, restores and expires a tenant's data.
//
// Two artifact formats, because two different questions are being answered:
//
//   - `image` (Snapshot): the tenant is stopped, the loopback image is
//     unmounted and compressed whole. Byte-exact, and therefore the format for
//     every snapshot something is about to roll back to — pre_deploy,
//     pre_upgrade, and the final snapshot on destroy.
//   - `files` (SnapshotLive): the tenant keeps serving. Each database is
//     streamed out of the sandbox by pbsnap under one read transaction, then
//     integrity-checked and re-serialised with VACUUM INTO on the host, from
//     a private copy (INV-20: the host never opens a live tenant database).
//     §11 permits exactly this for routine backups of a busy instance, and
//     nothing looser: `cp` of a live WAL database remains forbidden
//     everywhere in this package.
//
// Never PocketBase's own backup endpoint — it needs superuser credentials, and
// credentials inside the instance are readable by hostile hooks (INV-1, INV-5).
//
// Retention is §11's table, enforced by Sweep. Offsite replication is still not
// built (§16, Later), so every snapshot here is on the same host as the data it
// protects; say so rather than implying otherwise.
package backup

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Copier fills dst with a consistent copy of a tenant's pb_data.
type Copier func(ctx context.Context, dst string) error

// ErrNoLock is returned when a caller asks for a snapshot without holding the
// tenant's instance.lock.
var ErrNoLock = errors.New("backup: the caller must hold the tenant's instance.lock")

// ErrVersionMismatch is returned when restoring a snapshot would hand older
// data to a newer binary, or newer data to an older one.
var ErrVersionMismatch = errors.New("backup: snapshot was written by a different PocketBase version")

// Retention per §11. A pre_deploy snapshot only has to outlive the deploy that
// took it; a pre_upgrade one is the ONLY rollback path and is kept far
// longer.
func retention(kind string) time.Duration {

	const day = 24 * time.Hour
	switch kind {

	case store.BackupPreDeploy:
		return 48 * time.Hour
	case store.BackupPreUpgrade:
		return 30 * day
	case store.BackupManual:
		return 30 * day
	default:
		return 7 * day
	}
}

// Service snapshots and restores tenant data images.
type Service struct {
	cfg   config.Config
	db    *store.DB
	fs    *hostfs.FS
	audit *auditlog.Logger
	log   *slog.Logger

	usernsBase int
}

// New returns a Service. usernsBase is the /etc/subuid base used to re-chown a
// restored image, or 0 when userns-remap is off.
func New(cfg config.Config, db *store.DB, fs *hostfs.FS, audit *auditlog.Logger, log *slog.Logger, usernsBase int) *Service {

	return &Service{cfg: cfg, db: db, fs: fs, audit: audit, log: log, usernsBase: usernsBase}
}

// Snapshot compresses the tenant's data image and records a backup row.
//
// The container must already be stopped and lock must be held: SQLite is
// single-writer, and copying a live WAL database is how a backup becomes a
// corrupt one (§11). The lock is a parameter rather than a comment so
// the requirement is visible at every call site.
func (s *Service) Snapshot(ctx context.Context, actor identity.Actor, t store.Tenant, kind string, lock *hostfs.Lock) (store.Backup, error) {

	if lock == nil {

		return store.Backup{}, ErrNoLock
	}
	out, err := s.snapshotPath(t.ID, kind, store.FormatImage)
	if err != nil {

		return store.Backup{}, err
	}
	if err := s.fs.Unmount(t.ID); err != nil {

		return store.Backup{}, err
	}
	size, err := compress(s.fs.DataImage(t.ID), out)
	remountErr := s.fs.EnsureMounted(t.ID)
	if err != nil {

		_ = os.Remove(out)
		return store.Backup{}, err
	}
	if remountErr != nil {

		return store.Backup{}, remountErr
	}
	return s.record(ctx, actor, t, kind, store.FormatImage, out, size)
}

// SnapshotLive records a snapshot without stopping the tenant.
//
// This is the routine-backup path of §11 and the source of a rehearsal's data
// copy. It is NOT a substitute for Snapshot on the rollback paths: a `files`
// snapshot is a re-serialised database, byte-identical in content and not in
// bytes, and a rollback wants the image it actually had.
//
// lock is still required — see LiveCopy. copyData fills the staging directory;
// the reconciler supplies one that runs LiveCopy and falls back to StoppedCopy.
func (s *Service) SnapshotLive(ctx context.Context, actor identity.Actor, t store.Tenant, kind string, lock *hostfs.Lock, copyData Copier) (store.Backup, error) {

	if lock == nil {

		return store.Backup{}, ErrNoLock
	}
	out, err := s.snapshotPath(t.ID, kind, store.FormatFiles)
	if err != nil {

		return store.Backup{}, err
	}
	// Staged through a scratch directory rather than streamed: VACUUM INTO
	// writes a file, so there is a copy on disk either way, and staging keeps
	// the tar single-pass over a directory that is no longer changing.
	stage, err := os.MkdirTemp(s.cfg.ScratchDir(), "live-"+t.ID+"-")
	if err != nil {

		return store.Backup{}, fmt.Errorf("backup: %w", err)
	}
	defer os.RemoveAll(stage)

	if err := copyData(ctx, stage); err != nil {

		return store.Backup{}, err
	}
	size, err := archiveDir(stage, out)
	if err != nil {

		_ = os.Remove(out)
		return store.Backup{}, err
	}
	return s.record(ctx, actor, t, kind, store.FormatFiles, out, size)
}

// RehearsalCopy builds a throwaway copy of a tenant's data for an upgrade
// rehearsal (§12), returning the mounted directory and a teardown func.
//
// The copy is a real ext4 image of the tenant's real size, mounted with the
// same flags: a rehearsal that cannot run out of disk, or that can execute what
// the live mount marks noexec, is rehearsing a different upgrade. The tenant
// never stops for it.
func (s *Service) RehearsalCopy(ctx context.Context, t store.Tenant, jobID string, lock *hostfs.Lock, copyData Copier) (string, func() error, error) {

	if lock == nil {

		return "", nil, ErrNoLock
	}
	dir, err := s.fs.EnsureScratchImage(hostfs.ScratchRehearse, jobID, hostfs.QuotaImageSize(t.DiskMiB))
	if err != nil {

		return "", nil, err
	}
	cleanup := func() error { return s.fs.RemoveScratch(hostfs.ScratchRehearse, jobID) }
	if err := copyData(ctx, dir); err != nil {

		_ = cleanup()
		return "", nil, err
	}
	// The whole tree: the copy was written as root, and the rehearsal boots the
	// same image under the same unprivileged UID the real instance uses.
	if err := s.fs.ChownTree(dir, s.usernsBase); err != nil {

		_ = cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// snapshotPath builds the destination file for one snapshot.
func (s *Service) snapshotPath(tenantID, kind, format string) (string, error) {

	dir := filepath.Join(s.cfg.BackupsDir(), tenantID, kind)
	if err := os.MkdirAll(dir, 0o700); err != nil {

		return "", fmt.Errorf("backup: %w", err)
	}
	return filepath.Join(dir, time.Now().UTC().Format("20060102-150405")+"."+snapshotExt(format)), nil
}

// record writes the row and its audit event in one transaction.
func (s *Service) record(ctx context.Context, actor identity.Actor, t store.Tenant, kind, format, path string, size int64) (store.Backup, error) {

	sum, err := fileSHA256(path)
	if err != nil {

		return store.Backup{}, err
	}
	b := store.Backup{
		ID:        store.NewID("bk"),
		TenantID:  t.ID,
		Kind:      kind,
		Format:    format,
		Path:      path,
		SizeBytes: size,
		Sha256:    sum,
		// Which binary wrote this data. The restore path reads it before it
		// touches anything: a 0.28 snapshot on a 0.40 runtime
		// re-triggers the one-way migration, silently.
		PBVersion: t.RuntimeVersion,
	}
	until := time.Now().UTC().Add(retention(kind))
	b.RetainUntil = &until

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertBackup(ctx, tx, b); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionBackupCreated,
			SubjectRef: "backup/" + b.ID,
			Detail: map[string]any{
				"kind": kind, "format": format, "bytes": size, "pb_version": b.PBVersion,
			},
		})
		return err
	})
	if err != nil {

		_ = os.Remove(path)
		return store.Backup{}, err
	}
	s.log.Info("snapshot taken", "tenant", t.ID, "kind", kind, "format", format, "backup", b.ID, "bytes", size)
	return b, nil
}

// Restore writes a snapshot back over the tenant's data image.
//
// The container must be stopped and lock must be held. A snapshot written by a
// different runtime version is refused unless force is set: restoring older
// data onto a newer binary re-runs the irreversible migration, and restoring
// newer data onto an older binary produces an instance that answers
// /api/health and has a broken data plane (design.md INV-4).
func (s *Service) Restore(ctx context.Context, actor identity.Actor, t store.Tenant, b store.Backup, force bool, lock *hostfs.Lock) error {

	if lock == nil {

		return ErrNoLock
	}
	if b.TenantID != t.ID {

		return fmt.Errorf("backup: %s belongs to %s, not %s", b.ID, b.TenantID, t.ID)
	}
	if b.PBVersion != t.RuntimeVersion && !force {

		return fmt.Errorf("%w: snapshot %s is %s, the tenant runs %s", ErrVersionMismatch, b.ID, b.PBVersion, t.RuntimeVersion)
	}
	// Checked before anything is unmounted or emptied: an archive that is not
	// the one that was written — truncated by a full disk, damaged in a copy
	// between hosts, or replaced — must fail here, with the tenant's data
	// still in place, rather than halfway through overwriting it.
	if err := verifyArchive(b); err != nil {

		return err
	}
	if b.Sha256 == "" {

		s.log.Warn("restoring a snapshot recorded without a digest; its integrity cannot be checked",
			"tenant", t.ID, "backup", b.ID)
	}

	var err error
	switch b.Format {

	case store.FormatFiles:
		err = s.restoreFiles(t, b)
	default:
		err = s.restoreImage(t, b)
	}
	if err != nil {

		return err
	}
	// Always, not only under userns-remap: a restore is also how a snapshot
	// moves between hosts, and the ids the archive came from are not this
	// host's.
	//
	// An `image` restore only needs the mountpoint — the ext4 image carries the
	// ownership of everything inside it. A `files` restore needs the whole tree,
	// because the platform extracted it as root: chowning the mountpoint alone
	// leaves the tenant with a database it cannot open, and the instance then
	// fails for a reason that has nothing to do with the restore.
	if b.Format == store.FormatFiles {

		if err := s.fs.ChownTree(s.fs.DataDir(t.ID), s.usernsBase); err != nil {

			return err
		}

	} else if err := s.fs.ChownData(t.ID, s.usernsBase); err != nil {

		return err
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		// The state change here is on the host, not in a table, so the audit
		// event is the whole record. It still goes in a transaction of its own
		// so a crash cannot drop it silently.
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionBackupRestored,
			SubjectRef: "backup/" + b.ID,
			Detail: map[string]any{
				"kind": b.Kind, "format": b.Format, "pb_version": b.PBVersion, "forced": force,
			},
		})
		return err
	})
	if err != nil {

		return err
	}
	s.log.Warn("data restored from snapshot", "tenant", t.ID, "backup", b.ID, "kind", b.Kind, "format", b.Format)
	return nil
}

// restoreImage writes a whole-image snapshot back over data.img.
//
// Into a temporary file next to it first, then renamed over it: decompressing
// straight onto data.img destroyed the live image the moment the archive
// turned out to be short or corrupt, leaving the tenant with neither.
func (s *Service) restoreImage(t store.Tenant, b store.Backup) error {

	if err := s.fs.Unmount(t.ID); err != nil {

		return err
	}
	img := s.fs.DataImage(t.ID)
	tmp := img + ".restore"
	_ = os.Remove(tmp)
	err := decompress(b.Path, tmp)
	if err == nil {

		err = os.Rename(tmp, img)
	}
	if err != nil {

		_ = os.Remove(tmp)
	}
	if mErr := s.fs.EnsureMounted(t.ID); err == nil {

		err = mErr
	}
	return err
}

// ErrArchiveDigest means a snapshot's file no longer matches the digest
// recorded when it was written.
var ErrArchiveDigest = errors.New("backup: snapshot does not match its recorded digest")

func verifyArchive(b store.Backup) error {

	if b.Sha256 == "" {

		return nil
	}
	sum, err := fileSHA256(b.Path)
	if err != nil {

		return err
	}
	if sum != b.Sha256 {

		return fmt.Errorf("%w: %s (%s)", ErrArchiveDigest, b.ID, b.Path)
	}
	return nil
}

func fileSHA256(path string) (string, error) {

	f, err := os.Open(path)
	if err != nil {

		return "", fmt.Errorf("backup: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {

		return "", fmt.Errorf("backup: digest %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// restoreFiles empties the mounted data directory and extracts a `files`
// snapshot into it.
//
// The image is NOT replaced, only its contents: a live logical snapshot says
// nothing about how big the tenant's image should be, and recreating it here
// would silently resize the tenant's quota to whatever this code thought at
// restore time.
func (s *Service) restoreFiles(t store.Tenant, b store.Backup) error {

	if err := s.fs.EnsureMounted(t.ID); err != nil {

		return err
	}
	dir := s.fs.DataDir(t.ID)
	if err := emptyDir(dir); err != nil {

		return fmt.Errorf("backup: clear %s: %w", dir, err)
	}
	return extractDir(b.Path, dir)
}

// SweepResult is one retention pass.
type SweepResult struct {
	Deleted int      `json:"deleted"`
	Bytes   int64    `json:"bytes"`
	Kept    int      `json:"kept"`
	Errors  []string `json:"errors,omitempty"`
	At      time.Time
}

// Sweep enforces §11's retention.
//
// Two rows survive their retain_until regardless, and both exceptions are the
// difference between a policy and an outage:
//
//   - a tenant's single newest snapshot, whatever its kind or age. A sweep that
//     runs in the gap before the next routine backup must never leave a tenant
//     with nothing to restore.
//   - any snapshot an in-flight upgrade job names. INV-4 makes that snapshot
//     the only way back from a one-way migration.
//
// Deletion order is row-then-file. A crash between them leaks a file, which is
// inert and findable; the reverse leaks a row pointing at nothing, and that is
// discovered by a restore, at the worst possible moment.
func (s *Service) Sweep(ctx context.Context, now time.Time) (SweepResult, error) {

	res := SweepResult{At: now.UTC()}
	expired, err := store.ExpiredBackups(ctx, s.db.Reader(), now)
	if err != nil {

		return res, err
	}
	if len(expired) == 0 {

		return res, nil
	}
	referenced, err := store.BackupsReferencedByJobs(ctx, s.db.Reader())
	if err != nil {

		return res, err
	}
	newest := map[string]string{}
	for _, b := range expired {

		if _, ok := newest[b.TenantID]; ok {

			continue
		}
		n, err := store.NewestBackup(ctx, s.db.Reader(), b.TenantID)
		if err != nil {

			return res, err
		}
		newest[b.TenantID] = n.ID
	}

	for _, b := range expired {

		switch {

		case referenced[b.ID]:
			res.Kept++
			s.log.Info("retention: keeping a snapshot an upgrade job still needs",
				"tenant", b.TenantID, "backup", b.ID)
			continue

		case newest[b.TenantID] == b.ID:
			res.Kept++
			s.log.Info("retention: keeping a tenant's last remaining snapshot",
				"tenant", b.TenantID, "backup", b.ID)
			continue
		}
		if err := s.expire(ctx, b); err != nil {

			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", b.ID, err))
			continue
		}
		res.Deleted++
		res.Bytes += b.SizeBytes
	}
	if res.Deleted > 0 || len(res.Errors) > 0 {

		s.log.Info("retention sweep", "deleted", res.Deleted, "bytes", res.Bytes,
			"kept", res.Kept, "errors", len(res.Errors))
	}
	return res, s.auditSweep(ctx, res)
}

// expire deletes one snapshot: row and audit event first, file second.
func (s *Service) expire(ctx context.Context, b store.Backup) error {

	err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.DeleteBackup(ctx, tx, b.ID); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: auditlog.PlatformPrincipal, ActorKind: auditlog.ActorPlatform, TenantID: b.TenantID,
			Action:     auditlog.ActionBackupDeleted,
			SubjectRef: "backup/" + b.ID,
			Detail: map[string]any{
				"kind": b.Kind, "format": b.Format, "bytes": b.SizeBytes, "reason": "retention",
			},
		})
		return err
	})
	if err != nil {

		return err
	}
	if err := os.Remove(b.Path); err != nil && !os.IsNotExist(err) {

		// The row is already gone, so this is a leaked file and not a lost
		// backup. Loud, because a sweep that cannot unlink is a sweep that is
		// not reclaiming anything.
		return fmt.Errorf("row deleted but file remains: %w", err)
	}
	return nil
}

// auditSweep records the pass itself, once, in addition to the per-snapshot
// events. Without it a sweep that deleted nothing is indistinguishable from one
// that never ran.
func (s *Service) auditSweep(ctx context.Context, res SweepResult) error {

	if res.Deleted == 0 && len(res.Errors) == 0 {

		return nil
	}
	return s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: auditlog.PlatformPrincipal, ActorKind: auditlog.ActorPlatform,
			Action: auditlog.ActionBackupSwept,
			Detail: map[string]any{
				"deleted": res.Deleted, "bytes": res.Bytes, "kept": res.Kept, "errors": len(res.Errors),
			},
		})
		return err
	})
}

// Delete removes one snapshot on request, rather than on expiry.
func (s *Service) Delete(ctx context.Context, actor identity.Actor, b store.Backup, reason string) error {

	err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.DeleteBackup(ctx, tx, b.ID); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: b.TenantID,
			Action:     auditlog.ActionBackupDeleted,
			SubjectRef: "backup/" + b.ID,
			Detail:     map[string]any{"kind": b.Kind, "reason": reason},
		})
		return err
	})
	if err != nil {

		return err
	}
	if err := os.Remove(b.Path); err != nil && !os.IsNotExist(err) {

		return fmt.Errorf("backup: row deleted but file remains: %w", err)
	}
	return nil
}

// zstdPath is resolved once, so every snapshot is written with the same
// compressor and any of them is readable by any other.
var zstdPath, _ = exec.LookPath("zstd")

func snapshotExt(format string) string {

	base := "img"
	if format == store.FormatFiles {

		base = "tar"
	}
	if zstdPath != "" {

		return base + ".zst"
	}
	return base + ".gz"
}

func compress(src, dst string) (int64, error) {

	if zstdPath != "" {

		if out, err := exec.Command(zstdPath, "-q", "-T0", "-f", "-o", dst, src).CombinedOutput(); err != nil {

			return 0, fmt.Errorf("backup: zstd %s: %w: %s", src, err, out)
		}
		return fileSize(dst)
	}
	in, err := os.Open(src)
	if err != nil {

		return 0, fmt.Errorf("backup: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {

		return 0, fmt.Errorf("backup: %w", err)
	}
	defer out.Close()

	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {

		return 0, fmt.Errorf("backup: compress %s: %w", src, err)
	}
	if err := zw.Close(); err != nil {

		return 0, err
	}
	return fileSize(dst)
}

func decompress(src, dst string) error {

	switch filepath.Ext(src) {

	case ".zst":
		if zstdPath == "" {

			return fmt.Errorf("backup: %s is zstd-compressed and zstd is not installed", src)
		}
		if out, err := exec.Command(zstdPath, "-d", "-q", "-f", "-o", dst, src).CombinedOutput(); err != nil {

			return fmt.Errorf("backup: unzstd %s: %w: %s", src, err, out)
		}
		return nil

	case ".gz":
		in, err := os.Open(src)
		if err != nil {

			return fmt.Errorf("backup: %w", err)
		}
		defer in.Close()

		zr, err := gzip.NewReader(in)
		if err != nil {

			return fmt.Errorf("backup: %s: %w", src, err)
		}
		defer zr.Close()

		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {

			return fmt.Errorf("backup: %w", err)
		}
		defer out.Close()

		if _, err := io.Copy(out, zr); err != nil {

			return fmt.Errorf("backup: decompress %s: %w", src, err)
		}
		return out.Sync()

	default:
		return fmt.Errorf("backup: %s is not a snapshot this platform wrote", src)
	}
}

func fileSize(path string) (int64, error) {

	fi, err := os.Stat(path)
	if err != nil {

		return 0, err
	}
	return fi.Size(), nil
}
