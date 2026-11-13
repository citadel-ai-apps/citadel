// Package hostfs owns every root-only filesystem operation behind the §7
// on-disk layout: the loopback quota image and its mount, the singleton
// lock, per-tenant keys, and the content-addressed artifact store.
//
// It is deliberately separate from internal/driver (which talks to Docker) and
// internal/store (which talks to SQLite): internal/backup needs the
// same image and mount primitives, and a snapshot must not have to reach into
// the driver to get them.
package hostfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

// FS performs host filesystem operations for one configured root.
type FS struct {
	cfg config.Config
}

// New returns an FS over cfg.
func New(cfg config.Config) *FS { return &FS{cfg: cfg} }

// EnsureLayout creates the §7 directory tree. Idempotent.
//
// 0700 throughout: control/keys holds per-tenant encryption keys, and there is
// no reason for anything but root to traverse any of it.
func (f *FS) EnsureLayout() error {

	for _, d := range []string{
		filepath.Join(f.cfg.PBRoot, "control"),
		f.cfg.KeysDir(),
		f.cfg.ArtifactsDir(),
		f.cfg.TenantsDir(),
		f.cfg.BackupsDir(),
		f.cfg.ScratchDir(),
		f.cfg.LogsDir(),
		f.cfg.CaddyDir(),
		f.cfg.EdgeAdminDir,
		f.cfg.AnchorsDir(),
		f.cfg.AttestationsDir(),
	} {

		if err := os.MkdirAll(d, 0o700); err != nil {

			return fmt.Errorf("hostfs: mkdir %s: %w", d, err)
		}
	}
	return nil
}

// EnsureTenantDirs creates one tenant's directories.
func (f *FS) EnsureTenantDirs(tenantID string) error {

	dir := f.cfg.TenantDir(tenantID)
	for _, d := range []string{dir, filepath.Join(dir, "app"), filepath.Join(dir, "data"),
		filepath.Join(f.cfg.LogsDir(), tenantID)} {

		if err := os.MkdirAll(d, 0o700); err != nil {

			return fmt.Errorf("hostfs: mkdir %s: %w", d, err)
		}
	}
	return nil
}

// DataImage is the loopback ext4 image backing a tenant's pb_data (D4).
func (f *FS) DataImage(tenantID string) string {

	return filepath.Join(f.cfg.TenantDir(tenantID), "data.img")
}

// DataDir is the mountpoint bind-mounted into the container at /pb/pb_data.
func (f *FS) DataDir(tenantID string) string {

	return filepath.Join(f.cfg.TenantDir(tenantID), "data")
}

// AppCurrent is the symlink bind-mounted read-only at /pb/app.
func (f *FS) AppCurrent(tenantID string) string {

	return filepath.Join(f.cfg.TenantDir(tenantID), "app", "current")
}

// LockPath is the singleton guard: one process per pb_data, ever.
func (f *FS) LockPath(tenantID string) string {

	return filepath.Join(f.cfg.TenantDir(tenantID), "instance.lock")
}

// RemoveTenantDir deletes a tenant's directory tree. The caller must have
// unmounted the data image first; Unmount is not implicit here because
// rm -rf over a live mount would delete the tenant's database.
func (f *FS) RemoveTenantDir(tenantID string) error {

	mounted, err := f.IsMounted(tenantID)
	if err != nil {

		return err
	}
	if mounted {

		return fmt.Errorf("hostfs: refusing to remove %s while its data image is mounted", tenantID)
	}
	return os.RemoveAll(f.cfg.TenantDir(tenantID))
}

// BackupsDir is where a tenant's snapshots live.
func (f *FS) BackupsDir(tenantID string) string {

	return filepath.Join(f.cfg.BackupsDir(), tenantID)
}

// RemoveBackups deletes a tenant's snapshots.
//
// Only called on an explicit purge: a snapshot is the only copy of a tenant's
// data once the image is gone, so it outlives the tenant by default and is
// destroyed only when an operator asked for that in as many words (D10).
func (f *FS) RemoveBackups(tenantID string) error {

	return os.RemoveAll(f.BackupsDir(tenantID))
}

// run executes a host command, folding stderr into the error so a failure says
// what the tool actually complained about.
func run(name string, args ...string) (string, error) {

	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {

		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
