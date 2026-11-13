package hostfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// fsOverheadPercent is the headroom added on top of a tenant's nominal quota.
//
// design.md §7 measured 82 MiB usable out of a 100 MiB ext4 image,
// so an image sized at the nominal quota gives the tenant ~18 % less than the
// number they were sold. Sizing above it makes disk_mib mean what it says.
const fsOverheadPercent = 20

// CreateDataImage creates the loopback ext4 image for a tenant, sized above the
// nominal quota by fsOverheadPercent. Idempotent: an existing image is left
// alone, because re-running mkfs would destroy the tenant's database.
func (f *FS) CreateDataImage(tenantID string, nominalMiB int) error {

	if nominalMiB <= 0 {

		return fmt.Errorf("hostfs: disk quota for %s must be positive", tenantID)
	}
	if err := createImage(f.DataImage(tenantID), QuotaImageSize(nominalMiB)); err != nil {

		return fmt.Errorf("hostfs: data image for %s: %w", tenantID, err)
	}
	return nil
}

// QuotaImageSize is the on-disk size of an image sold as nominalMiB.
//
// Exported because a rehearsal copy has to be the SAME size as the tenant's own
// image: a rehearsal that cannot run out of space is not rehearsing the
// migration the tenant is about to run.
func QuotaImageSize(nominalMiB int) int {

	return nominalMiB + nominalMiB*fsOverheadPercent/100
}

// createImage formats an ext4 image at path, sized sizeMiB. Idempotent: an
// existing image is left alone, because re-running mkfs would destroy whatever
// database is in it.
func createImage(path string, sizeMiB int) error {

	if _, err := os.Stat(path); err == nil {

		return nil

	} else if !os.IsNotExist(err) {

		return err
	}
	// Written to a temp name and renamed, so a crash mid-mkfs cannot leave a
	// half-formatted image that the next provisioning run would adopt.
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if _, err := run("truncate", "-s", strconv.Itoa(sizeMiB)+"M", tmp); err != nil {

		return err
	}
	// -F: mke2fs otherwise asks whether to proceed on a non-block-device. It
	// skips the prompt when stdin is not a tty, which is true here, but relying
	// on that is how a provisioning run hangs the day something gives it a tty.
	// -m 0: reserved blocks are for a root process recovering a full root fs;
	// inside a per-tenant quota image they are 5 % of the tenant's paid space.
	if _, err := run("mkfs.ext4", "-q", "-F", "-m", "0", tmp); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// IsMounted reports whether a tenant's data image is mounted at its mountpoint.
//
// Compares the device of the mountpoint against the device of its parent: a
// mountpoint always differs from the directory containing it.
func (f *FS) IsMounted(tenantID string) (bool, error) {

	return isMountedAt(f.DataDir(tenantID))
}

// isMountedAt reports whether dir is a mountpoint, by comparing its device
// against its parent's: a mountpoint always differs from the directory
// containing it.
func isMountedAt(dir string) (bool, error) {

	var st, parent syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {

		if os.IsNotExist(err) {

			return false, nil
		}
		return false, fmt.Errorf("hostfs: stat %s: %w", dir, err)
	}
	if err := syscall.Stat(filepath.Dir(dir), &parent); err != nil {

		return false, fmt.Errorf("hostfs: stat parent of %s: %w", dir, err)
	}
	return st.Dev != parent.Dev, nil
}

// EnsureMounted mounts a tenant's data image if it is not already mounted.
//
// Loopback mounts do not survive a reboot (design.md §8.3), so every
// path that touches pb_data calls this first — including the reconciler, before
// it ever starts a container. A container started before its mount serves an
// empty pb_data, silently.
func (f *FS) EnsureMounted(tenantID string) error {

	mounted, err := f.IsMounted(tenantID)
	if err != nil {

		return err
	}
	if mounted {

		return nil
	}
	img := f.DataImage(tenantID)
	if _, err := os.Stat(img); err != nil {

		return fmt.Errorf("hostfs: no data image for %s: %w", tenantID, err)
	}
	if err := mountImage(img, f.DataDir(tenantID)); err != nil {

		return fmt.Errorf("hostfs: mount %s: %w", tenantID, err)
	}
	return nil
}

// mountImage loop-mounts img at dir. The ONLY definition of the tenant mount
// flags in the tree, so a rehearsal copy cannot be mounted more permissively
// than the image it stands in for.
func mountImage(img, dir string) error {

	if err := os.MkdirAll(dir, 0o700); err != nil {

		return err
	}
	// nosuid,nodev,noexec: this filesystem holds tenant-writable data. Nothing
	// in it should ever be executable or a device node, and the mount is the
	// cheapest place to say so.
	_, err := run("mount", "-o", "loop,nosuid,nodev,noexec", img, dir)
	return err
}

// unmountDir releases a mount. Not being mounted is not an error.
func unmountDir(dir string) error {

	mounted, err := isMountedAt(dir)
	if err != nil || !mounted {

		return err
	}
	_, err = run("umount", dir)
	return err
}

// Unmount releases a tenant's data mount. A tenant that is not mounted is not
// an error — callers use this on teardown and before a snapshot, and both must
// be idempotent.
func (f *FS) Unmount(tenantID string) error {

	if err := unmountDir(f.DataDir(tenantID)); err != nil {

		return fmt.Errorf("hostfs: unmount %s: %w", tenantID, err)
	}
	return nil
}

// DataDeviceID returns the device number of a tenant's mounted data directory.
//
// The reconciler compares this against the device the running container has
// bound at /pb/pb_data: if they differ, the container was started against a
// different (or absent) mount and must be recreated. A heuristic like "was it
// running before we mounted" only approximates this; the device number is the
// fact.
func (f *FS) DataDeviceID(tenantID string) (uint64, error) {

	var st syscall.Stat_t
	if err := syscall.Stat(f.DataDir(tenantID), &st); err != nil {

		return 0, err
	}
	return uint64(st.Dev), nil
}

// Usage reports bytes used and available inside a tenant's quota image.
//
// data.img's size is not the usable size (design.md §7), so the
// portal must show what statfs says rather than the nominal quota.
func (f *FS) Usage(tenantID string) (usedBytes, availBytes uint64, err error) {

	var st syscall.Statfs_t
	if err := syscall.Statfs(f.DataDir(tenantID), &st); err != nil {

		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	return (uint64(st.Blocks) - uint64(st.Bfree)) * bs, uint64(st.Bavail) * bs, nil
}
