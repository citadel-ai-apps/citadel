package hostfs

import (
	"errors"
	"fmt"
	"os"
)

// ErrNetworkFS is a tenant data path on a network or userspace filesystem.
var ErrNetworkFS = errors.New("hostfs: tenant data must live on a local filesystem (INV-10)")

// CheckLocal refuses a directory that sits on a network or FUSE filesystem.
//
// pb_data itself is always an ext4 loop mount, so SQLite's locks never cross a
// network. But the loop image is a FILE in the tenant directory, and a loop
// device over NFS or SMB is a block device whose writes can be lost, reordered
// or seen stale — the same failure INV-10 exists to rule out, one layer down.
// So the directories that hold data images and their rehearsal copies must
// themselves be local. Missing directories are skipped: they are created
// later, on whatever filesystem their parent is on, which is checked too.
func CheckLocal(paths ...string) error {

	for _, p := range paths {

		for dir := p; ; {

			if _, err := os.Stat(dir); err == nil {

				name, remote, err := fsKind(dir)
				if err != nil {

					return fmt.Errorf("hostfs: statfs %s: %w", dir, err)
				}
				if remote {

					return fmt.Errorf("%w: %s is on %s", ErrNetworkFS, p, name)
				}
				break
			}
			parent := parentDir(dir)
			if parent == dir {

				break
			}
			dir = parent
		}
	}
	return nil
}
