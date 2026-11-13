package hostfs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ContainerUID is the UID the hardened image declares with USER (§5).
const ContainerUID = 10001

// SubuidPath is where Docker's remap range is recorded.
const SubuidPath = "/etc/subuid"

// RemapUser is the account Docker's `userns-remap: default` creates.
const RemapUser = "dockremap"

// SubuidBase returns the host UID that container UID 0 maps to.
//
// Read from /etc/subuid, never hardcoded: the base is 100000 on the
// development host but is assigned by useradd and differs between hosts
// (design.md §4).
func SubuidBase() (int, error) {

	f, err := os.Open(SubuidPath)
	if err != nil {

		return 0, fmt.Errorf("hostfs: userns-remap is enabled but %s is unreadable: %w", SubuidPath, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {

		fields := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(fields) < 2 || fields[0] != RemapUser {

			continue
		}
		base, err := strconv.Atoi(fields[1])
		if err != nil {

			return 0, fmt.Errorf("hostfs: %s has a malformed %s line: %q", SubuidPath, RemapUser, sc.Text())
		}
		return base, nil
	}
	if err := sc.Err(); err != nil {

		return 0, err
	}
	// smoke.sh treats this as fatal for the same reason: the daemon will remap
	// UIDs using a base we cannot see, so any chown we perform is a guess and
	// the tenant's first write fails with EACCES for no visible reason.
	return 0, fmt.Errorf("hostfs: userns-remap is enabled but %s has no %s entry", SubuidPath, RemapUser)
}

// ChownData gives a tenant's mounted data directory to the UID its container
// will run as.
//
// Must run AFTER EnsureMounted: chowning before the mount chowns the underlying
// directory instead of the ext4 root inode, and the container then cannot write
// (design.md §4).
//
// usernsBase is 0 when the daemon has no userns-remap, in which case container
// UID 10001 is host UID 10001.
func (f *FS) ChownData(tenantID string, usernsBase int) error {

	mounted, err := f.IsMounted(tenantID)
	if err != nil {

		return err
	}
	if !mounted {

		return fmt.Errorf("hostfs: refusing to chown %s before its data image is mounted", tenantID)
	}
	// app/ stays root-owned: it is bind-mounted :ro and a hook must not be able
	// to rewrite its own release (§13.1).
	return f.ChownDir(f.DataDir(tenantID), usernsBase)
}

// ChownDir gives one directory to the UID a tenant container runs as.
//
// The path-based half of ChownData, for the rehearsal copy: a rehearsal boots
// the same image under the same UID, so its data directory needs the same
// ownership or the container fails to write for a reason that has nothing to do
// with the upgrade being rehearsed.
func (f *FS) ChownDir(dir string, usernsBase int) error {

	uid := usernsBase + ContainerUID
	if err := os.Chown(dir, uid, uid); err != nil {

		return fmt.Errorf("hostfs: chown %s to %d: %w", dir, uid, err)
	}
	return nil
}

// ChownTree gives a directory AND everything under it to the container's UID.
//
// The directory alone is enough when the container created the contents itself,
// which is the case for a freshly mounted image and for a restored one — the
// ext4 image carries its own ownership. It is NOT enough whenever the platform
// wrote the contents: a `files` restore extracts as root, and a rehearsal copy
// is vacuumed and copied as root. Chowning only the mountpoint there leaves the
// tenant looking at a database it cannot open, and the instance then fails for
// a reason that has nothing to do with what was being restored or rehearsed.
func (f *FS) ChownTree(dir string, usernsBase int) error {

	uid := usernsBase + ContainerUID
	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {

		if err != nil {

			return err
		}
		// Lchown, not Chown: a symlink has no business being here, and
		// following one would chown whatever it points at.
		if err := os.Lchown(path, uid, uid); err != nil {

			return fmt.Errorf("hostfs: chown %s to %d: %w", path, uid, err)
		}
		return nil
	})
}
