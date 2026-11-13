//go:build linux

package hostfs

import (
	"path/filepath"
	"syscall"
)

// Filesystem magic numbers (statfs(2), linux/magic.h) that are not local
// block storage.
var remoteFS = map[int64]string{
	0x6969:     "nfs",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x517b:     "smb",
	0x65735546: "fuse",
	0x01021997: "9p",
	0x5346414f: "afs",
	0x73757245: "coda",
	0x47504653: "gpfs",
	0x0bd00bd0: "lustre",
	0x00c36400: "ceph",
	0x013111a8: "ibrix",
	0x6b414653: "kafs",
	0x564c:     "ncp",
	0x7461636f: "ocfs2",
}

func fsKind(dir string) (string, bool, error) {

	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {

		return "", false, err
	}
	name, remote := remoteFS[int64(st.Type)]
	return name, remote, nil
}

func parentDir(dir string) string { return filepath.Dir(dir) }
