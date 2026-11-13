package hostfs

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrNotRegular is returned when a tenant-writable path names something other
// than a regular file.
var ErrNotRegular = errors.New("hostfs: not a regular file")

// ErrOtherDevice is returned when a file under a tenant directory lives on a
// different filesystem from the directory itself.
var ErrOtherDevice = errors.New("hostfs: file is on a different device from its directory")

// OpenRegularUnder opens rel beneath dir for reading, refusing anything that
// would leave dir, and returns the open handle with its own stat.
//
// Everything under a tenant's pb_data is written by hostile code that keeps
// running while the host reads it (INV-1). A check on a path followed by an
// open of the same path is a race the tenant can win: swap a file or a parent
// directory for a symlink in between, and the host — running as root — opens
// whatever the link names. So the open goes through os.Root, which resolves
// every component beneath dir and refuses a symlink that points out of it, and
// every check after that is made on the handle, never on the path again.
//
// O_NONBLOCK keeps a planted FIFO from hanging the caller in open(2); it is
// then refused as not regular. The device check catches a file that is under
// dir by path but on another filesystem, which the tenant cannot arrange today
// and which nothing on the host should ever read as tenant data.
func OpenRegularUnder(dir, rel string) (*os.File, os.FileInfo, error) {

	root, err := os.OpenRoot(dir)
	if err != nil {

		return nil, nil, fmt.Errorf("hostfs: open %s: %w", dir, err)
	}
	defer root.Close()
	return openRegularIn(root, rel)
}

// openRegularIn is OpenRegularUnder for a caller that already holds the root.
func openRegularIn(root *os.Root, rel string) (*os.File, os.FileInfo, error) {

	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {

		return nil, nil, fmt.Errorf("hostfs: open %s: %w", rel, err)
	}
	fi, err := f.Stat()
	if err != nil {

		_ = f.Close()
		return nil, nil, fmt.Errorf("hostfs: stat %s: %w", rel, err)
	}
	if !fi.Mode().IsRegular() {

		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: %s is %s", ErrNotRegular, rel, fi.Mode().Type())
	}
	dirInfo, err := root.Stat(".")
	if err != nil {

		_ = f.Close()
		return nil, nil, fmt.Errorf("hostfs: stat root: %w", err)
	}
	if device(fi) != device(dirInfo) {

		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: %s", ErrOtherDevice, rel)
	}
	return f, fi, nil
}

// OpenRegularIn opens rel beneath an already-open root with the same checks as
// OpenRegularUnder. Callers walking a tree open the root once.
func OpenRegularIn(root *os.Root, rel string) (*os.File, os.FileInfo, error) {

	return openRegularIn(root, rel)
}

func device(fi os.FileInfo) uint64 {

	if st, ok := fi.Sys().(*syscall.Stat_t); ok {

		return uint64(st.Dev) // int32 on darwin, uint64 on linux
	}
	return 0
}
