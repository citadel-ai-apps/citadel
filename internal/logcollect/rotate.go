package logcollect

import (
	"fmt"
	"os"
	"strconv"
)

// Rotate renames path to path.1, shifting existing generations up and dropping
// anything past `keep`. It reports whether a rotation happened.
//
// Size-triggered rather than time-triggered, because the thing being bounded is
// a hostile workload's output: a hook in a loop can produce a day's worth of
// log lines in a minute, and a daily rotation would let it fill the disk first.
//
// Rename, not truncate: a writer holding the file open keeps writing to the
// rotated inode until it reopens, which loses at most the lines written between
// the rename and the reopen. Truncating in place would instead leave the writer
// at its old offset and produce a sparse file the size of everything it ever
// wrote, which is exactly the outcome rotation exists to prevent.
func Rotate(path string, maxBytes int64, keep int) (bool, error) {

	info, err := os.Stat(path)
	if err != nil {

		if os.IsNotExist(err) {

			return false, nil
		}
		return false, err
	}
	if info.Size() < maxBytes {

		return false, nil
	}
	if keep <= 0 {

		return true, os.Remove(path)
	}
	// Oldest first, so nothing is overwritten before it has been shifted.
	if err := os.Remove(path + "." + strconv.Itoa(keep)); err != nil && !os.IsNotExist(err) {

		return false, err
	}
	for i := keep - 1; i >= 1; i-- {

		from := path + "." + strconv.Itoa(i)
		to := path + "." + strconv.Itoa(i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {

			return false, fmt.Errorf("logcollect: rotate %s: %w", from, err)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {

		return false, fmt.Errorf("logcollect: rotate %s: %w", path, err)
	}
	return true, nil
}
