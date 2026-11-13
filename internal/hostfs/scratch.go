package hostfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scratch kinds. One per thing that needs a throwaway data image.
const ScratchRehearse = "rehearse"

// ScratchDir is the working directory for one throwaway job.
//
// Deliberately outside tenants/: everything under tenants/<id> is the tenant's
// live state, and the orphan scan that runs every tick treats an unexpected
// directory there as drift. A rehearsal's copy is not tenant state — it exists
// for minutes and is destroyed whatever the outcome.
func (f *FS) ScratchDir(kind, id string) string {

	return filepath.Join(f.cfg.ScratchDir(), kind, id)
}

// ScratchImage is the ext4 image inside a scratch directory.
func (f *FS) ScratchImage(kind, id string) string {

	return filepath.Join(f.ScratchDir(kind, id), "data.img")
}

// ScratchData is the mountpoint inside a scratch directory.
func (f *FS) ScratchData(kind, id string) string {

	return filepath.Join(f.ScratchDir(kind, id), "data")
}

// EnsureScratchImage creates and mounts a scratch data image of sizeMiB,
// returning the mounted directory.
//
// sizeMiB is the tenant's real image size, not a convenient small number: a
// rehearsal has to be able to run out of space exactly where the real upgrade
// would, and it mounts with the same nosuid,nodev,noexec flags for the same
// reason.
func (f *FS) EnsureScratchImage(kind, id string, sizeMiB int) (string, error) {

	dir := f.ScratchDir(kind, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {

		return "", fmt.Errorf("hostfs: mkdir %s: %w", dir, err)
	}
	if err := createImage(f.ScratchImage(kind, id), sizeMiB); err != nil {

		return "", fmt.Errorf("hostfs: scratch image %s/%s: %w", kind, id, err)
	}
	data := f.ScratchData(kind, id)
	mounted, err := isMountedAt(data)
	if err != nil {

		return "", err
	}
	if !mounted {

		if err := mountImage(f.ScratchImage(kind, id), data); err != nil {

			return "", fmt.Errorf("hostfs: mount scratch %s/%s: %w", kind, id, err)
		}
	}
	return data, nil
}

// RemoveScratch unmounts and deletes one scratch directory.
//
// The unmount is attempted first and its failure is fatal: rm -rf over a live
// mount would delete the contents of the image rather than the image, and while
// a rehearsal's contents are disposable, the same mistake against the wrong
// path is not.
func (f *FS) RemoveScratch(kind, id string) error {

	if err := unmountDir(f.ScratchData(kind, id)); err != nil {

		return fmt.Errorf("hostfs: unmount scratch %s/%s: %w", kind, id, err)
	}
	return os.RemoveAll(f.ScratchDir(kind, id))
}

// OrphanScratch lists scratch ids of the given kind that are not in live.
//
// A crash mid-rehearsal leaves a mounted loop device and a multi-gigabyte file
// behind, and nothing else would ever look at them again. The caller removes
// what this returns; full teardown is only true if it is also true after a
// crash, which is the one case where the claim is tested.
func (f *FS) OrphanScratch(kind string, live map[string]bool) ([]string, error) {

	entries, err := os.ReadDir(filepath.Join(f.cfg.ScratchDir(), kind))
	if os.IsNotExist(err) {

		return nil, nil
	}
	if err != nil {

		return nil, err
	}
	var out []string
	for _, e := range entries {

		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {

			continue
		}
		if !live[e.Name()] {

			out = append(out, e.Name())
		}
	}
	return out, nil
}
