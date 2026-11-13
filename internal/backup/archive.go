package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Archive limits. A `files` snapshot is written from a tenant-writable
// directory and read back onto a live mount, so extraction is bounded on both
// count and size — the same discipline the package unpacker applies to an
// uploaded zip, for the same reason.
const (
	maxArchiveEntries = 200_000
	maxArchiveBytes   = 64 << 30
)

// archiveDir writes dir as a tar stream through the configured compressor.
func archiveDir(dir, dst string) (int64, error) {

	out, done, err := compressWriter(dst)
	if err != nil {

		return 0, err
	}
	tw := tar.NewWriter(out)
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {

		if err != nil {

			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {

			return err
		}
		if rel == "." {

			return nil
		}
		info, err := d.Info()
		if err != nil {

			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {

			return fmt.Errorf("backup: refusing to archive %s: not a regular file or directory", path)
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {

			return err
		}
		h.Name = filepath.ToSlash(rel)
		// Ownership is not carried. A snapshot may be restored onto a host with
		// a different userns-remap base, and the restore re-chowns from the
		// live configuration anyway (§7); baking in the numeric ids from the
		// machine that took the backup only creates a way for the two to
		// disagree.
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(h); err != nil {

			return err
		}
		if info.IsDir() {

			return nil
		}
		f, err := os.Open(path)
		if err != nil {

			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})
	if walkErr != nil {

		_ = tw.Close()
		_ = done()
		_ = os.Remove(dst)
		return 0, walkErr
	}
	if err := tw.Close(); err != nil {

		_ = done()
		_ = os.Remove(dst)
		return 0, err
	}
	if err := done(); err != nil {

		_ = os.Remove(dst)
		return 0, err
	}
	return fileSize(dst)
}

// extractDir unpacks an archive over dir, which must already exist.
//
// Every entry is checked before anything is written. A tar read back onto a
// tenant's live pb_data is the one place where the archive's own contents
// decide what the platform writes and where, so: no absolute paths, no `..`, no
// symlinks or hardlinks (which would let an extraction plant a path out of
// pb_data that survives the restore), no devices, and hard caps on entry count
// and total bytes.
func extractDir(src, dir string) error {

	r, closeFn, err := decompressReader(src)
	if err != nil {

		return err
	}
	defer closeFn()

	tr := tar.NewReader(r)
	var entries int
	var total int64
	for {

		h, err := tr.Next()
		if err == io.EOF {

			break
		}
		if err != nil {

			return fmt.Errorf("backup: read %s: %w", src, err)
		}
		entries++
		if entries > maxArchiveEntries {

			return fmt.Errorf("backup: %s has more than %d entries", src, maxArchiveEntries)
		}
		name, err := safeEntryName(h.Name)
		if err != nil {

			return fmt.Errorf("backup: %s: %w", src, err)
		}
		target := filepath.Join(dir, name)
		switch h.Typeflag {

		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(h.Mode).Perm()|0o700); err != nil {

				return err
			}

		case tar.TypeReg:
			total += h.Size
			if total > maxArchiveBytes {

				return fmt.Errorf("backup: %s expands past %d bytes", src, int64(maxArchiveBytes))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {

				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode).Perm())
			if err != nil {

				return err
			}
			if _, err := io.CopyN(f, tr, h.Size); err != nil {

				f.Close()
				return fmt.Errorf("backup: extract %s: %w", h.Name, err)
			}
			if err := f.Close(); err != nil {

				return err
			}

		default:
			return fmt.Errorf("backup: %s contains %q, which is not a regular file or directory", src, h.Name)
		}
	}
	return nil
}

// safeEntryName rejects any archive path that would escape the destination.
func safeEntryName(name string) (string, error) {

	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == string(filepath.Separator) {

		return "", fmt.Errorf("entry %q has no name", name)
	}
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {

		return "", fmt.Errorf("entry %q escapes the archive root", name)
	}
	return clean, nil
}

// emptyDir removes the CONTENTS of dir, leaving dir itself in place.
//
// A `files` restore replaces pb_data wholesale, and dir is a mountpoint: remove
// the directory and the mount goes with it, so only its contents may go.
func emptyDir(dir string) error {

	entries, err := os.ReadDir(dir)
	if err != nil {

		return err
	}
	for _, e := range entries {

		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {

			return err
		}
	}
	return nil
}

// compressWriter opens dst through zstd when available, gzip otherwise. The
// returned done() must be called to flush and close the whole chain.
func compressWriter(dst string) (io.Writer, func() error, error) {

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {

		return nil, nil, fmt.Errorf("backup: %w", err)
	}
	if zstdPath == "" {

		zw := gzip.NewWriter(out)
		return zw, func() error {

			if err := zw.Close(); err != nil {

				out.Close()
				return err
			}
			return out.Close()
		}, nil
	}
	cmd := exec.Command(zstdPath, "-q", "-T0", "-c")
	cmd.Stdout = out
	stdin, err := cmd.StdinPipe()
	if err != nil {

		out.Close()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {

		out.Close()
		return nil, nil, err
	}
	return stdin, func() error {

		if err := stdin.Close(); err != nil {

			_ = cmd.Wait()
			out.Close()
			return err
		}
		if err := cmd.Wait(); err != nil {

			out.Close()
			return fmt.Errorf("backup: zstd: %w", err)
		}
		return out.Close()
	}, nil
}

// decompressReader opens a snapshot for streaming reads, dispatching on the
// extension the platform itself wrote.
func decompressReader(src string) (io.Reader, func(), error) {

	switch filepath.Ext(src) {

	case ".zst":
		if zstdPath == "" {

			return nil, nil, fmt.Errorf("backup: %s is zstd-compressed and zstd is not installed", src)
		}
		cmd := exec.Command(zstdPath, "-d", "-q", "-c", src)
		stdout, err := cmd.StdoutPipe()
		if err != nil {

			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {

			return nil, nil, err
		}
		return stdout, func() { _ = cmd.Wait() }, nil

	case ".gz":
		in, err := os.Open(src)
		if err != nil {

			return nil, nil, fmt.Errorf("backup: %w", err)
		}
		zr, err := gzip.NewReader(in)
		if err != nil {

			in.Close()
			return nil, nil, fmt.Errorf("backup: %s: %w", src, err)
		}
		return zr, func() { zr.Close(); in.Close() }, nil

	default:
		return nil, nil, fmt.Errorf("backup: %s is not a snapshot this platform wrote", src)
	}
}
