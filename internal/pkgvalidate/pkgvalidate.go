// Package pkgvalidate checks an uploaded tenant package against design §6 and
// unpacks it into a directory the release store can stage.
//
// Validation is NOT a security boundary. Tenant code is still hostile: every .js in
// pb_hooks is arbitrary code execution inside the PocketBase process, and no
// amount of checking here changes that. What this package buys is a guardrail
// against accidents — a zip bomb, a stray absolute path, a hook file that is
// really a symlink to /etc/shadow — and, more importantly, an error message
// that names the offending file, because the upload path is a developer-facing
// product surface.
package pkgvalidate

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits bound what an upload may contain (design §6 defaults).
type Limits struct {
	MaxUncompressed int64
	MaxFiles        int
	MaxRatio        float64
}

// DefaultLimits are §6's: 50 MiB unpacked, 2000 files, and a compression ratio
// no tenant package has a legitimate reason to exceed.
func DefaultLimits() Limits {

	return Limits{MaxUncompressed: 50 << 20, MaxFiles: 2000, MaxRatio: 200}
}

// Options is everything Validate needs that is not in the zip.
type Options struct {
	Limits
	HostPolicy

	// Supported is the set of runtime versions the platform currently offers.
	// Empty skips the intersection check, which is what a unit test wants and
	// what the control plane never passes.
	Supported []string

	// Refused, when set, reports a subject this tenant may not request at all.
	// The normal §14.7 path is *not* this hook — a previously revoked host is
	// re-requestable and lands at Tier 2. This exists for an operator hard
	// block.
	Refused func(host string) bool
}

// Result is a validated, unpacked package.
type Result struct {
	Manifest    Manifest
	Raw         []byte // the manifest bytes as uploaded, stored verbatim in release.manifest
	Dir         string
	Files       int
	Bytes       int64
	Compressed  int64
	HasHooks    bool
	HasMigrates bool
}

// allowedRoots are the only top-level names a package may contain (§6).
var allowedRoots = map[string]bool{
	"pb_hooks": true, "pb_migrations": true, "pb_public": true,
}

// jsOnly are the directories where a non-.js file is a mistake: PocketBase
// loads every file it finds there, and a .ts or a .map would either be ignored
// silently or fail at boot.
var jsOnly = map[string]bool{"pb_hooks": true, "pb_migrations": true}

// Validate reads the zip at r, checks every §6 rule, and unpacks it into dest,
// which must exist and should be empty.
//
// On any failure it returns a wrapped sentinel naming the offending path, and
// dest is left for the caller to remove.
func Validate(r io.ReaderAt, size int64, dest string, opt Options) (Result, error) {

	if opt.MaxUncompressed == 0 {

		opt.Limits = DefaultLimits()
	}
	if size > opt.MaxUncompressed {

		return Result{}, fmt.Errorf("%w: the upload alone is %d bytes, over the %d byte cap",
			ErrTooLarge, size, opt.MaxUncompressed)
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {

		return Result{}, fmt.Errorf("%w: %v", ErrNotZip, err)
	}

	res := Result{Dir: dest}
	var manifestRaw []byte
	for _, f := range zr.File {

		clean, isDir, err := entryPath(f.Name)
		if err != nil {

			return Result{}, err
		}
		if isDir {

			if err := checkEntryMode(clean, f.Mode(), true); err != nil {

				return Result{}, err
			}
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(clean)), 0o755); err != nil {

				return Result{}, err
			}
			continue
		}

		res.Files++
		if res.Files > opt.MaxFiles {

			return Result{}, fmt.Errorf("%w: more than %d entries", ErrTooManyFiles, opt.MaxFiles)
		}
		if err := checkEntryMode(clean, f.Mode(), false); err != nil {

			return Result{}, err
		}
		if err := checkExtension(clean); err != nil {

			return Result{}, err
		}

		// UncompressedSize64 is attacker-controlled metadata, so it is used only
		// to reject early. The copy below is what actually bounds the write.
		res.Compressed += int64(f.CompressedSize64)
		if res.Bytes+int64(f.UncompressedSize64) > opt.MaxUncompressed {

			return Result{}, fmt.Errorf("%w: %s takes the package over the %d byte cap",
				ErrTooLarge, clean, opt.MaxUncompressed)
		}

		n, err := extractFile(f, dest, clean, opt.MaxUncompressed-res.Bytes)
		if err != nil {

			return Result{}, err
		}
		res.Bytes += n

		switch {

		case clean == ManifestName:
			manifestRaw, err = os.ReadFile(filepath.Join(dest, ManifestName))
			if err != nil {

				return Result{}, err
			}
		case strings.HasPrefix(clean, "pb_hooks/"):
			res.HasHooks = true
		case strings.HasPrefix(clean, "pb_migrations/"):
			res.HasMigrates = true
		}
	}

	if err := checkRatio(res, opt.Limits); err != nil {

		return Result{}, err
	}
	if manifestRaw == nil {

		return Result{}, fmt.Errorf("%w: the package has no %s at its root", ErrManifest, ManifestName)
	}
	m, err := ParseManifest(manifestRaw, opt)
	if err != nil {

		return Result{}, err
	}
	res.Manifest = m
	res.Raw = manifestRaw
	return res, nil
}

// entryPath normalises a zip entry name and rejects everything §6 forbids about
// it: absolute paths, traversal, backslashes, and anything outside the three
// directories plus the manifest.
func entryPath(name string) (clean string, isDir bool, err error) {

	if strings.ContainsRune(name, '\\') {

		return "", false, fmt.Errorf("%w: %q uses a backslash separator", ErrTraversal, name)
	}
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {

		return "", false, fmt.Errorf("%w: %q is an absolute path", ErrTraversal, name)
	}
	isDir = strings.HasSuffix(name, "/")
	clean = path.Clean(name)
	if clean == "." || clean == "/" {

		return "", true, nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {

		return "", false, fmt.Errorf("%w: %q escapes the package root", ErrTraversal, name)
	}
	root, _, _ := strings.Cut(clean, "/")
	switch {

	case clean == ManifestName:
	case allowedRoots[root]:
	default:
		return "", false, fmt.Errorf("%w: %q is not under pb_hooks/, pb_migrations/ or pb_public/, and is not %s",
			ErrForeignPath, name, ManifestName)
	}
	// A bare "pb_hooks" entry with no trailing slash is still a directory as far
	// as the layout is concerned.
	if !isDir && allowedRoots[clean] {

		isDir = true
	}
	return clean, isDir, nil
}

func checkEntryMode(name string, mode os.FileMode, isDir bool) error {

	switch {

	case mode&os.ModeSymlink != 0:
		return fmt.Errorf("%w: %q is a symlink; a package carries files, not references to the host", ErrSymlink, name)
	case mode&(os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeIrregular) != 0:
		return fmt.Errorf("%w: %q", ErrNodeType, name)
	case mode&(os.ModeSetuid|os.ModeSetgid) != 0:
		return fmt.Errorf("%w: %q carries a setuid/setgid bit", ErrExecBit, name)
	}
	// Directories keep their traversal bit; a file does not get one. The image
	// has no shell to run it with (§5), but an executable file in a package is
	// a sign the uploader thinks it will be run, and that expectation is the
	// bug worth naming.
	if !isDir && mode.Perm()&0o111 != 0 {

		return fmt.Errorf("%w: %q is executable; nothing in a package is ever executed directly", ErrExecBit, name)
	}
	return nil
}

func checkExtension(clean string) error {

	root, rest, found := strings.Cut(clean, "/")
	if !found || !jsOnly[root] {

		return nil
	}
	if path.Ext(rest) != ".js" {

		return fmt.Errorf("%w: %q is in %s/, which loads every file it finds", ErrNonJS, clean, root)
	}
	return nil
}

// checkRatio is the zip-bomb guard. It only fires above 1 MiB unpacked: small
// packages of highly repetitive JSON legitimately compress very well, and
// failing those would be a false positive on the happy path.
func checkRatio(res Result, lim Limits) error {

	if res.Bytes < 1<<20 || res.Compressed == 0 {

		return nil
	}
	ratio := float64(res.Bytes) / float64(res.Compressed)
	if ratio > lim.MaxRatio {

		return fmt.Errorf("%w: %d bytes unpacked from %d compressed (%.0f:1, cap %.0f:1)",
			ErrZipBomb, res.Bytes, res.Compressed, ratio, lim.MaxRatio)
	}
	return nil
}

func extractFile(f *zip.File, dest, clean string, budget int64) (int64, error) {

	target := filepath.Join(dest, filepath.FromSlash(clean))
	// Defence in depth: entryPath already refused traversal, but the write is
	// the step that would do the damage, so it checks again against the
	// resolved path rather than trusting the earlier decision.
	if rel, err := filepath.Rel(dest, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {

		return 0, fmt.Errorf("%w: %q resolves outside the package root", ErrTraversal, f.Name)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {

		return 0, err
	}
	rc, err := f.Open()
	if err != nil {

		return 0, fmt.Errorf("%w: %s: %v", ErrNotZip, clean, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {

		if errors.Is(err, os.ErrExist) {

			return 0, fmt.Errorf("%w: %q appears twice in the archive", ErrForeignPath, clean)
		}
		return 0, err
	}
	defer out.Close()

	// LimitReader by the remaining budget plus one byte: if the copy reaches the
	// extra byte, the entry lied about its size and the package is over the cap.
	n, err := io.Copy(out, io.LimitReader(rc, budget+1))
	if err != nil {

		return 0, fmt.Errorf("%w: %s: %v", ErrNotZip, clean, err)
	}
	if n > budget {

		return 0, fmt.Errorf("%w: %s unpacks to more than the declared size", ErrTooLarge, clean)
	}
	return n, nil
}
