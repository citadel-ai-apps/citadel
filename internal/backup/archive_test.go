package backup

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

func TestArchiveRoundTrip(t *testing.T) {

	src, out := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "storage", "abc"), 0o700); err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "data.db"), []byte("pretend database"), 0o600); err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "storage", "abc", "file.bin"), []byte("upload"), 0o600); err != nil {

		t.Fatal(err)
	}
	dst := filepath.Join(out, "snap."+snapshotExt("files"))
	if _, err := archiveDir(src, dst); err != nil {

		t.Fatalf("archive: %v", err)
	}
	back := t.TempDir()
	if err := extractDir(dst, back); err != nil {

		t.Fatalf("extract: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(back, "storage", "abc", "file.bin"))
	if err != nil || string(b) != "upload" {

		t.Fatalf("nested file did not survive the round trip: %q %v", b, err)
	}
}

// writeTar builds an archive by hand, which is the only way to produce the
// entries a well-behaved writer never would.
func writeTar(t *testing.T, path string, headers []*tar.Header) {

	t.Helper()
	w, done, err := compressWriter(path)
	if err != nil {

		t.Fatal(err)
	}
	tw := tar.NewWriter(w)
	for _, h := range headers {

		if err := tw.WriteHeader(h); err != nil {

			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {

		t.Fatal(err)
	}
	if err := done(); err != nil {

		t.Fatal(err)
	}
}

// A `files` snapshot is written from a tenant-writable directory and read back
// onto a live mount, so the archive's own contents decide what the platform
// writes and where. Every one of these has to be refused.
func TestExtractRefusesEscapingEntries(t *testing.T) {

	cases := []struct {
		name   string
		header *tar.Header
	}{
		{"parent traversal", &tar.Header{Name: "../escaped", Typeflag: tar.TypeReg, Mode: 0o600}},
		{"absolute path", &tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o600}},
		{"nested traversal", &tar.Header{Name: "storage/../../escaped", Typeflag: tar.TypeReg, Mode: 0o600}},
		{"symlink", &tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink, Mode: 0o777}},
		{"hardlink", &tar.Header{Name: "hard", Linkname: "data.db", Typeflag: tar.TypeLink, Mode: 0o600}},
		{"device node", &tar.Header{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o600}},
	}
	for _, c := range cases {

		t.Run(c.name, func(t *testing.T) {

			dir := t.TempDir()
			path := filepath.Join(dir, "evil."+snapshotExt("files"))
			writeTar(t, path, []*tar.Header{c.header})
			if err := extractDir(path, t.TempDir()); err == nil {

				t.Fatalf("%s was extracted instead of refused", c.name)
			}
		})
	}
}

func TestExtractRefusesTooManyEntries(t *testing.T) {

	dir := t.TempDir()
	path := filepath.Join(dir, "many."+snapshotExt("files"))
	headers := make([]*tar.Header, 0, maxArchiveEntries+1)
	for i := range maxArchiveEntries + 1 {

		headers = append(headers, &tar.Header{
			Name: filepath.Join("f", string(rune('a'+i%26)), "x"), Typeflag: tar.TypeDir, Mode: 0o700,
		})
	}
	writeTar(t, path, headers)
	if err := extractDir(path, t.TempDir()); err == nil {

		t.Fatal("an archive past the entry cap was extracted")
	}
}

// A `files` restore replaces pb_data wholesale, and the directory it replaces
// is a MOUNTPOINT: removing the directory itself would take the mount with it.
func TestEmptyDirLeavesTheDirectoryInPlace(t *testing.T) {

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "storage"), 0o700); err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.db"), []byte("x"), 0o600); err != nil {

		t.Fatal(err)
	}
	if err := emptyDir(dir); err != nil {

		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {

		t.Fatalf("the directory itself was removed: %v", err)
	}
	if len(entries) != 0 {

		t.Fatalf("%d entries survived", len(entries))
	}
}

// §11's table, which the sweep enforces. pre_upgrade is the outlier and is the
// one that matters: it is the only rollback path a one-way migration has.
func TestRetentionMatchesTheTable(t *testing.T) {

	const day = 24
	cases := map[string]float64{
		"pre_deploy":  48,
		"pre_upgrade": 30 * day,
		"manual":      30 * day,
		"routine":     7 * day,
	}
	for kind, hours := range cases {

		if got := retention(kind).Hours(); got != hours {

			t.Fatalf("%s retention is %.0fh, want %.0fh", kind, got, hours)
		}
	}
}

// A snapshot that is not the file that was written must be refused before a
// restore touches the tenant's data; a legacy row with no digest still
// restores.
func TestVerifyArchiveRefusesAChangedSnapshot(t *testing.T) {

	path := filepath.Join(t.TempDir(), "snap.tar.gz")
	if err := os.WriteFile(path, []byte("the archive as written"), 0o600); err != nil {

		t.Fatal(err)
	}
	sum, err := fileSHA256(path)
	if err != nil {

		t.Fatal(err)
	}
	b := store.Backup{ID: "bk-1", Path: path, Sha256: sum}
	if err := verifyArchive(b); err != nil {

		t.Fatalf("intact snapshot refused: %v", err)
	}
	if err := os.WriteFile(path, []byte("the archive as written, trunc"), 0o600); err != nil {

		t.Fatal(err)
	}
	if err := verifyArchive(b); !errors.Is(err, ErrArchiveDigest) {

		t.Fatalf("changed snapshot: err = %v, want ErrArchiveDigest", err)
	}
	if err := verifyArchive(store.Backup{ID: "bk-old", Path: path}); err != nil {

		t.Fatalf("a pre-digest row was refused: %v", err)
	}
}
