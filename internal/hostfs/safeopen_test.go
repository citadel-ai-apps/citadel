package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRegularUnderReadsAFileInside(t *testing.T) {

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("inside"), 0o600); err != nil {

		t.Fatal(err)
	}
	f, fi, err := OpenRegularUnder(dir, "sub/a.txt")
	if err != nil {

		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != "inside" || fi.Size() != 6 {

		t.Fatalf("read %q (size %d)", b, fi.Size())
	}
}

// The attack: a file or a parent directory under pb_data is replaced by a
// symlink to somewhere the tenant cannot read, and the host opens it as root.
func TestOpenRegularUnderRefusesEscapes(t *testing.T) {

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("host only"), 0o600); err != nil {

		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "data.db")); err != nil {

		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "storage")); err != nil {

		t.Fatal(err)
	}
	for _, rel := range []string{"data.db", "storage/secret", "../" + filepath.Base(outside) + "/secret"} {

		if f, _, err := OpenRegularUnder(dir, rel); err == nil {

			_ = f.Close()
			t.Errorf("%s: opened a file outside the root", rel)
		}
	}
}

func TestOpenRegularUnderRefusesNonRegular(t *testing.T) {

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {

		t.Fatal(err)
	}
	// A FIFO would block a plain open(2) forever.
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {

		t.Fatal(err)
	}
	for _, rel := range []string{"d", "fifo"} {

		_, _, err := OpenRegularUnder(dir, rel)
		if !errors.Is(err, ErrNotRegular) {

			t.Errorf("%s: err = %v, want ErrNotRegular", rel, err)
		}
	}
}
