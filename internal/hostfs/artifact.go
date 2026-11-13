package hostfs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// appSubdirs are the three directories the image entrypoint points its
// --hooksDir/--publicDir/--migrationsDir flags at. All three must exist even
// when empty, or PocketBase logs a startup error for the missing ones.
var appSubdirs = []string{"pb_hooks", "pb_migrations", "pb_public"}

// ArtifactDigest computes a content-addressed digest of a release tree.
//
// The digest commits to the sorted relative path, the executable bit, and the
// contents of every regular file — nothing else. It deliberately does not hash
// a tar stream: that would commit to GNU tar's member ordering, header format
// and `./` prefixes, so the same tree hashed differently under a different
// tar, and the three always-created subdirectories fell outside the hash
// entirely.
//
// Symlinks, devices and anything else non-regular are rejected rather than
// skipped. internal/pkgvalidate rejects them at upload; refusing them
// here too means a hand-placed fixture cannot smuggle one in.
func ArtifactDigest(srcDir string) (string, error) {

	type entry struct {
		rel  string
		mode fs.FileMode
	}
	var entries []entry

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {

		if err != nil {

			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {

			return err
		}
		if rel == "." {

			return nil
		}
		if d.IsDir() {

			return nil
		}
		info, err := d.Info()
		if err != nil {

			return err
		}
		if !info.Mode().IsRegular() {

			return fmt.Errorf("hostfs: %s is not a regular file (mode %s); releases contain files only", rel, info.Mode())
		}
		entries = append(entries, entry{rel: filepath.ToSlash(rel), mode: info.Mode()})
		return nil
	})
	if err != nil {

		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	h := sha256.New()
	var n [8]byte
	writeField := func(b []byte) {

		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	for _, e := range entries {

		writeField([]byte(e.rel))
		exec := byte(0)
		if e.mode&0o111 != 0 {

			exec = 1
		}
		h.Write([]byte{exec})

		f, err := os.Open(filepath.Join(srcDir, filepath.FromSlash(e.rel)))
		if err != nil {

			return "", err
		}
		info, err := f.Stat()
		if err != nil {

			_ = f.Close()
			return "", err
		}
		binary.BigEndian.PutUint64(n[:], uint64(info.Size()))
		h.Write(n[:])
		if _, err := io.Copy(h, f); err != nil {

			_ = f.Close()
			return "", err
		}
		_ = f.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// StageArtifact copies srcDir into the content-addressed artifact store and
// returns its digest.
//
// Artifacts are immutable and shared: a digest already present is left
// untouched, so a tree used by ten tenants is stored once (§7). Staging goes to
// a temp directory and is renamed into place, so a crash never leaves a partial
// artifact that a later run would adopt as complete.
func (f *FS) StageArtifact(srcDir string) (string, error) {

	sha, err := ArtifactDigest(srcDir)
	if err != nil {

		return "", err
	}
	dst := filepath.Join(f.cfg.ArtifactsDir(), sha)
	if _, err := os.Stat(dst); err == nil {

		return sha, nil

	} else if !os.IsNotExist(err) {

		return "", err
	}
	if err := os.MkdirAll(f.cfg.ArtifactsDir(), 0o700); err != nil {

		return "", err
	}
	tmp, err := os.MkdirTemp(f.cfg.ArtifactsDir(), sha+".tmp-")
	if err != nil {

		return "", err
	}
	defer os.RemoveAll(tmp)

	if err := copyTree(srcDir, tmp); err != nil {

		return "", err
	}
	for _, d := range appSubdirs {

		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {

			return "", err
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {

		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {

		// A concurrent stage of the same content won the race, which is fine:
		// the contents are identical by construction.
		if _, statErr := os.Stat(dst); statErr == nil {

			return sha, nil
		}
		return "", err
	}
	return sha, nil
}

// EmptyArtifact stages the minimal valid app tree: the three subdirectories and
// nothing else. A tenant created without --app-dir gets this.
func (f *FS) EmptyArtifact() (string, error) {

	tmp, err := os.MkdirTemp("", "v2p-empty-")
	if err != nil {

		return "", err
	}
	defer os.RemoveAll(tmp)
	for _, d := range appSubdirs {

		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {

			return "", err
		}
	}
	return f.StageArtifact(tmp)
}

// SwapAppCurrent repoints a tenant's app/current symlink at an artifact.
//
// symlink-to-temp then rename, so the swap is atomic and a reader never sees a
// missing link. The container still has to be recreated afterwards: Docker
// resolves a bind mount's source at create time, so a running container keeps
// the old target (§7).
func (f *FS) SwapAppCurrent(tenantID, sha string) error {

	target := filepath.Join(f.cfg.ArtifactsDir(), sha)
	if _, err := os.Stat(target); err != nil {

		return fmt.Errorf("hostfs: artifact %s is not staged: %w", sha, err)
	}
	link := f.AppCurrent(tenantID)
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {

		return err
	}
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {

		return err
	}
	if err := os.Rename(tmp, link); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Meta is the §7 last-known-good breadcrumb for disaster recovery.
//
// The control-plane database is authoritative; this file exists so that a host
// whose state.db is gone can still be reconstructed by hand. It was once the
// tenant registry, which is why a truncated write bricked every later
// script — here it is written atomically and only ever read as a hint.
type Meta struct {
	TenantID    string    `json:"tenant_id"`
	Slug        string    `json:"slug"`
	Hostname    string    `json:"hostname"`
	PBVersion   string    `json:"pb_version"`
	ImageDigest string    `json:"image_digest"`
	Network     string    `json:"network"`
	Bridge      string    `json:"bridge"`
	Subnet      string    `json:"subnet"`
	ContainerIP string    `json:"container_ip"`
	Artifact    string    `json:"artifact"`
	WrittenAt   time.Time `json:"written_at"`
}

// WriteMeta writes the breadcrumb atomically.
func (f *FS) WriteMeta(m Meta) error {

	m.WrittenAt = time.Now().UTC()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {

		return err
	}
	path := filepath.Join(f.cfg.TenantDir(m.TenantID), "meta.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {

		return err
	}
	if err := os.Rename(tmp, path); err != nil {

		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// OrphanTenantDirs lists tenant directories on disk that no known id claims.
//
// Reported, never deleted: a directory holds a tenant's database, and removing
// one on the strength of a missing row would turn a control-plane bug into
// permanent data loss.
func (f *FS) OrphanTenantDirs(known map[string]bool) ([]string, error) {

	entries, err := os.ReadDir(f.cfg.TenantsDir())
	if err != nil {

		if os.IsNotExist(err) {

			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {

		if e.IsDir() && !known[e.Name()] {

			out = append(out, e.Name())
		}
	}
	return out, nil
}

func copyTree(src, dst string) error {

	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {

		if err != nil {

			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {

			return err
		}
		if rel == "." {

			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {

			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {

			return err
		}
		if !info.Mode().IsRegular() {

			return fmt.Errorf("hostfs: refusing to copy %s (mode %s)", rel, info.Mode())
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {

		return err
	}
	in, err := os.Open(src)
	if err != nil {

		return err
	}
	defer in.Close()
	// Releases are mounted read-only and executed by nothing: drop any
	// executable bit rather than carrying it into the artifact store.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o644)
	if err != nil {

		return err
	}
	if _, err := io.Copy(out, in); err != nil {

		_ = out.Close()
		return err
	}
	return out.Close()
}

// ResolveAppDir makes a user-supplied app directory absolute, accepting a path
// relative to the repository root.
func ResolveAppDir(dir, repoRoot string) (string, error) {

	if dir == "" {

		return "", nil
	}
	if filepath.IsAbs(dir) {

		return dir, nil
	}
	for _, base := range []string{"", repoRoot} {

		candidate := filepath.Join(base, dir)
		if base == "" {

			abs, err := filepath.Abs(dir)
			if err != nil {

				continue
			}
			candidate = abs
		}
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {

			return candidate, nil
		}
	}
	return "", fmt.Errorf("hostfs: app dir %q not found (tried it directly and under %s)", dir, repoRoot)
}
