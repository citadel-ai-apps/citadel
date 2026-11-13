package hostfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

func testFS(t *testing.T) *FS {

	t.Helper()
	cfg := config.Default()
	cfg.PBRoot = t.TempDir()
	cfg.EdgeAdminDir = filepath.Join(cfg.PBRoot, "caddy", "admin")
	f := New(cfg)
	if err := f.EnsureLayout(); err != nil {

		t.Fatal(err)
	}
	return f
}

func writeTree(t *testing.T, files map[string]string) string {

	t.Helper()
	dir := t.TempDir()
	for name, body := range files {

		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {

			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {

			t.Fatal(err)
		}
	}
	return dir
}

func TestArtifactDigestIsStableAcrossIdenticalTrees(t *testing.T) {

	files := map[string]string{
		"pbapp.json":           `{"name":"demo"}`,
		"pb_hooks/main.pb.js":  "routerAdd('GET','/x',()=>{})",
		"pb_public/index.html": "<h1>hi</h1>",
	}
	a, err := ArtifactDigest(writeTree(t, files))
	if err != nil {

		t.Fatal(err)
	}
	b, err := ArtifactDigest(writeTree(t, files))
	if err != nil {

		t.Fatal(err)
	}
	if a != b {

		t.Fatalf("identical trees hashed differently: %s vs %s", a, b)
	}
	if len(a) != 64 {

		t.Fatalf("digest %q is not a sha256 hex string", a)
	}
}

func TestArtifactDigestChangesWithContentPathAndMode(t *testing.T) {

	base := map[string]string{"pb_hooks/main.pb.js": "one"}
	ref, err := ArtifactDigest(writeTree(t, base))
	if err != nil {

		t.Fatal(err)
	}

	// Different content.
	changed, err := ArtifactDigest(writeTree(t, map[string]string{"pb_hooks/main.pb.js": "two"}))
	if err != nil {

		t.Fatal(err)
	}
	if changed == ref {

		t.Error("changing a file's content did not change the digest")
	}

	// Same content, different path — the digest commits to the path, because
	// PocketBase loads by directory and filename.
	moved, err := ArtifactDigest(writeTree(t, map[string]string{"pb_hooks/other.pb.js": "one"}))
	if err != nil {

		t.Fatal(err)
	}
	if moved == ref {

		t.Error("moving a file did not change the digest")
	}

	// Same content and path, executable bit set.
	dir := writeTree(t, base)
	if err := os.Chmod(filepath.Join(dir, "pb_hooks/main.pb.js"), 0o755); err != nil {

		t.Fatal(err)
	}
	execMode, err := ArtifactDigest(dir)
	if err != nil {

		t.Fatal(err)
	}
	if execMode == ref {

		t.Error("setting the executable bit did not change the digest")
	}
}

// TestArtifactDigestRejectsNonRegularFiles: internal/pkgvalidate rejects
// symlinks at upload, and refusing them here too means a hand-placed fixture
// cannot smuggle one past.
func TestArtifactDigestRejectsSymlinks(t *testing.T) {

	dir := writeTree(t, map[string]string{"pb_hooks/main.pb.js": "one"})
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "pb_hooks", "sneaky.js")); err != nil {

		t.Skipf("cannot create a symlink here: %v", err)
	}
	if _, err := ArtifactDigest(dir); err == nil {

		t.Fatal("a tree containing a symlink was hashed")
	}
}

func TestStageArtifactDedupesAndMaterialisesTheThreeSubdirs(t *testing.T) {

	f := testFS(t)
	files := map[string]string{"pb_hooks/main.pb.js": "one"}

	sha, err := f.StageArtifact(writeTree(t, files))
	if err != nil {

		t.Fatal(err)
	}
	dst := filepath.Join(f.cfg.ArtifactsDir(), sha)
	// All three exist even when empty: the image entrypoint points its
	// --hooksDir/--publicDir/--migrationsDir flags at them, and PocketBase logs
	// a startup error for any that are missing.
	for _, d := range appSubdirs {

		if st, err := os.Stat(filepath.Join(dst, d)); err != nil || !st.IsDir() {

			t.Errorf("%s was not materialised: %v", d, err)
		}
	}
	body, err := os.ReadFile(filepath.Join(dst, "pb_hooks", "main.pb.js"))
	if err != nil || string(body) != "one" {

		t.Fatalf("content not copied: %q %v", body, err)
	}

	// Content-addressed and immutable: the same tree from ten tenants is stored
	// once (§7).
	again, err := f.StageArtifact(writeTree(t, files))
	if err != nil {

		t.Fatal(err)
	}
	if again != sha {

		t.Fatalf("restaging the same content produced %s, want %s", again, sha)
	}
	entries, err := os.ReadDir(f.cfg.ArtifactsDir())
	if err != nil {

		t.Fatal(err)
	}
	if len(entries) != 1 {

		t.Fatalf("artifact store holds %d entries, want 1", len(entries))
	}
}

func TestStageArtifactLeavesNoTempDirectoryBehind(t *testing.T) {

	f := testFS(t)
	if _, err := f.StageArtifact(writeTree(t, map[string]string{"a.js": "x"})); err != nil {

		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.cfg.ArtifactsDir())
	if err != nil {

		t.Fatal(err)
	}
	for _, e := range entries {

		if filepath.Ext(e.Name()) == ".tmp" || len(e.Name()) != 64 {

			t.Fatalf("artifact store contains %q; staging must rename into place atomically", e.Name())
		}
	}
}

func TestSwapAppCurrentIsAtomicAndRepointable(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureTenantDirs("demo"); err != nil {

		t.Fatal(err)
	}
	first, err := f.StageArtifact(writeTree(t, map[string]string{"pb_hooks/main.pb.js": "v1"}))
	if err != nil {

		t.Fatal(err)
	}
	second, err := f.StageArtifact(writeTree(t, map[string]string{"pb_hooks/main.pb.js": "v2"}))
	if err != nil {

		t.Fatal(err)
	}

	if err := f.SwapAppCurrent("demo", first); err != nil {

		t.Fatal(err)
	}
	assertLink(t, f.AppCurrent("demo"), filepath.Join(f.cfg.ArtifactsDir(), first))

	// Rollback is repointing at the previous sha (§7). No temp link may survive.
	if err := f.SwapAppCurrent("demo", second); err != nil {

		t.Fatal(err)
	}
	assertLink(t, f.AppCurrent("demo"), filepath.Join(f.cfg.ArtifactsDir(), second))
	if _, err := os.Lstat(f.AppCurrent("demo") + ".tmp"); !os.IsNotExist(err) {

		t.Fatal("a temporary symlink survived the swap")
	}
}

func assertLink(t *testing.T, link, want string) {

	t.Helper()
	got, err := os.Readlink(link)
	if err != nil {

		t.Fatal(err)
	}
	if got != want {

		t.Fatalf("app/current -> %s, want %s", got, want)
	}
}

func TestSwapAppCurrentRefusesAnUnstagedArtifact(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureTenantDirs("demo"); err != nil {

		t.Fatal(err)
	}
	if err := f.SwapAppCurrent("demo", "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {

		t.Fatal("app/current was pointed at an artifact that is not staged")
	}
}

func TestEmptyArtifactHasOnlyTheThreeSubdirs(t *testing.T) {

	f := testFS(t)
	sha, err := f.EmptyArtifact()
	if err != nil {

		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(f.cfg.ArtifactsDir(), sha))
	if err != nil {

		t.Fatal(err)
	}
	if len(entries) != len(appSubdirs) {

		t.Fatalf("the empty artifact holds %d entries, want %d", len(entries), len(appSubdirs))
	}
}

func TestEnsureKeysGeneratesTheExactKeyLengthPocketBaseRequires(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	key, err := f.EncryptionKey("demo")
	if err != nil {

		t.Fatal(err)
	}
	// Exactly 32 characters. PocketBase's --encryptionEnv rejects anything else,
	// so this is not a parameter to tune upward.
	if len(key) != 32 {

		t.Fatalf("encryption key is %d chars, want exactly 32", len(key))
	}

	st, err := os.Stat(filepath.Join(f.cfg.KeysDir(), EncKeyRef("demo")))
	if err != nil {

		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {

		t.Errorf("encryption key has mode %v, want 0600", st.Mode().Perm())
	}
}

// No PocketBase superuser password is stored: the owner opens /_/ through the
// portal and the health check signs its own token. A file left by an earlier
// control plane is removed, and removing it twice is not an error.
func TestNoSuperuserPasswordIsStored(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	legacy := filepath.Join(f.cfg.KeysDir(), legacySuCredRef("demo"))
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {

		t.Fatalf("EnsureKeys wrote %s (err = %v)", legacy, err)
	}
	if err := os.WriteFile(legacy, []byte("admin-demo@example.invalid:pw\n"), 0o600); err != nil {

		t.Fatal(err)
	}
	for range 2 {

		if err := f.RemoveLegacySuperuserCredential("demo"); err != nil {

			t.Fatal(err)
		}
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {

		t.Fatalf("%s survived removal (err = %v)", legacy, err)
	}
}

// TestEnsureKeysIsIdempotent: regenerating the encryption key would make the
// existing pb_data settings undecryptable.
func TestEnsureKeysIsIdempotent(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	first, err := f.EncryptionKey("demo")
	if err != nil {

		t.Fatal(err)
	}
	if err := f.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	second, err := f.EncryptionKey("demo")
	if err != nil {

		t.Fatal(err)
	}
	if first != second {

		t.Fatal("EnsureKeys rotated an existing encryption key; pb_data settings would become unreadable")
	}
}

func TestKeysAreUniquePerTenant(t *testing.T) {

	f := testFS(t)
	for _, id := range []string{"a", "b"} {

		if err := f.EnsureKeys(id); err != nil {

			t.Fatal(err)
		}
	}
	ka, _ := f.EncryptionKey("a")
	kb, _ := f.EncryptionKey("b")
	if ka == kb {

		t.Fatal("two tenants share an encryption key; a stolen key must be useless elsewhere")
	}
}

func TestOrphanTenantDirsReportsUnknownDirectories(t *testing.T) {

	f := testFS(t)
	for _, id := range []string{"known", "stray"} {

		if err := f.EnsureTenantDirs(id); err != nil {

			t.Fatal(err)
		}
	}
	got, err := f.OrphanTenantDirs(map[string]bool{"known": true})
	if err != nil {

		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "stray" {

		t.Fatalf("orphans = %v, want [stray]", got)
	}
	// Reported, never deleted: the directory holds a database.
	if _, err := os.Stat(filepath.Join(f.cfg.TenantsDir(), "stray")); err != nil {

		t.Fatal("the orphan directory was removed; data must never be GC'd on a guess")
	}
}

func TestWriteMetaIsAtomicAndReadable(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureTenantDirs("demo"); err != nil {

		t.Fatal(err)
	}
	if err := f.WriteMeta(Meta{TenantID: "demo", Slug: "demo", PBVersion: "0.40.4"}); err != nil {

		t.Fatal(err)
	}
	path := filepath.Join(f.cfg.TenantDir("demo"), "meta.json")
	if _, err := os.Stat(path); err != nil {

		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {

		t.Fatal("a temporary meta.json survived the write")
	}
}

func TestLockIsExclusiveAndReleases(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureTenantDirs("demo"); err != nil {

		t.Fatal(err)
	}
	lock, err := f.Lock("demo")
	if err != nil {

		t.Fatal(err)
	}
	// Within one process flock is per-descriptor, so a second open must fail:
	// this is what stops the 5 s tick and a concurrent API call from both
	// acting on a tenant.
	if _, err := f.Lock("demo"); err == nil {

		t.Fatal("a second lock was granted while the first was held")
	}
	lock.Release()
	again, err := f.Lock("demo")
	if err != nil {

		t.Fatalf("the lock was not released: %v", err)
	}
	again.Release()
	// Release is idempotent, because it is called from a defer and from the
	// success path.
	again.Release()
}

func TestLocksAreIndependentPerTenant(t *testing.T) {

	f := testFS(t)
	for _, id := range []string{"a", "b"} {

		if err := f.EnsureTenantDirs(id); err != nil {

			t.Fatal(err)
		}
	}
	la, err := f.Lock("a")
	if err != nil {

		t.Fatal(err)
	}
	defer la.Release()
	lb, err := f.Lock("b")
	if err != nil {

		t.Fatalf("locking tenant b while a is held: %v", err)
	}
	lb.Release()
}

func TestResolveAppDirAcceptsRepoRelativePaths(t *testing.T) {

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "test", "fixtures", "basic-hook"), 0o755); err != nil {

		t.Fatal(err)
	}
	got, err := ResolveAppDir("test/fixtures/basic-hook", repo)
	if err != nil {

		t.Fatal(err)
	}
	if got != filepath.Join(repo, "test", "fixtures", "basic-hook") {

		t.Fatalf("resolved to %s", got)
	}
	if _, err := ResolveAppDir("nope/nowhere", repo); err == nil {

		t.Fatal("a nonexistent app dir resolved")
	}
}

// TestPurgeRemovesKeysAndDirectory covers the operator-requested purge path.
// The default is to retain (D10); this is what --purge does.
func TestPurgeRemovesKeysAndDirectory(t *testing.T) {

	f := testFS(t)
	if err := f.EnsureTenantDirs("demo"); err != nil {

		t.Fatal(err)
	}
	if err := f.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	if err := f.RemoveTenantDir("demo"); err != nil {

		t.Fatal(err)
	}
	if _, err := os.Stat(f.cfg.TenantDir("demo")); !os.IsNotExist(err) {

		t.Fatal("the tenant directory survived the purge")
	}
	if err := f.RemoveKeys("demo"); err != nil {

		t.Fatal(err)
	}
	if _, err := f.EncryptionKey("demo"); err == nil {

		t.Fatal("the encryption key survived the purge")
	}
	// Idempotent: teardown has to be re-runnable after a crash.
	if err := f.RemoveKeys("demo"); err != nil {

		t.Fatalf("RemoveKeys is not idempotent: %v", err)
	}
	if err := f.RemoveTenantDir("demo"); err != nil {

		t.Fatalf("RemoveTenantDir is not idempotent: %v", err)
	}
}
