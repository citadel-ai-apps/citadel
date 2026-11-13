package pkgvalidate_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
)

// entry is one member of a test archive. mode 0 means "an ordinary 0644 file".
type entry struct {
	name string
	body string
	mode os.FileMode
}

const goodManifest = `{
  "schemaVersion": 1,
  "name": "demo",
  "version": "1.0.0",
  "pocketbase": {"min": "0.38.0", "max": "0.40.x"},
  "healthcheck": {"path": "/api/health", "expectStatus": 200},
  "smoke": [{"method": "GET", "path": "/fixture/ping", "expectStatus": 200}]
}`

func build(t *testing.T, entries ...entry) ([]byte, int64) {

	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {

		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {

			h.SetMode(e.mode)

		} else {

			h.SetMode(0o644)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {

			t.Fatal(err)
		}
		if _, err := io.WriteString(w, e.body); err != nil {

			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {

		t.Fatal(err)
	}
	return buf.Bytes(), int64(buf.Len())
}

func validate(t *testing.T, opt pkgvalidate.Options, entries ...entry) (pkgvalidate.Result, error) {

	t.Helper()
	raw, size := build(t, entries...)
	return pkgvalidate.Validate(bytes.NewReader(raw), size, t.TempDir(), opt)
}

func goodPackage() []entry {

	return []entry{
		{name: "pbapp.json", body: goodManifest},
		{name: "pb_hooks/main.pb.js", body: "routerAdd('GET','/fixture/ping',e=>e.json(200,{ok:true}))"},
		{name: "pb_public/index.html", body: "<html><body>hi</body></html>"},
	}
}

func TestAValidPackageUnpacksWithItsManifestParsed(t *testing.T) {

	res, err := validate(t, pkgvalidate.Options{}, goodPackage()...)
	if err != nil {

		t.Fatalf("valid package rejected: %v", err)
	}
	if res.Manifest.Name != "demo" || res.Manifest.PocketBase.Max != "0.40.x" {

		t.Fatalf("manifest = %+v", res.Manifest)
	}
	if !res.HasHooks {

		t.Error("HasHooks = false, want true")
	}
	if len(res.Manifest.Smoke) != 1 {

		t.Errorf("smoke requests = %d, want 1", len(res.Manifest.Smoke))
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "pb_hooks", "main.pb.js")); err != nil {

		t.Errorf("hook not unpacked: %v", err)
	}
	// release.manifest stores the bytes as uploaded, not a re-encoding: the
	// tenant's own formatting is what they see quoted back at them.
	if string(res.Raw) != goodManifest {

		t.Error("Raw is not the manifest as uploaded")
	}
}

// Each case names the §6 checklist row it covers. The assertion is on the
// sentinel AND on the message naming the offending path, because §6 calls this
// a developer-facing product surface.
func TestEveryValidationRuleReturnsItsOwnError(t *testing.T) {

	cases := []struct {
		name    string
		opt     pkgvalidate.Options
		entries []entry
		want    error
		names   string
	}{
		{
			name:    "total size over the cap",
			opt:     pkgvalidate.Options{Limits: pkgvalidate.Limits{MaxUncompressed: 1024, MaxFiles: 10, MaxRatio: 1e9}},
			entries: append(goodPackage(), entry{name: "pb_public/big.txt", body: strings.Repeat("a", 5000)}),
			want:    pkgvalidate.ErrTooLarge,
			names:   "pb_public/big.txt",
		},
		{
			name:    "file count over the cap",
			opt:     pkgvalidate.Options{Limits: pkgvalidate.Limits{MaxUncompressed: 1 << 20, MaxFiles: 2, MaxRatio: 1e9}},
			entries: append(goodPackage(), entry{name: "pb_public/a.txt", body: "a"}),
			want:    pkgvalidate.ErrTooManyFiles,
		},
		{
			name:    "zip bomb",
			opt:     pkgvalidate.Options{},
			entries: append(goodPackage(), entry{name: "pb_public/bomb.bin", body: strings.Repeat("\x00", 4<<20)}),
			want:    pkgvalidate.ErrZipBomb,
		},
		{
			name:    "entry outside the three directories",
			entries: append(goodPackage(), entry{name: "README.md", body: "hi"}),
			want:    pkgvalidate.ErrForeignPath,
			names:   "README.md",
		},
		{
			name:    "parent traversal",
			entries: append(goodPackage(), entry{name: "../escape.js", body: "x"}),
			want:    pkgvalidate.ErrTraversal,
			names:   "../escape.js",
		},
		{
			name:    "absolute path",
			entries: append(goodPackage(), entry{name: "/etc/passwd", body: "x"}),
			want:    pkgvalidate.ErrTraversal,
			names:   "/etc/passwd",
		},
		{
			name:    "symlink",
			entries: append(goodPackage(), entry{name: "pb_public/link", body: "/etc/shadow", mode: os.ModeSymlink | 0o777}),
			want:    pkgvalidate.ErrSymlink,
			names:   "pb_public/link",
		},
		{
			name:    "device node",
			entries: append(goodPackage(), entry{name: "pb_public/null", mode: os.ModeDevice | os.ModeCharDevice | 0o666}),
			want:    pkgvalidate.ErrNodeType,
			names:   "pb_public/null",
		},
		{
			name:    "setuid bit",
			entries: append(goodPackage(), entry{name: "pb_public/tool", body: "x", mode: os.ModeSetuid | 0o644}),
			want:    pkgvalidate.ErrExecBit,
			names:   "pb_public/tool",
		},
		{
			name:    "executable file",
			entries: append(goodPackage(), entry{name: "pb_public/run.sh", body: "#!/bin/sh", mode: 0o755}),
			want:    pkgvalidate.ErrExecBit,
			names:   "pb_public/run.sh",
		},
		{
			name:    "non-js in pb_hooks",
			entries: append(goodPackage(), entry{name: "pb_hooks/notes.txt", body: "x"}),
			want:    pkgvalidate.ErrNonJS,
			names:   "pb_hooks/notes.txt",
		},
		{
			name:    "non-js in pb_migrations",
			entries: append(goodPackage(), entry{name: "pb_migrations/001.ts", body: "x"}),
			want:    pkgvalidate.ErrNonJS,
			names:   "pb_migrations/001.ts",
		},
		{
			name:    "no manifest",
			entries: []entry{{name: "pb_hooks/main.pb.js", body: "//"}},
			want:    pkgvalidate.ErrManifest,
			names:   "pbapp.json",
		},
		{
			name:    "manifest does not parse",
			entries: []entry{{name: "pbapp.json", body: "{"}},
			want:    pkgvalidate.ErrManifest,
			names:   "pbapp.json",
		},
		{
			name:    "unknown schema version",
			entries: []entry{{name: "pbapp.json", body: `{"schemaVersion":2,"name":"x","version":"1"}`}},
			want:    pkgvalidate.ErrManifest,
			names:   "schemaVersion",
		},
		{
			name:    "no name",
			entries: []entry{{name: "pbapp.json", body: `{"schemaVersion":1,"version":"1"}`}},
			want:    pkgvalidate.ErrManifest,
			names:   "name",
		},
		{
			name: "min above max",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","pocketbase":{"min":"0.41.0","max":"0.40.x"}}`}},
			want:  pkgvalidate.ErrRange,
			names: "0.41.0",
		},
		{
			name: "unparseable version",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","pocketbase":{"min":"zero point four"}}`}},
			want:  pkgvalidate.ErrRange,
			names: "zero point four",
		},
		{
			name: "range matches no supported runtime",
			opt:  pkgvalidate.Options{Supported: []string{"0.38.2", "0.40.4"}},
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","pocketbase":{"min":"0.19.0","max":"0.19.x"}}`}},
			want:  pkgvalidate.ErrNoSupportedRuntime,
			names: "0.19.0",
		},
		{
			name: "egress names an IP literal",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","egress":["169.254.169.254"]}`}},
			want:  pkgvalidate.ErrEgressPolicy,
			names: "169.254.169.254",
		},
		{
			name: "egress wildcards a whole TLD",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","egress":["*.com"]}`}},
			want:  pkgvalidate.ErrEgressPolicy,
			names: "*.com",
		},
		{
			name: "egress names a platform domain",
			opt:  pkgvalidate.Options{HostPolicy: pkgvalidate.HostPolicy{PlatformDomains: []string{"apps.localhost"}}},
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","egress":["victim.apps.localhost"]}`}},
			want:  pkgvalidate.ErrEgressPolicy,
			names: "victim.apps.localhost",
		},
		{
			name: "egress names a URL",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","egress":["https://api.stripe.com/v1"]}`}},
			want:  pkgvalidate.ErrEgressPolicy,
			names: "https://api.stripe.com/v1",
		},
		{
			name: "egress repeats a host",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","egress":["api.stripe.com","api.stripe.com"]}`}},
			want:  pkgvalidate.ErrManifest,
			names: "api.stripe.com",
		},
		{
			name: "smoke names a method that is not one",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","smoke":[{"method":"FETCH","path":"/"}]}`}},
			want:  pkgvalidate.ErrManifest,
			names: "FETCH",
		},
		{
			name: "smoke path is not rooted",
			entries: []entry{{name: "pbapp.json",
				body: `{"schemaVersion":1,"name":"x","version":"1","smoke":[{"path":"api/health"}]}`}},
			want:  pkgvalidate.ErrManifest,
			names: "api/health",
		},
	}

	for _, c := range cases {

		t.Run(c.name, func(t *testing.T) {

			_, err := validate(t, c.opt, c.entries...)
			if !errors.Is(err, c.want) {

				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.names != "" && !strings.Contains(err.Error(), c.names) {

				t.Errorf("error %q does not name %q", err, c.names)
			}
		})
	}
}

// A hostile hook must not be able to plant a file outside the package by
// hiding traversal in a directory entry, which the mode check path handles
// separately from the file path.
func TestDirectoryEntriesAreHeldToTheSameRules(t *testing.T) {

	_, err := validate(t, pkgvalidate.Options{},
		entry{name: "pbapp.json", body: goodManifest},
		entry{name: "../outside/", mode: os.ModeDir | 0o755})
	if !errors.Is(err, pkgvalidate.ErrTraversal) {

		t.Fatalf("err = %v, want ErrTraversal", err)
	}
}

func TestAPackageMayContainNothingButAManifest(t *testing.T) {

	// The three directories are created by the artifact stager, so a package
	// with no hooks yet is a legitimate first upload rather than an error.
	res, err := validate(t, pkgvalidate.Options{}, entry{name: "pbapp.json", body: goodManifest})
	if err != nil {

		t.Fatalf("manifest-only package rejected: %v", err)
	}
	if res.HasHooks || res.HasMigrates {

		t.Error("reported hooks or migrations that are not there")
	}
}

func TestAnUnreadableArchiveIsNotAServerError(t *testing.T) {

	body := []byte("this is not a zip file")
	_, err := pkgvalidate.Validate(bytes.NewReader(body), int64(len(body)), t.TempDir(), pkgvalidate.Options{})
	if !errors.Is(err, pkgvalidate.ErrNotZip) {

		t.Fatalf("err = %v, want ErrNotZip", err)
	}
}

// Archive names that are hostile in ways the table above does not spell out:
// Windows separators, a NUL that truncates the name for C code downstream, and
// a second entry under a name already written. Each must be refused, whatever
// error names it.
func TestHostileEntryNamesAreRefused(t *testing.T) {

	for name, entries := range map[string][]entry{
		"backslash traversal": append(goodPackage(), entry{name: "pb_public\\..\\..\\escape.js", body: "x"}),
		"drive letter":        append(goodPackage(), entry{name: "C:/Windows/evil.js", body: "x"}),
		"NUL in the name":     append(goodPackage(), entry{name: "pb_hooks/a.pb.js\x00.txt", body: "x"}),
		"duplicate entry":     append(goodPackage(), entry{name: "pb_public/index.html", body: "<script>x</script>"}),
	} {

		if _, err := validate(t, pkgvalidate.Options{}, entries...); err == nil {

			t.Errorf("%s: package accepted", name)
		}
	}
}
