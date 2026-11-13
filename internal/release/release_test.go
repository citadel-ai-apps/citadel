package release_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

const digest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

func manifest(hosts string) string {

	return `{"schemaVersion":1,"name":"demo","version":"1.0.0",
	  "pocketbase":{"min":"0.38.0","max":"0.40.x"},
	  "egress":[` + hosts + `],
	  "smoke":[{"method":"GET","path":"/fixture/ping","expectStatus":200}]}`
}

func zipPackage(t *testing.T, files map[string]string) ([]byte, int64) {

	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {

		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {

			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {

			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {

		t.Fatal(err)
	}
	return buf.Bytes(), int64(buf.Len())
}

func setup(t *testing.T) (config.Config, *store.DB, *release.Store, store.Tenant) {

	t.Helper()
	ctx := context.Background()

	cfg := config.Default()
	cfg.PBRoot = t.TempDir()
	cfg.AppsDomain = "apps.localhost"
	// config.Load derives this from PBRoot; a Config built by hand has to say so.
	cfg.EdgeAdminDir = filepath.Join(cfg.PBRoot, "caddy", "admin")

	fs := hostfs.New(cfg)
	if err := fs.EnsureLayout(); err != nil {

		t.Fatal(err)
	}
	db, err := store.Open(ctx, cfg.StateDB())
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tn := store.Tenant{
		ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
		DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: digest,
		NetworkName: "t-demo", Subnet: "10.213.1.0/29", GatewayIP: "10.213.1.1",
		EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
		CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB", EncKeyRef: "demo.key",
	}
	err = db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: digest, State: store.VersionCurrent,
		}); err != nil {

			return err
		}
		return store.InsertTenant(ctx, tx, tn)
	})
	if err != nil {

		t.Fatal(err)
	}
	return cfg, db, release.New(cfg, db, fs, auditlog.New()), tn
}

// Two uploads of the same content share one artifact directory (§7: a sha
// shared by ten tenants is stored once) but are still two releases, because a
// release is an event in a tenant's history, not a blob.
func TestIngestDedupesTheArtifactButNotTheRelease(t *testing.T) {

	cfg, db, rel, tn := setup(t)
	ctx := context.Background()
	actor := identity.Platform()

	files := map[string]string{
		"pbapp.json":          manifest(`"api.stripe.com"`),
		"pb_hooks/main.pb.js": "routerAdd('GET','/fixture/ping',e=>e.json(200,{ok:true}))",
	}
	raw, size := zipPackage(t, files)

	first, err := rel.Ingest(ctx, actor, tn, bytes.NewReader(raw), size)
	if err != nil {

		t.Fatal(err)
	}
	second, err := rel.Ingest(ctx, actor, tn, bytes.NewReader(raw), size)
	if err != nil {

		t.Fatal(err)
	}
	if first.Sha256 != second.Sha256 {

		t.Errorf("identical packages produced different artifacts: %s vs %s", first.Sha256, second.Sha256)
	}
	if first.ID == second.ID {

		t.Error("two uploads collapsed into one release row")
	}
	if _, err := os.Stat(filepath.Join(cfg.ArtifactsDir(), first.Sha256, "pb_hooks", "main.pb.js")); err != nil {

		t.Errorf("the hook was not staged: %v", err)
	}
	// §7 keeps the upload for audit: the unpacked tree is what runs, but the
	// bytes the tenant sent are what a later question is about.
	if _, err := os.Stat(filepath.Join(cfg.ArtifactsDir(), first.Sha256+".zip")); err != nil {

		t.Errorf("the original zip was not kept: %v", err)
	}
	if first.EgressHosts != `["api.stripe.com"]` {

		t.Errorf("egress_hosts = %q; the request is recorded even though it grants nothing", first.EgressHosts)
	}

	rows, err := store.ListReleases(ctx, db.Reader(), tn.ID)
	if err != nil || len(rows) != 2 {

		t.Fatalf("ListReleases = %d rows, %v; want 2", len(rows), err)
	}
	// Every mutation carries its audit event (§14.4).
	events, err := auditlog.Select(ctx, db.Reader(), auditlog.Query{TenantID: tn.ID, Action: auditlog.ActionReleaseUploaded})
	if err != nil || len(events) != 2 {

		t.Fatalf("release.uploaded events = %d, %v; want 2", len(events), err)
	}
}

// The tenant's manifest is stored exactly as uploaded, so the portal quotes the
// tenant's own file back at them rather than a re-encoding.
func TestIngestKeepsTheManifestVerbatim(t *testing.T) {

	_, _, rel, tn := setup(t)
	raw, size := zipPackage(t, map[string]string{"pbapp.json": manifest("")})

	row, err := rel.Ingest(context.Background(), identity.Platform(), tn, bytes.NewReader(raw), size)
	if err != nil {

		t.Fatal(err)
	}
	if row.Manifest != manifest("") {

		t.Error("the stored manifest is not the uploaded bytes")
	}
	man, err := release.Manifest(row)
	if err != nil {

		t.Fatal(err)
	}
	if man.Name != "demo" || len(man.Smoke) != 1 {

		t.Errorf("manifest = %+v", man)
	}
}

// A package naming a host that can never be granted is refused at upload, with
// the host in the message (§6).
func TestIngestRefusesADeniedEgressHost(t *testing.T) {

	_, _, rel, tn := setup(t)
	raw, size := zipPackage(t, map[string]string{"pbapp.json": manifest(`"victim.apps.localhost"`)})

	_, err := rel.Ingest(context.Background(), identity.Platform(), tn, bytes.NewReader(raw), size)
	if !errors.Is(err, pkgvalidate.ErrEgressPolicy) {

		t.Fatalf("err = %v, want ErrEgressPolicy", err)
	}
}

// A manifest that no registered runtime satisfies is refused at upload rather
// than at deploy, where it would look like a platform failure.
func TestIngestRefusesAnUnschedulableRange(t *testing.T) {

	_, _, rel, tn := setup(t)
	raw, size := zipPackage(t, map[string]string{
		"pbapp.json": `{"schemaVersion":1,"name":"demo","version":"1","pocketbase":{"min":"0.19.0","max":"0.19.x"}}`,
	})

	_, err := rel.Ingest(context.Background(), identity.Platform(), tn, bytes.NewReader(raw), size)
	if !errors.Is(err, pkgvalidate.ErrNoSupportedRuntime) {

		t.Fatalf("err = %v, want ErrNoSupportedRuntime", err)
	}
}
