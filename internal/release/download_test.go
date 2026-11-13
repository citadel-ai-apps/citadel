package release_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// A download hands back the exact bytes the tenant uploaded, and says so in
// the audit log.
func TestDownloadReturnsTheUploadedZip(t *testing.T) {

	cfg, db, rel, tn := setup(t)
	ctx := context.Background()
	raw, size := zipPackage(t, map[string]string{
		"pbapp.json":          manifest(""),
		"pb_hooks/main.pb.js": "routerAdd('GET','/x',e=>e.json(200,{}))",
	})
	row, err := rel.Ingest(ctx, identity.Platform(), tn, bytes.NewReader(raw), size)
	if err != nil {

		t.Fatal(err)
	}

	d, err := rel.OpenDownload(ctx, identity.Platform(), tn, row.ID)
	if err != nil {

		t.Fatal(err)
	}
	if d.Name != row.ID+".zip" {

		t.Errorf("name = %q", d.Name)
	}
	rec := httptest.NewRecorder()
	d.Serve(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), raw) {

		t.Fatalf("served %d, %d bytes; want 200 and the %d uploaded bytes", rec.Code, rec.Body.Len(), len(raw))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {

		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename=`+row.ID+`.zip` {

		t.Errorf("content-disposition = %q", cd)
	}
	events, err := auditlog.Select(ctx, db.Reader(), auditlog.Query{TenantID: tn.ID, Action: auditlog.ActionReleaseDownloaded})
	if err != nil || len(events) != 1 {

		t.Fatalf("release.downloaded events = %d, %v; want 1", len(events), err)
	}

	// The zip gone from disk is a not-found, not a 500 or an empty body.
	if err := os.Remove(filepath.Join(cfg.ArtifactsDir(), row.Sha256+".zip")); err != nil {

		t.Fatal(err)
	}
	if _, err := rel.OpenDownload(ctx, identity.Platform(), tn, row.ID); !errors.Is(err, release.ErrUploadMissing) {

		t.Fatalf("missing zip: err = %v, want ErrUploadMissing", err)
	}
}

// Another tenant's release id is answered exactly like an unknown one.
func TestDownloadRefusesAnotherTenantsRelease(t *testing.T) {

	_, _, rel, tn := setup(t)
	ctx := context.Background()
	raw, size := zipPackage(t, map[string]string{"pbapp.json": manifest("")})
	row, err := rel.Ingest(ctx, identity.Platform(), tn, bytes.NewReader(raw), size)
	if err != nil {

		t.Fatal(err)
	}
	other := tn
	other.ID = "other"
	d, err := rel.OpenDownload(ctx, identity.Platform(), other, row.ID)
	if !errors.Is(err, store.ErrReleaseNotFound) {

		if err == nil {

			_ = d.File.Close()
		}
		t.Fatalf("err = %v, want ErrReleaseNotFound", err)
	}
	if _, err := rel.OpenDownload(ctx, identity.Platform(), tn, "rel-nope"); !errors.Is(err, store.ErrReleaseNotFound) {

		t.Fatalf("unknown id: err = %v, want ErrReleaseNotFound", err)
	}
}
