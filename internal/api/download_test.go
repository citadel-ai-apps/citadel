package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// seedDownload gives the fixture a release store and a release on demo whose
// kept zip is body.
func seedDownload(t *testing.T, f authzFixture, body []byte) {

	t.Helper()
	ctx := context.Background()
	f.srv.cfg.PBRoot = t.TempDir()
	f.srv.rel = release.New(f.srv.cfg, f.srv.db, nil, f.srv.audit)
	if err := os.MkdirAll(f.srv.cfg.ArtifactsDir(), 0o700); err != nil {

		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.srv.cfg.ArtifactsDir(), "abc.zip"), body, 0o600); err != nil {

		t.Fatal(err)
	}
	err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertRelease(ctx, tx, store.Release{
			ID: "rel-1", TenantID: "demo", Sha256: "abc", Status: store.ReleaseValidated, Manifest: `{}`,
		})
	})
	if err != nil {

		t.Fatal(err)
	}
}

func TestReleaseDownloadServesTheZipToADeployer(t *testing.T) {

	f := newAuthzFixture(t)
	body := []byte("PK\x03\x04 not really a zip")
	seedDownload(t, f, body)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/demo/releases/rel-1/download", nil)
	req.Header.Set("Authorization", "Bearer "+f.owner)
	w := httptest.NewRecorder()
	f.srv.APIHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), body) {

		t.Fatalf("owner download = %d %q", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Disposition"); got != "attachment; filename=rel-1.zip" {

		t.Errorf("content-disposition = %q", got)
	}
}

// Downloading is gated on deploy: a viewer can read the manifest but not the
// code; a principal with no role is told the tenant does not exist.
func TestReleaseDownloadNeedsDeploy(t *testing.T) {

	f := newAuthzFixture(t)
	seedDownload(t, f, []byte("zip"))
	h := f.srv.APIHandler()
	const path = "/api/v1/tenants/demo/releases/rel-1/download"
	if got := do(h, http.MethodGet, path, f.viewer); got != http.StatusForbidden {

		t.Errorf("viewer = %d, want 403", got)
	}
	if got := do(h, http.MethodGet, path, f.stranger); got != http.StatusNotFound {

		t.Errorf("stranger = %d, want 404", got)
	}
	if got := do(h, http.MethodGet, "/api/v1/tenants/demo/releases/rel-nope/download", f.owner); got != http.StatusNotFound {

		t.Errorf("unknown release = %d, want 404", got)
	}
	if err := os.Remove(filepath.Join(f.srv.cfg.ArtifactsDir(), "abc.zip")); err != nil {

		t.Fatal(err)
	}
	if got := do(h, http.MethodGet, path, f.owner); got != http.StatusNotFound {

		t.Errorf("zip gone from disk = %d, want 404", got)
	}
}
