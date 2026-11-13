package portal

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func getAs(f adminFixture, principal, path string) *httptest.ResponseRecorder {

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: f.sessions.Issue(principal)})
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

// The Releases tab's Download link serves the kept zip to anyone who may
// deploy, and nothing to a viewer.
func TestPortalReleaseDownload(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	f.srv.rel = release.New(f.srv.cfg, f.db, f.srv.fs, f.srv.audit)
	body := []byte("PK\x03\x04 kept upload")
	if err := os.WriteFile(filepath.Join(f.srv.cfg.ArtifactsDir(), "abc.zip"), body, 0o600); err != nil {

		t.Fatal(err)
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertRelease(ctx, tx, store.Release{
			ID: "rel-1", TenantID: "demo", Sha256: "abc", Status: store.ReleaseValidated, Manifest: `{}`,
		})
	}); err != nil {

		t.Fatal(err)
	}

	const path = "/t/demo/releases/rel-1/download"
	rec := getAs(f, "person:admin", path)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), body) {

		t.Fatalf("admin download = %d %q", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "attachment; filename=rel-1.zip" {

		t.Errorf("content-disposition = %q", got)
	}
	if rec := getAs(f, "person:viewer", path); rec.Code != http.StatusForbidden {

		t.Errorf("viewer download = %d, want 403", rec.Code)
	}
	if rec := getAs(f, "person:owner", "/t/demo/releases/rel-nope/download"); rec.Code != http.StatusNotFound {

		t.Errorf("unknown release = %d, want 404", rec.Code)
	}
}
