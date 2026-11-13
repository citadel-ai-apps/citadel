package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Resize is an operator action: it records the new limit and an audit event,
// refuses what create would refuse, and is a no-op when nothing changes.
func TestResizeTenant(t *testing.T) {

	ctx := context.Background()
	f := newAuthzFixture(t)
	f.srv.cfg.TenantRuntime = "runsc"
	sock := f.srv.SocketHandler()
	const path = "/api/v1/admin/tenants/demo/resize"

	if got := doBody(f.srv.APIHandler(), http.MethodPost, path, f.owner, `{"mem_mib":512}`); got != http.StatusForbidden {

		t.Errorf("resize over TCP as the owner = %d, want 403", got)
	}
	for _, body := range []string{`{"mem_mib":64}`, `{"mem_mib":0}`, `{"mem_mib":-1}`} {

		if got := asOperator(sock, path, body); got != http.StatusBadRequest {

			t.Errorf("resize %s = %d, want 400", body, got)
		}
	}
	if got := asOperator(sock, "/api/v1/admin/tenants/nope/resize", `{"mem_mib":512}`); got != http.StatusNotFound {

		t.Errorf("resize of an unknown tenant = %d, want 404", got)
	}

	if got := asOperator(sock, path, `{"mem_mib":512}`); got != http.StatusOK {

		t.Fatalf("resize = %d, want 200", got)
	}
	if got := asOperator(sock, path, `{"mem_mib":512}`); got != http.StatusOK {

		t.Fatalf("repeat resize = %d, want 200", got)
	}
	tn, err := store.GetTenant(ctx, f.srv.db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	if tn.MemMiB != 512 {

		t.Errorf("mem_mib = %d, want 512", tn.MemMiB)
	}
	n, err := f.srv.db.Reader().NewSelect().Table("audit_event").
		Where("action = ?", auditlog.ActionTenantResized).Count(ctx)
	if err != nil {

		t.Fatal(err)
	}
	if n != 1 {

		t.Errorf("%d resize audit events, want 1 (the repeat changed nothing)", n)
	}
}

// asOperator posts on the socket the way citadel does, naming an operator who
// holds no role on the tenant.
func asOperator(h http.Handler, path, body string) int {

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PrincipalHeader, "person:stranger")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}
