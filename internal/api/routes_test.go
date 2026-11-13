package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// newRouterForTest builds a Server with no collaborators. Nothing here calls a
// handler body; the subject is the routing table itself, which is exactly the
// part that changed when the API moved off http.ServeMux.
func newRouterForTest(t *testing.T) *mux.Router {

	t.Helper()
	s := &Server{router: mux.NewRouter()}
	s.routes()
	return s.router
}

func TestEveryRouteResolves(t *testing.T) {

	r := newRouterForTest(t)
	cases := []struct {
		method, path, wantVar string
	}{
		{http.MethodPost, "/api/v1/admin/tenants", ""},
		{http.MethodGet, "/api/v1/admin/tenants", ""},
		{http.MethodDelete, "/api/v1/admin/tenants/demo", "demo"},
		{http.MethodPost, "/api/v1/admin/tenants/demo/resize", "demo"},
		{http.MethodGet, "/api/v1/admin/fleet", ""},
		{http.MethodPost, "/api/v1/admin/runtime-versions", ""},
		{http.MethodGet, "/api/v1/admin/runtime-versions", ""},
		{http.MethodPost, "/api/v1/admin/runtime-versions/0.40.4/state", ""},
		{http.MethodGet, "/api/v1/admin/upgrades", ""},
		{http.MethodPost, "/api/v1/admin/principals", ""},
		{http.MethodGet, "/api/v1/admin/principals", ""},
		{http.MethodGet, "/api/v1/admin/audit", ""},
		{http.MethodGet, "/api/v1/admin/audit/verify", ""},
		{http.MethodGet, "/api/v1/tenants/demo", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/start", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/stop", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/restart", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/logs", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/owner", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/upgrade", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/upgrade", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/upgrade/uj-1234", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/backups/bk-1234/restore", "demo"},
		{http.MethodPost, "/api/v1/admin/principals/person:alice/password", "person:alice"},
		{http.MethodGet, "/api/v1/admin/grants", ""},
		{http.MethodPost, "/api/v1/admin/grants/g-1234/approve", ""},
		{http.MethodPost, "/api/v1/admin/grants/g-1234/deny", ""},
		{http.MethodPost, "/api/v1/admin/tokens", ""},
		{http.MethodGet, "/api/v1/admin/tokens", ""},
		{http.MethodDelete, "/api/v1/admin/tokens/tk-1234", "tk-1234"},
		{http.MethodPost, "/api/v1/tenants/demo/owner/transfer", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/owner/accept", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/owner/decline", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/owner/cancel", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/releases", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/releases", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/releases/rel-1234", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/releases/rel-1234/download", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/releases/rel-1234/deploy", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/rollback", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/backups", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/backups", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/egress", "demo"},
		{http.MethodGet, "/api/v1/tenants/demo/grants", "demo"},
		{http.MethodPost, "/api/v1/tenants/demo/grants", "demo"},
		{http.MethodDelete, "/api/v1/tenants/demo/grants/g-1234", "demo"},
	}
	for _, c := range cases {

		req := httptest.NewRequest(c.method, c.path, nil)
		var match mux.RouteMatch
		if !r.Match(req, &match) {

			t.Errorf("%s %s does not route (err %v)", c.method, c.path, match.MatchErr)
			continue
		}
		if got := match.Vars["id"]; got != c.wantVar {

			t.Errorf("%s %s bound id=%q, want %q", c.method, c.path, got, c.wantVar)
		}
	}
}

// TestUnroutedRequestsSpeakJSON covers the two paths Gorilla answers itself.
// citadel decodes every response as the apiError envelope, so a plain-text body
// would surface to an operator as a decode failure instead of the real problem.
func TestUnroutedRequestsSpeakJSON(t *testing.T) {

	r := newRouterForTest(t)
	cases := []struct {
		name, method, path string
		wantStatus         int
	}{
		{"unknown path", http.MethodGet, "/api/v1/admin/nope", http.StatusNotFound},
		{"unknown tenant subpath", http.MethodGet, "/api/v1/tenants/demo/nope", http.StatusNotFound},
		{"wrong method", http.MethodPut, "/api/v1/admin/tenants", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {

		t.Run(c.name, func(t *testing.T) {

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
			if w.Code != c.wantStatus {

				t.Fatalf("status = %d, want %d", w.Code, c.wantStatus)
			}
			var body apiError
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {

				t.Fatalf("body %q is not the apiError envelope: %v", w.Body.String(), err)
			}
			if body.Error == "" {

				t.Fatal("apiError.Error is empty")
			}
		})
	}
}

// TestTenantIDsWithDotsSurvive: slugs are [a-z0-9-] but citadel also accepts a
// tenant id, and ids are not constrained to exclude dots. Gorilla's default
// {id} pattern must not stop at one.
func TestTenantIDsWithDotsSurvive(t *testing.T) {

	r := newRouterForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/a.b", nil)
	var match mux.RouteMatch
	if !r.Match(req, &match) {

		t.Fatalf("GET /api/v1/tenants/a.b does not route (err %v)", match.MatchErr)
	}
	if got := match.Vars["id"]; got != "a.b" {

		t.Fatalf("id = %q, want a.b", got)
	}
}
