package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The socket's 0600 mode is the authorisation boundary, so X-V2P-Principal
// there is attribution. On a TCP listener the same header would be free
// impersonation of any principal, including the platform — so it is stripped
// before the router sees it, and the request arrives with no actor at all.
func TestThePrincipalHeaderIsIgnoredOnATCPListener(t *testing.T) {

	s := &Server{}
	var sawHeader string
	var hadActor bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {

		sawHeader = req.Header.Get(PrincipalHeader)
		_, hadActor = ActorFrom(req.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/fleet", nil)
	req.Header.Set(PrincipalHeader, "platform")
	s.authenticate(next, false).ServeHTTP(httptest.NewRecorder(), req)

	if sawHeader != "" {

		t.Errorf("the handler saw %s = %q on a TCP listener", PrincipalHeader, sawHeader)
	}
	if hadActor {

		t.Error("a header-only request was authenticated on a TCP listener")
	}
}

// On the socket, a request with no credentials at all reaches the handler, which
// then answers 400 through identity.ErrNoActor if it needs an actor. Failing in
// the middleware instead would make the socket's anonymous read endpoints
// (fleet, status) unreachable. The TCP listener refuses it: see authz_test.go.
func TestAnUnauthenticatedSocketRequestIsNotRejectedByTheMiddleware(t *testing.T) {

	s := &Server{}
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	w := httptest.NewRecorder()
	s.authenticate(next, true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/admin/fleet", nil))

	if !reached {

		t.Error("the middleware swallowed a request with no credentials")
	}
	if w.Code != http.StatusOK {

		t.Errorf("status = %d, want the handler's own answer", w.Code)
	}
}

func TestBearerParsing(t *testing.T) {

	cases := []struct {
		header string
		want   string
	}{
		{"Bearer v2p_tk-1_secret", "v2p_tk-1_secret"},
		{"bearer v2p_tk-1_secret", "v2p_tk-1_secret"},
		{"Basic dXNlcjpwdw==", ""},
		{"Bearer", ""},
		{"", ""},
	}
	for _, c := range cases {

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {

			req.Header.Set("Authorization", c.header)
		}
		got, ok := bearer(req)
		if (c.want == "") == ok {

			t.Errorf("bearer(%q) ok = %v, want %v", c.header, ok, c.want != "")
			continue
		}
		if got != c.want {

			t.Errorf("bearer(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}
