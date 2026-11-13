package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// checkerFor points a Checker at a test server standing in for the edge.
func checkerFor(t *testing.T, h http.HandlerFunc) *Checker {

	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {

		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return NewChecker(host, p)
}

// The data-plane check presents a token at the version's refresh path and
// needs a fresh token back; no password is involved anywhere.
func TestDataPlaneRefreshesAtTheVersionsPath(t *testing.T) {

	for version, want := range map[string]string{"0.40.4": RefreshPath, "0.22.55": LegacyRefreshPath} {

		var gotPath, gotAuth, gotHost string
		c := checkerFor(t, func(w http.ResponseWriter, r *http.Request) {

			gotPath, gotAuth, gotHost = r.URL.Path, r.Header.Get("Authorization"), r.Host
			_, _ = w.Write([]byte(`{"token":"fresh"}`))
		})
		if err := c.DataPlane(context.Background(), "demo.apps.localhost", version, "signed"); err != nil {

			t.Fatalf("%s: %v", version, err)
		}
		if gotPath != want || gotAuth != "signed" || gotHost != "demo.apps.localhost" {

			t.Errorf("%s: path %q auth %q host %q", version, gotPath, gotAuth, gotHost)
		}
	}
}

func TestDataPlaneFailsWithoutAFreshToken(t *testing.T) {

	for name, h := range map[string]http.HandlerFunc{
		"rejected": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"no token": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) },
	} {

		if err := checkerFor(t, h).DataPlane(context.Background(), "demo.apps.localhost", "0.40.4", "signed"); err == nil {

			t.Errorf("%s: passed", name)
		}
	}
}
