package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func TestThrottleWindowSlides(t *testing.T) {

	now := time.Unix(1_000_000, 0)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }
	k := throttleKey{"principal", "person:owner"}
	for range failuresPerPrincipal {

		if !th.allowed(k) {

			t.Fatal("refused inside the budget")
		}
		th.fail(k)
	}
	if th.allowed(k) {

		t.Fatal("allowed past the budget")
	}
	now = now.Add(throttleWindow + time.Second)
	if !th.allowed(k) {

		t.Fatal("still refused after the window passed")
	}
}

func login(f adminFixture, principal, password, remote string) *httptest.ResponseRecorder {

	form := url.Values{"principal": {principal}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

// After the budget of failures, even the right password is refused for the
// rest of the window, and the refusals stop adding rows to the audit chain.
func TestLoginIsThrottledPerPrincipal(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	const good = "correct horse battery staple"
	hash, err := authn.HashPassword(good)
	if err != nil {

		t.Fatal(err)
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		return store.SetCredential(ctx, tx, store.PrincipalCredential{
			PrincipalID: "person:owner", Algo: authn.Algo, Hash: hash,
		})
	}); err != nil {

		t.Fatal(err)
	}
	for i := range failuresPerPrincipal {

		// Different source addresses: the per-principal budget is what trips.
		login(f, "owner", "wrong password", "192.0.2."+string(rune('1'+i%9))+":4000")
	}
	auditBefore := countLoginFailures(t, f)

	rec := login(f, "owner", good, "198.51.100.7:4000")
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "too+many") {

		t.Fatalf("the right password after %d failures was let through: %d %s", failuresPerPrincipal, rec.Code, loc)
	}
	for range 5 {

		login(f, "owner", "wrong password", "198.51.100.7:4000")
	}
	if after := countLoginFailures(t, f); after != auditBefore {

		t.Fatalf("throttled attempts wrote %d audit rows", after-auditBefore)
	}
	if rec := login(f, "viewer", "wrong password", "198.51.100.8:4000"); strings.Contains(rec.Header().Get("Location"), "too+many") {

		t.Fatal("one principal's failures throttled another")
	}
}

func countLoginFailures(t *testing.T, f adminFixture) int {

	t.Helper()
	var n int
	if err := f.db.Reader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_event WHERE action = 'auth.login.failed'`).Scan(&n); err != nil {

		t.Fatal(err)
	}
	return n
}

// Signing out ends the session server-side: a copy of the cookie taken before
// sign-out no longer opens a page. A password change does the same.
func TestSignOutAndPasswordChangeEndCopiedSessions(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	setPassword := func(pw string) {

		hash, err := authn.HashPassword(pw)
		if err != nil {

			t.Fatal(err)
		}
		if err := f.db.Tx(ctx, func(tx bun.Tx) error {

			return store.SetCredential(ctx, tx, store.PrincipalCredential{PrincipalID: "person:owner", Algo: authn.Algo, Hash: hash})
		}); err != nil {

			t.Fatal(err)
		}
	}
	const pw = "correct horse battery staple"
	setPassword(pw)

	cookieFrom := func(rec *httptest.ResponseRecorder) string {

		for _, c := range rec.Result().Cookies() {

			if c.Name == authn.SessionCookie && c.Value != "" {

				return c.Value
			}
		}
		t.Fatalf("no session cookie in %v", rec.Result().Cookies())
		return ""
	}
	page := func(cookie string) int {

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		f.srv.router.ServeHTTP(rec, req)
		return rec.Code
	}

	copied := cookieFrom(login(f, "owner", pw, "198.51.100.1:1"))
	if got := page(copied); got != http.StatusOK {

		t.Fatalf("fresh session = %d, want 200", got)
	}
	form := url.Values{"csrf": {f.sessions.CSRFToken(copied)}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: copied})
	f.srv.router.ServeHTTP(httptest.NewRecorder(), req)
	if got := page(copied); got != http.StatusSeeOther {

		t.Fatalf("a cookie copied before sign-out still opens pages: %d", got)
	}

	again := cookieFrom(login(f, "owner", pw, "198.51.100.1:1"))
	setPassword("another long passphrase")
	if got := page(again); got != http.StatusSeeOther {

		t.Fatalf("a session from before the password change still opens pages: %d", got)
	}
}

func TestSecureCookiesUseTheHostPrefix(t *testing.T) {

	f := newAdminFixture(t)
	f.srv.cfg.PortalSecureCookies = true
	rec := httptest.NewRecorder()
	f.srv.setCookie(rec, "v")
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-"+authn.SessionCookie || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {

		t.Fatalf("secure session cookie = %+v", c)
	}
}
