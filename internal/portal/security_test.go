package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/identity"
)

// hxTag matches an element that fetches with htmx, up to the end of its tag.
var hxTag = regexp.MustCompile(`<[a-z]+[^>]*\shx-(?:get|post)="[^"]*"[^>]*>`)

// A response swapped in as HTML is HTML insertion, whatever Content-Type the
// handler set. Every htmx fetch therefore names its swap, and a swap that
// inserts markup must also hx-select from a page the portal rendered itself —
// never a raw body such as container output, which is what put a tenant's
// console.log into an operator's session.
func TestEveryHtmxFetchSwapsSafely(t *testing.T) {

	entries, err := assets.ReadDir("templates")
	if err != nil {

		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {

		raw, err := assets.ReadFile("templates/" + e.Name())
		if err != nil {

			t.Fatal(err)
		}
		// Tags can span lines in the templates; join them first.
		body := strings.Join(strings.Fields(string(raw)), " ")
		for _, tag := range hxTag.FindAllString(body, -1) {

			found++
			switch {

			case strings.Contains(tag, `hx-swap="textContent"`):
			case strings.Contains(tag, `hx-swap="none"`):
			case strings.Contains(tag, `hx-swap=`) && strings.Contains(tag, `hx-select=`):
			default:
				t.Errorf("%s: htmx fetch inserts its response as HTML: %s", e.Name(), tag)
			}
		}
	}
	if found == 0 {

		t.Fatal("no htmx fetches found; the pattern no longer matches the templates")
	}
}

// Inline script would need 'unsafe-inline' in the policy, which is the one
// thing the policy exists to refuse.
func TestTemplatesCarryNoInlineScript(t *testing.T) {

	inline := regexp.MustCompile(`(?i)\son[a-z]+=|<script>|<script\s+(?:[^>]*\s)?type=|javascript:|\sstyle=`)
	entries, err := assets.ReadDir("templates")
	if err != nil {

		t.Fatal(err)
	}
	for _, e := range entries {

		raw, err := assets.ReadFile("templates/" + e.Name())
		if err != nil {

			t.Fatal(err)
		}
		if m := inline.FindString(string(raw)); m != "" {

			t.Errorf("%s carries inline script or style (%q); the CSP forbids it", e.Name(), m)
		}
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {

	f := newAdminFixture(t)
	for _, path := range []string{"/login", "/static/app.css", "/no/such/page", "/"} {

		rec := httptest.NewRecorder()
		f.srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		h := rec.Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {

			t.Errorf("%s: Content-Security-Policy = %q", path, csp)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {

			t.Errorf("%s: policy allows framing: %q", path, csp)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {

			t.Errorf("%s: X-Content-Type-Options = %q", path, got)
		}
		if got := h.Get("X-Frame-Options"); got != "DENY" {

			t.Errorf("%s: X-Frame-Options = %q", path, got)
		}
	}
}

// The admin handoff is a form post that redirects to the tenant's hostname,
// and browsers apply form-action to that redirect.
func TestPolicyLetsTheAdminHandoffRedirect(t *testing.T) {

	csp := contentSecurityPolicy("apps.example.com")
	if !strings.Contains(csp, "form-action 'self' http://*.apps.example.com https://*.apps.example.com") {

		t.Fatalf("form-action does not cover the apps domain: %q", csp)
	}
}

func TestSafeNextKeepsTheRedirectOnThisOrigin(t *testing.T) {

	for in, want := range map[string]string{
		"":                       "/",
		"/t/demo":                "/t/demo",
		"/t/demo?tab=snapshots":  "/t/demo?tab=snapshots",
		"//evil.example":         "/",
		"/\\evil.example":        "/",
		"https://evil.example/":  "/",
		"evil.example":           "/",
		"/\t/evil.example":       "/",
		"/%0d%0aSet-Cookie:x=y":  "/%0d%0aSet-Cookie:x=y", // stays a path on this origin
		"javascript:alert(1)":    "/",
		"/ok\\..\\..\\evil":      "/",
		"///evil.example/path":   "/",
		"/@evil.example":         "/@evil.example",
		"/foo//bar":              "/foo//bar",
		"/\r\n/evil.example":     "/",
		"\\\\evil.example":       "/",
		"/.\\./evil.example":     "/",
		"/a/../../evil.example/": "/a/../../evil.example/",
	} {

		if got := safeNext(in); got != want {

			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// postAs submits a form to the portal as principal, with or without a valid
// CSRF token in the body.
func postAs(f adminFixture, principal, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {

	cookie := f.sessions.Issue(principal)
	if form == nil {

		form = url.Values{}
	}
	if withCSRF {

		form.Set("csrf", f.sessions.CSRFToken(cookie))
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func TestPostWithoutTheCSRFTokenIsRefused(t *testing.T) {

	f := newAdminFixture(t)
	if rec := postAs(f, "person:owner", "/t/demo/restart", nil, false); rec.Code != http.StatusForbidden {

		t.Fatalf("POST without a token = %d, want 403", rec.Code)
	}
	// A token in the query string is not accepted: it leaks through logs,
	// history and Referer.
	cookie := f.sessions.Issue("person:owner")
	req := httptest.NewRequest(http.MethodPost, "/t/demo/restart?csrf="+url.QueryEscape(f.sessions.CSRFToken(cookie)), nil)
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {

		t.Fatalf("POST with the token in the query = %d, want 403", rec.Code)
	}
}

// Parsing the form to read the CSRF field happens before any role check, so
// the body has to be capped before that parse.
func TestOversizedPostIsRefusedBeforeTheHandler(t *testing.T) {

	f := newAdminFixture(t)
	big := url.Values{"pad": {strings.Repeat("x", formBodyLimit+1)}}
	if rec := postAs(f, "person:viewer", "/t/demo/restart", big, true); rec.Code != http.StatusForbidden {

		t.Fatalf("oversized POST = %d, want it refused", rec.Code)
	}
}

// Withdrawing a transfer offer is the owner's call, in the portal as over the
// API; a viewer is refused and the offer stays open.
func TestViewerCannotWithdrawATransferOffer(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		owner := identity.Actor{ID: "person:owner", Kind: identity.KindPerson}
		_, err := f.srv.ident.OfferTransfer(ctx, tx, owner, "demo", "person:admin", "")
		return err
	}); err != nil {

		t.Fatal(err)
	}
	postAs(f, "person:viewer", "/t/demo/owner/cancel", nil, true)
	if _, open, err := f.srv.ident.PendingTransfer(ctx, "demo"); err != nil || !open {

		t.Fatalf("a viewer withdrew the owner's transfer offer (open=%v, err=%v)", open, err)
	}
	postAs(f, "person:owner", "/t/demo/owner/cancel", nil, true)
	if _, open, _ := f.srv.ident.PendingTransfer(ctx, "demo"); open {

		t.Fatal("the owner could not withdraw their own offer")
	}
}

// On-demand attestation is operator-only (§8.4).
type countingAttestor struct{ calls int }

func (c *countingAttestor) Generate(context.Context, string) (attest.Report, error) {

	c.calls++
	return attest.Report{}, nil
}
