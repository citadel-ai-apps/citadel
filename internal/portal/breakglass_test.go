package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/breakglass"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

const oncallPassword = "correct horse battery staple"

// withOperators adds two named operators, person:oncall (with a portal
// password) and person:second, and returns their actors.
func withOperators(t *testing.T, f adminFixture) (oncall, second identity.Actor) {

	t.Helper()
	ctx := context.Background()
	hash, err := authn.HashPassword(oncallPassword)
	if err != nil {

		t.Fatal(err)
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		for _, id := range []string{"oncall", "second"} {

			if _, err := f.srv.ident.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: id}); err != nil {

				return err
			}
			if err := f.srv.ident.SetOperator(ctx, tx, identity.Platform(), "person:"+id, true); err != nil {

				return err
			}
		}
		return store.SetCredential(ctx, tx, store.PrincipalCredential{
			PrincipalID: "person:oncall", Algo: authn.Algo, Hash: hash,
		})
	}); err != nil {

		t.Fatal(err)
	}
	for _, id := range []string{"person:oncall", "person:second"} {

		a, err := f.srv.ident.ResolveActor(ctx, id)
		if err != nil {

			t.Fatal(err)
		}
		if !a.CanBreakglass() {

			t.Fatalf("%s resolved without the operator flag: %+v", id, a)
		}
		if id == "person:oncall" {

			oncall = a

		} else {

			second = a
		}
	}
	return oncall, second
}

func openFor(t *testing.T, f adminFixture, actor identity.Actor, kind, scope string) store.Grant {

	t.Helper()
	tenant, err := store.GetTenant(context.Background(), f.db.Reader(), "demo")
	if err != nil {

		t.Fatal(err)
	}
	g, err := f.srv.bg.Open(context.Background(), actor, tenant, breakglass.Request{
		Reason: "incident 42: restore check", Kind: kind, Scope: scope,
	})
	if err != nil {

		t.Fatal(err)
	}
	return g
}

func refused(rec interface {
	Result() *http.Response
}) bool {

	res := rec.Result()
	return res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound ||
		(res.StatusCode == http.StatusSeeOther && strings.Contains(res.Header.Get("Location"), "err="))
}

// A named operator opens break-glass from the portal, with their password:
// the grant, its audit event and both notices land together, and the
// operator is sent to the tenant's page.
func TestOperatorOpensBreakglassFromThePortal(t *testing.T) {

	f := newAdminFixture(t)
	withOperators(t, f)
	ctx := context.Background()

	open := func(principal, password string) *http.Response {

		return postAs(f, principal, "/attestations/demo/breakglass", url.Values{
			"reason": {"incident 42"}, "kind": {store.GrantOperatorDataAccess}, "password": {password},
		}, true).Result()
	}
	// The wrong password, an operator with no password, and a stolen cookie
	// alone all open nothing.
	for _, c := range []struct{ principal, password string }{
		{"person:oncall", "wrong"}, {"person:oncall", ""}, {"person:second", oncallPassword},
	} {

		if res := open(c.principal, c.password); !strings.Contains(res.Header.Get("Location"), "err=") {

			t.Errorf("open as %s with %q = %d %q, want refused", c.principal, c.password, res.StatusCode, res.Header.Get("Location"))
		}
	}
	if gs, _ := store.BreakglassGrants(ctx, f.db.Reader(), "demo"); len(gs) != 0 {

		t.Fatalf("refused opens left grants: %+v", gs)
	}

	res := open("person:oncall", oncallPassword)
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/t/demo?") || strings.Contains(loc, "err=") {

		t.Fatalf("open = %d %q, want the tenant page", res.StatusCode, loc)
	}
	gs, err := store.BreakglassGrants(ctx, f.db.Reader(), "demo")
	if err != nil || len(gs) != 1 {

		t.Fatalf("grants = %+v, %v", gs, err)
	}
	g := gs[0]
	if g.RequestedBy != "person:oncall" || g.DecidedBy != "person:oncall" || g.Subject != "pb_data" ||
		g.ExpiresAt.Sub(g.RequestedAt) != store.BreakglassTTL {

		t.Errorf("grant = %+v", g)
	}
	if recs, _ := auditlog.Select(ctx, f.db.Reader(), auditlog.Query{TenantID: "demo", Action: auditlog.ActionBreakglassOpened}); len(recs) != 1 {

		t.Errorf("opened audit rows = %d, want 1", len(recs))
	}
	for _, audience := range []string{store.AudienceTenant, store.AudienceOperator} {

		ns, _ := store.ListNotifications(ctx, f.db.Reader(), store.NotificationFilter{TenantID: "demo", Audience: audience})
		if len(ns) != 1 || !strings.Contains(ns[0].Body, "incident 42") {

			t.Errorf("%s notices = %+v", audience, ns)
		}
		// The tenant is told what the session can do, not only that it exists.
		if audience == store.AudienceTenant && len(ns) == 1 && !strings.Contains(ns[0].Body, "change and delete records") {

			t.Errorf("tenant notice does not say the session is read-write: %q", ns[0].Body)
		}
	}
}

// An open data-access session resolves the tenant with a read-only role and
// opens the admin handoff with a token that cannot outlive it; mutating
// routes stay shut.
func TestBreakglassOpensTheTenantReadOnly(t *testing.T) {

	f := newAdminFixture(t)
	oncall, _ := withOperators(t, f)
	ctx := context.Background()

	if _, err := f.srv.resolveTenant(ctx, oncall, "demo"); err == nil {

		t.Fatal("an operator with no session resolved the tenant")
	}
	g := openFor(t, f, oncall, "", "")

	a, err := f.srv.resolveTenant(ctx, oncall, "demo")
	if err != nil || a.Role != identity.RoleBreakglassData || a.Breakglass == nil || a.Breakglass.ID != g.ID {

		t.Fatalf("resolve = %+v, %v", a, err)
	}

	for _, path := range []string{
		"/t/demo/restart", "/t/demo/backup", "/t/demo/deploy", "/t/demo/rollback", "/t/demo/upload",
		"/t/demo/owner/transfer", "/t/demo/owner/accept", "/t/demo/owner/cancel", "/t/demo/upgrade",
	} {

		if rec := postAs(f, "person:oncall", path, url.Values{"release": {"rel-1"}, "to": {"person:oncall"}}, true); !refused(rec) {

			t.Errorf("POST %s under break-glass = %d %q, want refused", path, rec.Code, rec.Header().Get("Location"))
		}
	}

	rec := f.post("person:oncall")
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "#") {

		t.Fatalf("handoff = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	claims := handoffClaims(t, rec.Header().Get("Location"))
	if claims["refreshable"] != false {

		t.Errorf("break-glass admin token is refreshable: %v", claims)
	}
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if d := time.Until(exp); d <= 0 || d > maxBreakglassAdmin || exp.After(g.ExpiresAt) {

		t.Errorf("token exp %v (in %v), session ends %v", exp, d, g.ExpiresAt)
	}

	reads, _ := auditlog.Select(ctx, f.db.Reader(), auditlog.Query{TenantID: "demo", Action: auditlog.ActionDataRead})
	if len(reads) != 1 || reads[0].ActorID != "person:oncall" || reads[0].SubjectRef != "grant/"+g.ID {

		t.Errorf("data reads = %+v, want one tied to %s", reads, g.ID)

	} else if reads[0].Detail["access"] != "superuser, read-write" {

		t.Errorf("handoff audit detail = %v, want it to say the session is read-write", reads[0].Detail)
	}
	if opened, _ := auditlog.Select(ctx, f.db.Reader(), auditlog.Query{TenantID: "demo", Action: auditlog.ActionInstanceAdminOpened}); len(opened) != 0 {

		t.Errorf("break-glass handoff audited as the owner's door: %+v", opened)
	}
}

// handoffClaims decodes the JWT claims from the bridge URL's fragment.
func handoffClaims(t *testing.T, location string) map[string]any {

	t.Helper()
	u, err := url.Parse(location)
	if err != nil {

		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil {

		t.Fatal(err)
	}
	var p struct{ K, V string }
	if err := json.Unmarshal(raw, &p); err != nil {

		t.Fatal(err)
	}
	var entry struct{ Token string }
	if err := json.Unmarshal([]byte(p.V), &entry); err != nil {

		t.Fatal(err)
	}
	parts := strings.Split(entry.Token, ".")
	if len(parts) != 3 {

		t.Fatalf("token = %q", entry.Token)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {

		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {

		t.Fatal(err)
	}
	return claims
}

// support_impersonation, or a scope narrower than pb_data, is the pages only.
func TestBreakglassViewHasNoAdminHandoff(t *testing.T) {

	f := newAdminFixture(t)
	oncall, second := withOperators(t, f)
	ctx := context.Background()
	openFor(t, f, oncall, store.GrantSupportImpersonate, "")
	openFor(t, f, second, store.GrantOperatorDataAccess, "bk-123")

	for _, a := range []identity.Actor{oncall, second} {

		got, err := f.srv.resolveTenant(ctx, a, "demo")
		if err != nil || got.Role != identity.RoleBreakglassView {

			t.Errorf("%s resolve = %+v, %v; want the view role", a.ID, got, err)
		}
		if rec := f.post(a.ID); rec.Code != http.StatusForbidden {

			t.Errorf("%s handoff = %d, want 403", a.ID, rec.Code)
		}
	}
}

// Access ends on the next request when the session is closed, when it runs
// out, and when the operator flag is cleared.
func TestBreakglassAccessEnds(t *testing.T) {

	ctx := context.Background()

	t.Run("closed", func(t *testing.T) {

		f := newAdminFixture(t)
		oncall, _ := withOperators(t, f)
		g := openFor(t, f, oncall, "", "")
		rec := postAs(f, "person:oncall", "/breakglass/"+g.ID+"/close", nil, true)
		if strings.Contains(rec.Header().Get("Location"), "err=") {

			t.Fatalf("close = %q", rec.Header().Get("Location"))
		}
		if _, err := f.srv.resolveTenant(ctx, oncall, "demo"); err == nil {

			t.Error("tenant still resolves after close")
		}
		if rec := f.post("person:oncall"); rec.Code != http.StatusForbidden {

			t.Errorf("handoff after close = %d, want 403", rec.Code)
		}
		ns, _ := store.ListNotifications(ctx, f.db.Reader(), store.NotificationFilter{TenantID: "demo", Audience: store.AudienceTenant})
		closed := false
		for _, n := range ns {

			closed = closed || n.Kind == store.NotifyBreakglassClosed
		}
		if !closed {

			t.Errorf("the tenant was not told of the close: %+v", ns)
		}
	})

	t.Run("expired", func(t *testing.T) {

		f := newAdminFixture(t)
		oncall, _ := withOperators(t, f)
		past := time.Now().UTC().Add(-2 * time.Hour)
		if err := f.db.Tx(ctx, func(tx bun.Tx) error {

			return store.InsertGrant(ctx, tx, store.Grant{
				ID: "g-old", TenantID: "demo", Kind: store.GrantOperatorDataAccess, Direction: store.DirectionInbound,
				Subject: "pb_data", Tier: 3, Decision: store.DecisionApproved,
				RequestedBy: oncall.ID, RequestedAt: past, DecidedBy: oncall.ID, DecidedAt: &past,
				ExpiresAt: past.Add(store.BreakglassTTL),
			})
		}); err != nil {

			t.Fatal(err)
		}
		if _, err := f.srv.resolveTenant(ctx, oncall, "demo"); err == nil {

			t.Error("an expired session resolves the tenant")
		}
	})

	t.Run("flag cleared", func(t *testing.T) {

		f := newAdminFixture(t)
		oncall, _ := withOperators(t, f)
		openFor(t, f, oncall, "", "")
		if err := f.db.Tx(ctx, func(tx bun.Tx) error {

			return f.srv.ident.SetOperator(ctx, tx, identity.Platform(), oncall.ID, false)
		}); err != nil {

			t.Fatal(err)
		}
		if rec := f.post("person:oncall"); rec.Code != http.StatusForbidden {

			t.Errorf("handoff after the flag was cleared = %d, want 403", rec.Code)
		}
	})
}

// The platform principal never holds break-glass, even if a row names it.
func TestPlatformNeverHoldsBreakglass(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		return store.InsertGrant(ctx, tx, store.Grant{
			ID: "g-plat", TenantID: "demo", Kind: store.GrantOperatorDataAccess, Direction: store.DirectionInbound,
			Subject: "pb_data", Tier: 3, Decision: store.DecisionApproved,
			RequestedBy: identity.PlatformPrincipal, RequestedAt: now, DecidedBy: identity.PlatformPrincipal, DecidedAt: &now,
			ExpiresAt: now.Add(store.BreakglassTTL),
		})
	}); err != nil {

		t.Fatal(err)
	}
	if _, err := f.srv.resolveTenant(ctx, identity.Platform(), "demo"); err == nil {

		t.Error("the platform principal resolved a tenant through break-glass")
	}
}

// The review is someone else's, and only once; the tenant cannot revoke a
// session, an operator closes it.
func TestBreakglassReviewAndRevoke(t *testing.T) {

	f := newAdminFixture(t)
	oncall, _ := withOperators(t, f)
	ctx := context.Background()
	g := openFor(t, f, oncall, "", "")

	review := url.Values{"outcome": {"justified"}, "notes": {"restore check, as stated"}}
	if rec := postAs(f, "person:oncall", "/breakglass/"+g.ID+"/review", review, true); !strings.Contains(rec.Header().Get("Location"), "err=") {

		t.Errorf("self-review = %q, want refused", rec.Header().Get("Location"))
	}
	if rec := postAs(f, "person:second", "/breakglass/"+g.ID+"/review", review, true); strings.Contains(rec.Header().Get("Location"), "err=") {

		t.Fatalf("review by second = %q", rec.Header().Get("Location"))
	}
	if r, err := store.GetReview(ctx, f.db.Reader(), g.ID); err != nil || r.ReviewedBy != "person:second" {

		t.Errorf("review = %+v, %v", r, err)
	}
	if rec := postAs(f, "person:second", "/breakglass/"+g.ID+"/review", review, true); !strings.Contains(rec.Header().Get("Location"), "err=") {

		t.Errorf("second review = %q, want refused", rec.Header().Get("Location"))
	}

	rec := postAs(f, "person:owner", "/t/demo/grants/"+g.ID+"/revoke", nil, true)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {

		t.Errorf("tenant revoke of break-glass = %q, want refused", rec.Header().Get("Location"))
	}
	if got, _ := store.GetGrant(ctx, f.db.Reader(), g.ID); got.RevokedAt != nil {

		t.Error("the tenant revoked a break-glass session")
	}
}

// The access page offers the open form to a named operator and not to the
// shared platform login; the project list shows an operator their sessions.
func TestBreakglassSurfacesInThePortal(t *testing.T) {

	f := newAdminFixture(t)
	oncall, _ := withOperators(t, f)
	const form = `action="/attestations/demo/breakglass"`

	rec := getAs(f, "person:oncall", "/attestations")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), form) {

		t.Fatalf("GET /attestations as operator = %d, want the open form:\n%s", rec.Code, rec.Body)
	}
	if rec := getAs(f, identity.PlatformPrincipal, "/attestations"); strings.Contains(rec.Body.String(), form) {

		t.Error("the platform login is offered break-glass")
	}

	g := openFor(t, f, oncall, "", "")
	rec = getAs(f, "person:oncall", "/")
	if body := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(body, g.ID) ||
		!strings.Contains(body, `action="/breakglass/`+g.ID+`/close"`) {

		t.Errorf("GET / as operator = %d, want the open session with its close form:\n%s", rec.Code, body)
	}
	// The session awaits review by somebody else: the opener is not offered it.
	rec = getAs(f, "person:oncall", "/attestations")
	if strings.Contains(rec.Body.String(), `action="/breakglass/`+g.ID+`/review"`) {

		t.Error("the opener is offered the review of their own session")
	}
	rec = getAs(f, "person:second", "/attestations")
	if !strings.Contains(rec.Body.String(), `action="/breakglass/`+g.ID+`/review"`) {

		t.Error("another operator is not offered the review")
	}
	// The review comes after access has started; nothing on the page may read
	// as though the session were waiting for someone to let it in.
	body := rec.Body.String()
	if !strings.Contains(body, "nobody approves it first") || !strings.Contains(body, "access open now") ||
		strings.Contains(body, "Awaiting review") {

		t.Error("the access page presents the after-the-fact review as an approval step")
	}
}

// §14.4 audits impersonation: the first view of the tenant's pages under a
// support_impersonation session is a row on the tenant's Access tab, once per
// session however often the page is reloaded. A data session's views are not
// impersonation; its open event and its reads are what it records.
func TestImpersonationIsAuditedOncePerSession(t *testing.T) {

	f := newAdminFixture(t)
	f.srv.rec = reconcile.New(reconcile.Options{DB: f.db})
	oncall, second := withOperators(t, f)
	ctx := context.Background()
	support := openFor(t, f, oncall, store.GrantSupportImpersonate, "")
	openFor(t, f, second, store.GrantOperatorDataAccess, "")

	for range 3 {

		for _, who := range []string{"person:oncall", "person:second"} {

			if rec := getAs(f, who, "/t/demo?tab=access"); rec.Code != http.StatusOK {

				t.Fatalf("GET /t/demo as %s = %d: %s", who, rec.Code, rec.Body)
			}
		}
	}
	recs, err := auditlog.Select(ctx, f.db.Reader(), auditlog.Query{TenantID: "demo", Action: auditlog.ActionImpersonationStarted})
	if err != nil {

		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ActorID != "person:oncall" || recs[0].SubjectRef != "grant/"+support.ID {

		t.Fatalf("impersonation rows = %+v, want one by person:oncall for %s", recs, support.ID)
	}
	ns, _ := store.ListNotifications(ctx, f.db.Reader(), store.NotificationFilter{TenantID: "demo", Audience: store.AudienceTenant})
	for _, n := range ns {

		if n.SubjectRef == "grant/"+support.ID && !strings.Contains(n.Body, "read-only") {

			t.Errorf("support session notice = %q, want it to say read-only", n.Body)
		}
	}
}
