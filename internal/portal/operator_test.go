package portal

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// withRelease gives the fixture's tenant a downloadable release, rel-1.
func withRelease(t *testing.T, f adminFixture) (path string, body []byte) {

	t.Helper()
	ctx := context.Background()
	f.srv.rel = release.New(f.srv.cfg, f.db, f.srv.fs, f.srv.audit)
	body = []byte("PK\x03\x04 kept upload")
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
	return "/t/demo/releases/rel-1/download", body
}

// The platform principal is a principal like any other in the portal: with no
// role on a tenant it gets the same "no such tenant" as a stranger, on every
// /t/ route, read or write (§14: platform access to tenant data is
// break-glass, never standing).
func TestPlatformCannotOpenATenantItHasNoRoleOn(t *testing.T) {

	f := newAdminFixture(t)
	download, _ := withRelease(t, f)

	for _, path := range []string{"/t/demo", "/t/demo?tab=access", "/t/demo/logs", download, "/t/demo/upgrade/j1"} {

		rec := getAs(f, identity.PlatformPrincipal, path)
		if rec.Code == http.StatusOK {

			t.Errorf("GET %s as platform = 200, want refused", path)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("PK\x03\x04")) {

			t.Errorf("GET %s as platform served the release", path)
		}
	}
	// The refusal is the one a stranger gets, so it says nothing about
	// whether the tenant exists.
	stranger := getAs(f, identity.PlatformPrincipal, "/t/no-such-tenant")
	if rec := getAs(f, identity.PlatformPrincipal, "/t/demo"); rec.Code != stranger.Code ||
		!strings.Contains(rec.Body.String(), store.ErrTenantNotFound.Error()) {

		t.Errorf("GET /t/demo as platform = %d %q, want the not-found answer (%d)", rec.Code, rec.Body, stranger.Code)
	}

	for _, path := range []string{"/t/demo/restart", "/t/demo/backup", "/t/demo/deploy", "/t/demo/rollback"} {

		// Handlers refuse either outright or by redirecting with the error;
		// what none may do is succeed.
		rec := postAs(f, identity.PlatformPrincipal, path, url.Values{"release": {"rel-1"}}, true)
		refused := rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound ||
			(rec.Code == http.StatusSeeOther && strings.Contains(rec.Header().Get("Location"), "err="))
		if !refused {

			t.Errorf("POST %s as platform = %d %q, want refused", path, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// Custody is a real role row, and a real role row works for the platform as it
// does for anyone (§14.1): the fix removes the bypass, not the platform.
func TestPlatformWithARoleSeesTheTenant(t *testing.T) {

	f := newAdminFixture(t)
	path, body := withRelease(t, f)
	ctx := context.Background()
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		return f.srv.ident.GrantRole(ctx, tx, identity.Platform(), "demo", identity.PlatformPrincipal, identity.RoleDeployer)
	}); err != nil {

		t.Fatal(err)
	}
	rec := getAs(f, identity.PlatformPrincipal, path)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), body) {

		t.Fatalf("download as platform with a role = %d %q", rec.Code, rec.Body)
	}
}

func TestOnlyAnOperatorAttestsOnDemand(t *testing.T) {

	f := newAdminFixture(t)
	att := &countingAttestor{}
	f.srv.attest = att

	postAs(f, "person:owner", "/attestations/demo/check", nil, true)
	if att.calls != 0 {

		t.Fatal("a tenant owner triggered an on-demand attestation")
	}
	// The operator needs no role on the tenant to make the host re-check it,
	// and lands back on its own page, not the tenant's.
	rec := postAs(f, identity.PlatformPrincipal, "/attestations/demo/check", nil, true)
	if att.calls != 1 {

		t.Fatalf("operator re-check ran %d times, want 1", att.calls)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/attestations?") || strings.Contains(loc, "err=") {

		t.Errorf("operator re-check redirect = %q", loc)
	}
	// The old tenant-page route is gone.
	if rec := postAs(f, identity.PlatformPrincipal, "/t/demo/attest", nil, true); rec.Code != http.StatusNotFound {

		t.Errorf("POST /t/demo/attest = %d, want 404", rec.Code)
	}
}

// INV-16: a Tier-2 decision, a break-glass session and its review each need a
// named person. The portal's operator is the shared platform principal, which
// names nobody, so none of the three has a portal route; they are citadel
// commands on the socket, where the actor is the human at the terminal.
func TestPortalDecidesNoGrantAndOpensNoBreakglass(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	pending := store.Grant{
		ID: "g-t2", TenantID: "demo", Kind: store.GrantEgressHost, Direction: store.DirectionOutbound,
		Subject: "*.example.com", Tier: 2, Decision: store.DecisionPending,
		RequestedBy: "person:owner", RequestedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error { return store.InsertGrant(ctx, tx, pending) }); err != nil {

		t.Fatal(err)
	}

	for _, principal := range []string{identity.PlatformPrincipal, "person:owner"} {

		for _, path := range []string{
			"/grants/g-t2/approve", "/grants/g-t2/deny",
			"/attestations/demo/breakglass", "/t/demo/breakglass", "/breakglass/g-t2/review",
		} {

			rec := postAs(f, principal, path, url.Values{
				"reason": {"because"}, "outcome": {"justified"}, "notes": {"fine"},
			}, true)
			if rec.Code != http.StatusNotFound {

				t.Errorf("POST %s as %s = %d, want 404", path, principal, rec.Code)
			}
		}
	}
	g, err := store.GetGrant(ctx, f.db.Reader(), "g-t2")
	if err != nil {

		t.Fatal(err)
	}
	if g.Decision != store.DecisionPending {

		t.Errorf("Tier-2 grant decided through the portal: %s by %s", g.Decision, g.DecidedBy)
	}
	bg, err := store.ListGrants(ctx, f.db.Reader(), store.GrantFilter{
		TenantID: "demo", Kind: store.GrantOperatorDataAccess,
	})
	if err != nil {

		t.Fatal(err)
	}
	if len(bg) != 0 {

		t.Errorf("break-glass opened through the portal: %+v", bg)
	}
}

func TestAccessPageListsProjectsForTheOperatorOnly(t *testing.T) {

	f := newAdminFixture(t)
	rec := getAs(f, identity.PlatformPrincipal, "/attestations")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/attestations/demo/check"`) {

		t.Fatalf("GET /attestations as platform = %d, want the project row for demo:\n%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `href="/t/demo"`) {

		t.Error("the operator Access page links to a tenant page the operator cannot open")
	}
	if rec := getAs(f, "person:owner", "/attestations"); rec.Code != http.StatusForbidden {

		t.Errorf("GET /attestations as owner = %d, want 403", rec.Code)
	}
}

// Tier 1 is granted by the platform with nobody in the loop, so the
// Approvals page lists it: recent rows only, and only to someone who may see
// the tenant.
func TestApprovalsPageShowsTier1Grants(t *testing.T) {

	f := newAdminFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	tier1 := func(id, subject string, at time.Time) store.Grant {

		return store.Grant{
			ID: id, TenantID: "demo", Kind: store.GrantEgressHost, Direction: store.DirectionOutbound,
			Subject: subject, Tier: 1, Decision: store.DecisionAutoApproved,
			RequestedBy: "person:owner", RequestedAt: at, DecidedBy: identity.PlatformPrincipal, DecidedAt: &at,
			ExpiresAt: at.Add(90 * 24 * time.Hour),
		}
	}
	grants := []store.Grant{
		tier1("g-t1", "api.recent.example", now),
		tier1("g-t1-old", "api.stale.example", old),
	}
	if err := f.db.Tx(ctx, func(tx bun.Tx) error {

		for _, g := range grants {

			if err := store.InsertGrant(ctx, tx, g); err != nil {

				return err
			}
		}
		_, err := f.srv.ident.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: "stranger"})
		return err
	}); err != nil {

		t.Fatal(err)
	}

	for _, principal := range []string{identity.PlatformPrincipal, "person:viewer"} {

		rec := getAs(f, principal, "/grants")
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, "api.recent.example") {

			t.Errorf("GET /grants as %s = %d, want the recent Tier-1 grant:\n%s", principal, rec.Code, body)
		}
		if strings.Contains(body, "api.stale.example") {

			t.Errorf("GET /grants as %s lists a Tier-1 grant older than the window", principal)
		}
	}
	rec := getAs(f, "person:stranger", "/grants")
	if strings.Contains(rec.Body.String(), "api.recent.example") {

		t.Errorf("GET /grants as a person with no role on demo lists its Tier-1 grant")
	}
}
