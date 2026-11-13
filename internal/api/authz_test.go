package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

const authzDigest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

// authzFixture is a Server over a real store with one tenant, "demo", owned by
// person:owner, and a second principal, person:stranger, with no role on it.
// Each holds a live API token. Nothing here needs Docker: every request either
// stops at the authorisation check or reaches a handler that only reads rows.
type authzFixture struct {
	srv      *Server
	owner    string
	viewer   string
	stranger string
}

func newAuthzFixture(t *testing.T) authzFixture {

	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	audit := auditlog.New()
	ident := identity.New(db.Reader(), audit)
	srv := New(Options{
		DB: db, Identity: ident, Audit: audit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	f := authzFixture{srv: srv}
	err = db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: authzDigest, State: store.VersionCurrent,
		}); err != nil {

			return err
		}
		if err := store.InsertTenant(ctx, tx, store.Tenant{
			ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
			DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: authzDigest,
			NetworkName: "t-demo", Subnet: "10.213.1.0/29",
			GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
			CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB",
			EncKeyRef: "demo.key", CreatedAt: time.Now().UTC(),
		}); err != nil {

			return err
		}
		for _, id := range []string{"owner", "viewer", "stranger"} {

			if _, err := ident.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: id}); err != nil {

				return err
			}
		}
		if err := ident.GrantRole(ctx, tx, identity.Platform(), "demo", "person:owner", identity.RoleOwner); err != nil {

			return err
		}
		if err := ident.GrantRole(ctx, tx, identity.Platform(), "demo", "person:viewer", identity.RoleViewer); err != nil {

			return err
		}
		f.owner = mintToken(ctx, t, tx, "person:owner")
		f.viewer = mintToken(ctx, t, tx, "person:viewer")
		f.stranger = mintToken(ctx, t, tx, "person:stranger")
		return nil
	})
	if err != nil {

		t.Fatal(err)
	}
	return f
}

func mintToken(ctx context.Context, t *testing.T, tx bun.Tx, principal string) string {

	t.Helper()
	row := store.APIToken{
		ID: store.NewID("tk"), PrincipalID: principal, Name: "test",
		CreatedBy: identity.PlatformPrincipal, CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	plaintext, hash := authn.NewToken(row.ID)
	row.Hash = hash
	if err := store.InsertToken(ctx, tx, row); err != nil {

		t.Fatal(err)
	}
	return plaintext
}

func do(h http.Handler, method, path, token string) int {

	return doBody(h, method, path, token, "")
}

// tenantReads is every GET under /tenants/{id}. Logs is listed for the refusal
// cases only: reaching its handler needs a Docker driver.
var tenantReads = []string{
	"/api/v1/tenants/demo",
	"/api/v1/tenants/demo/logs",
	"/api/v1/tenants/demo/owner",
	"/api/v1/tenants/demo/releases",
	"/api/v1/tenants/demo/releases/rel-1",
	"/api/v1/tenants/demo/backups",
	"/api/v1/tenants/demo/upgrade",
	"/api/v1/tenants/demo/upgrade/uj-1",
	"/api/v1/tenants/demo/egress",
	"/api/v1/tenants/demo/grants",
	"/api/v1/tenants/demo/attestation",
	"/api/v1/tenants/demo/access-log",
}

var adminReads = []string{
	"/api/v1/admin/tenants",
	"/api/v1/admin/principals",
	"/api/v1/admin/audit",
	"/api/v1/admin/tokens",
	"/api/v1/admin/grants",
	"/api/v1/admin/fleet",
}

// On the TCP listener a request with no bearer token is refused before the
// router: §8.4 leaves nothing unauthenticated beyond login.
func TestTCPRefusesARequestWithoutAToken(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.APIHandler()
	paths := append(append([]string{}, tenantReads...), adminReads...)
	for _, p := range paths {

		if got := do(h, http.MethodGet, p, ""); got != http.StatusUnauthorized {

			t.Errorf("GET %s without a token = %d, want 401", p, got)
		}
	}
	if got := do(h, http.MethodPost, "/api/v1/tenants/demo/start", ""); got != http.StatusUnauthorized {

		t.Errorf("POST start without a token = %d, want 401", got)
	}
	if got := do(h, http.MethodGet, "/api/v1/tenants/demo", "v2p_tk-nope_secret"); got != http.StatusUnauthorized {

		t.Errorf("GET with a bad token = %d, want 401", got)
	}
}

// A valid token whose principal holds no role on the tenant reads nothing of
// it, and cannot tell it from a tenant that does not exist: a 403 for a real
// tenant next to a 404 for a missing one would let any token holder enumerate
// every slug and id on the platform.
func TestTCPRefusesTenantReadsWithoutARole(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.APIHandler()
	for _, p := range tenantReads {

		if got := do(h, http.MethodGet, p, f.stranger); got != http.StatusNotFound {

			t.Errorf("GET %s as a stranger = %d, want 404", p, got)
		}
		missing := strings.Replace(p, "/tenants/demo", "/tenants/no-such-tenant", 1)
		if got := do(h, http.MethodGet, missing, f.stranger); got != http.StatusNotFound {

			t.Errorf("GET %s = %d, want 404", missing, got)
		}
	}
	for _, p := range []string{"start", "stop", "restart"} {

		if got := do(h, http.MethodPost, "/api/v1/tenants/demo/"+p, f.stranger); got != http.StatusNotFound {

			t.Errorf("POST %s as a stranger = %d, want 404", p, got)
		}
	}
}

// Any role reads the tenant-facing surface; viewer is the floor (§14.1, §14.6).
func TestTCPAllowsTenantReadsWithARole(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.APIHandler()
	for _, tok := range []string{f.owner, f.viewer} {

		for _, p := range []string{
			"/api/v1/tenants/demo/owner",
			"/api/v1/tenants/demo/releases",
			"/api/v1/tenants/demo/backups",
			"/api/v1/tenants/demo/upgrade",
			"/api/v1/tenants/demo/egress",
			"/api/v1/tenants/demo/grants",
			"/api/v1/tenants/demo/access-log",
		} {

			if got := do(h, http.MethodGet, p, tok); got != http.StatusOK {

				t.Errorf("GET %s with a role = %d, want 200", p, got)
			}
		}
	}
	// A viewer cannot deploy, so it cannot start or stop the instance either.
	if got := do(h, http.MethodPost, "/api/v1/tenants/demo/stop", f.viewer); got != http.StatusForbidden {

		t.Errorf("POST stop as a viewer = %d, want 403", got)
	}
}

// /admin is operator-only (§8.4), and the operator boundary is the socket. A
// tenant owner's token is still a tenant credential.
func TestTCPRefusesAdminRoutesToAnyToken(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.APIHandler()
	for _, tok := range []string{f.owner, f.stranger} {

		for _, p := range adminReads {

			if got := do(h, http.MethodGet, p, tok); got != http.StatusForbidden {

				t.Errorf("GET %s with a token = %d, want 403", p, got)
			}
		}
		if got := do(h, http.MethodPost, "/api/v1/admin/tenants", tok); got != http.StatusForbidden {

			t.Errorf("POST /admin/tenants with a token = %d, want 403", got)
		}
	}
}

// The socket keeps its old contract: no credentials needed to read, and the
// header names an operator who holds no role on the tenant.
func TestSocketReadsAreUnchanged(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	for _, p := range []string{
		"/api/v1/admin/tenants",
		"/api/v1/admin/principals",
		"/api/v1/tenants/demo/releases",
		"/api/v1/tenants/demo/egress",
		"/api/v1/tenants/demo/grants",
	} {

		if got := do(h, http.MethodGet, p, ""); got != http.StatusOK {

			t.Errorf("socket GET %s = %d, want 200", p, got)
		}
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set(PrincipalHeader, "person:stranger")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {

			t.Errorf("socket GET %s as an operator with no role = %d, want 200", p, w.Code)
		}
	}
}

func doBody(h http.Handler, method, path, token, body string) int {

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {

		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// Over TCP a reason is not a substitute for the transfer capability: a token
// with no role must not be able to offer the tenant to itself and accept it.
func TestTCPTransferNeedsTheCapabilityEvenWithAReason(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.APIHandler()
	const path = "/api/v1/tenants/demo/owner/transfer"
	// A stranger cannot tell the tenant exists; a viewer can, and is refused.
	refusal := map[string]int{"stranger": http.StatusNotFound, "viewer": http.StatusForbidden}
	for name, tok := range map[string]string{"stranger": f.stranger, "viewer": f.viewer} {

		body := `{"to":"person:` + name + `","reason":"the owner left"}`
		if got := doBody(h, http.MethodPost, path, tok, body); got != refusal[name] {

			t.Errorf("POST transfer as %s with a reason = %d, want %d", name, got, refusal[name])
		}
	}
	if got := doBody(h, http.MethodPost, path, f.owner, `{"to":"person:viewer"}`); got != http.StatusCreated {

		t.Fatalf("POST transfer as the owner = %d, want 201", got)
	}
	// Only the offering side may cancel; the stranger and the viewer may not.
	for name, tok := range map[string]string{"stranger": f.stranger, "viewer": f.viewer} {

		if got := do(h, http.MethodPost, "/api/v1/tenants/demo/owner/cancel", tok); got != refusal[name] {

			t.Errorf("POST cancel as %s = %d, want %d", name, got, refusal[name])
		}
	}
	if got := do(h, http.MethodPost, "/api/v1/tenants/demo/owner/cancel", f.owner); got >= 300 {

		t.Errorf("POST cancel as the owner = %d, want 2xx", got)
	}
}

// On the socket an operator with no role may still reassign a tenant, as long
// as the reason is given.
func TestSocketOperatorTransferWithAReason(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/demo/owner/transfer",
		strings.NewReader(`{"to":"person:viewer","reason":"the owner left"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(PrincipalHeader, "person:stranger")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {

		t.Errorf("socket transfer with a reason = %d, want 201: %s", w.Code, w.Body)
	}
}

// requireCap exempts the platform, so a platform token would be every role on
// every tenant over TCP.
func TestThePlatformCannotHoldAToken(t *testing.T) {

	f := newAuthzFixture(t)
	h := f.srv.SocketHandler()
	for _, id := range []string{"platform", "platform:platform"} {

		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tokens",
			strings.NewReader(`{"principal":"`+id+`","name":"ci"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(PrincipalHeader, "person:owner")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnprocessableEntity {

			t.Errorf("token for %s = %d, want 422: %s", id, w.Code, w.Body)
		}
	}
}

// The role check is on {id}; a sub-resource id from another tenant must not
// ride through it. Before the fix, an owner of demo read other's manifest.
func TestTCPCannotReadAnotherTenantsRelease(t *testing.T) {

	f := newAuthzFixture(t)
	ctx := context.Background()
	err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertTenant(ctx, tx, store.Tenant{
			ID: "other", Slug: "other", Hostname: "other.apps.localhost",
			DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: authzDigest,
			NetworkName: "t-other", Subnet: "10.213.2.0/29",
			GatewayIP: "10.213.2.1", EdgeIP: "10.213.2.2", ContainerIP: "10.213.2.3",
			CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB",
			EncKeyRef: "other.key", CreatedAt: time.Now().UTC(),
		}); err != nil {

			return err
		}
		return store.InsertRelease(ctx, tx, store.Release{
			ID: "rel-other", TenantID: "other", Sha256: "x", Status: "uploaded",
			Manifest: `{"name":"secret-app"}`,
		})
	})
	if err != nil {

		t.Fatal(err)
	}
	h := f.srv.APIHandler()
	if got := do(h, http.MethodGet, "/api/v1/tenants/demo/releases/rel-other", f.owner); got != http.StatusNotFound {

		t.Fatalf("owner of demo reading other's release through demo = %d, want 404", got)
	}
	f.srv.rel = release.New(f.srv.cfg, f.srv.db, nil, f.srv.audit)
	if got := do(h, http.MethodGet, "/api/v1/tenants/demo/releases/rel-other/download", f.owner); got != http.StatusNotFound {

		t.Fatalf("owner of demo downloading other's release through demo = %d, want 404", got)
	}
	// Deploy makes the same check inside the reconciler (ErrWrongTenant),
	// which answers 404 for the same reason; reaching it needs Docker.
	if got := statusFor(reconcile.ErrWrongTenant); got != http.StatusNotFound {

		t.Fatalf("ErrWrongTenant maps to %d, want 404", got)
	}
}

// Every refused token gets the same answer, so a caller holding only a token
// id cannot learn whether it exists, was revoked or expired, or belongs to a
// suspended principal.
func TestRefusedTokensAreIndistinguishable(t *testing.T) {

	f := newAuthzFixture(t)
	ctx := context.Background()
	h := f.srv.APIHandler()
	body := func(tok string) (int, string) {

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/demo", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	idOf := func(tok string) string { return strings.SplitN(tok, "_", 3)[1] }

	var expired, revoked string
	err := f.srv.db.Tx(ctx, func(tx bun.Tx) error {

		revoked = mintToken(ctx, t, tx, "person:viewer")
		if err := store.RevokeToken(ctx, tx, idOf(revoked), identity.PlatformPrincipal); err != nil {

			return err
		}
		row := store.APIToken{
			ID: store.NewID("tk"), PrincipalID: "person:viewer", Name: "old",
			CreatedBy: identity.PlatformPrincipal, CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt: time.Now().UTC().Add(-time.Hour),
		}
		plaintext, hash := authn.NewToken(row.ID)
		row.Hash = hash
		expired = plaintext
		return store.InsertToken(ctx, tx, row)
	})
	if err != nil {

		t.Fatal(err)
	}
	wrongSecret := strings.Join(strings.SplitN(f.owner, "_", 3)[:2], "_") + "_not-the-secret"
	unknown := "v2p_tk-00000000_whatever"
	if !strings.HasPrefix(f.owner, "v2p_") {

		unknown = strings.SplitN(f.owner, "_", 2)[0] + "_tk-00000000_whatever"
	}

	wantCode, wantBody := body(unknown)
	if wantCode != http.StatusUnauthorized {

		t.Fatalf("unknown token = %d, want 401", wantCode)
	}
	for name, tok := range map[string]string{"revoked": revoked, "expired": expired, "wrong secret": wrongSecret} {

		code, b := body(tok)
		if code != wantCode || b != wantBody {

			t.Errorf("%s token answered %d %q; unknown token answered %d %q", name, code, b, wantCode, wantBody)
		}
	}
}
