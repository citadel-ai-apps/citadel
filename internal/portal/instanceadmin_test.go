package portal

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

const adminDigest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

type adminFixture struct {
	srv      *Server
	db       *store.DB
	sessions *authn.Sessions
	dataDir  string
}

// newAdminFixture is a portal over a real store and a real pb_data database in
// the 0.40 shape, with tenant "demo" owned by person:owner. No Docker: the
// handoff only reads files.
func newAdminFixture(t *testing.T) adminFixture {

	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {

		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Default()
	cfg.PBRoot = root
	cfg.EdgeAdminDir = filepath.Join(root, "caddy", "admin")
	fs := hostfs.New(cfg)
	if err := fs.EnsureLayout(); err != nil {

		t.Fatal(err)
	}
	if err := fs.EnsureKeys("demo"); err != nil {

		t.Fatal(err)
	}
	dataDir := fs.DataDir("demo")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {

		t.Fatal(err)
	}
	pb, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "data.db"))
	if err != nil {

		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE _collections (id TEXT PRIMARY KEY, name TEXT, options JSON)`,
		`INSERT INTO _collections VALUES ('pbc_3142635823', '_superusers', '{"authToken":{"secret":"collsecret"}}')`,
		`CREATE TABLE _superusers (id TEXT PRIMARY KEY, email TEXT, tokenKey TEXT, created TEXT)`,
		`INSERT INTO _superusers VALUES ('seat1', '` + pbauth.SeatEmail("demo") + `', 'seatkey', '2026-01-01')`,
	} {

		if _, err := pb.Exec(q); err != nil {

			t.Fatal(err)
		}
	}
	_ = pb.Close()

	sessions, err := authn.LoadSessions(filepath.Join(root, "session.key"), time.Hour)
	if err != nil {

		t.Fatal(err)
	}
	audit := auditlog.New()
	ident := identity.New(db.Reader(), audit)
	srv, err := New(Options{
		Config: cfg, DB: db, FS: fs, Identity: ident, Audit: audit, Sessions: sessions,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {

		t.Fatal(err)
	}

	err = db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, store.RuntimeVersion{
			Version: "0.40.4", HardeningRev: 1, ImageDigest: adminDigest, State: store.VersionCurrent,
		}); err != nil {

			return err
		}
		if err := store.InsertTenant(ctx, tx, store.Tenant{
			ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
			DesiredState: store.DesiredRunning, RuntimeVersion: "0.40.4", ImageDigest: adminDigest,
			NetworkName: "t-demo", Subnet: "10.213.1.0/29",
			GatewayIP: "10.213.1.1", EdgeIP: "10.213.1.2", ContainerIP: "10.213.1.3",
			CPUs: 1, MemMiB: 256, DiskMiB: 2048, BodyCap: "32MB",
			EncKeyRef: "demo.key", CreatedAt: time.Now().UTC(),
		}); err != nil {

			return err
		}
		roles := map[string]string{"owner": identity.RoleOwner, "admin": identity.RoleAdmin, "viewer": identity.RoleViewer}
		for id, role := range roles {

			if _, err := ident.Create(ctx, tx, identity.Platform(), identity.CreateOptions{ID: id}); err != nil {

				return err
			}
			if err := ident.GrantRole(ctx, tx, identity.Platform(), "demo", "person:"+id, role); err != nil {

				return err
			}
		}
		return nil
	})
	if err != nil {

		t.Fatal(err)
	}
	return adminFixture{srv: srv, db: db, sessions: sessions, dataDir: dataDir}
}

func (f adminFixture) post(principal string) *httptest.ResponseRecorder {

	cookie := f.sessions.Issue(principal)
	form := url.Values{"csrf": {f.sessions.CSRFToken(cookie)}}
	req := httptest.NewRequest(http.MethodPost, "/t/demo/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func TestOwnerIsHandedIntoTheAdminUI(t *testing.T) {

	f := newAdminFixture(t)
	rec := f.post("person:owner")
	if rec.Code != http.StatusSeeOther {

		t.Fatalf("status = %d, want 303: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {

		t.Fatal(err)
	}
	if loc.Host != "demo.apps.localhost" || loc.Path != proxyctl.AdminBridgePath {

		t.Fatalf("redirect = %s, want the bridge on the tenant's own hostname", loc)
	}
	// The token travels in the fragment only: never a query a server logs.
	if loc.RawQuery != "" || loc.Fragment == "" {

		t.Fatalf("redirect = %s, want the payload in the fragment and nowhere else", loc)
	}
	raw, err := base64.RawURLEncoding.DecodeString(loc.Fragment)
	if err != nil {

		t.Fatal(err)
	}
	var p struct{ K, V string }
	if err := json.Unmarshal(raw, &p); err != nil {

		t.Fatal(err)
	}
	var entry struct {
		Token  string
		Record struct{ ID, Email string }
	}
	if err := json.Unmarshal([]byte(p.V), &entry); err != nil {

		t.Fatal(err)
	}
	if p.K != "__pb_superusers__/_" || entry.Token == "" || entry.Record.ID != "seat1" {

		t.Fatalf("payload = %s", raw)
	}

	recs, err := auditlog.Select(context.Background(), f.db.Reader(), auditlog.Query{
		TenantID: "demo", Action: auditlog.ActionInstanceAdminOpened,
	})
	if err != nil {

		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ActorID != "person:owner" {

		t.Fatalf("audit = %+v, want one row by person:owner", recs)
	}
	b, _ := json.Marshal(recs[0])
	if strings.Contains(string(b), entry.Token) {

		t.Fatal("the audit row carries the token")
	}
}

func TestOwnerAndAdminGetTheAdminHandoff(t *testing.T) {

	f := newAdminFixture(t)
	for _, principal := range []string{"person:owner", "person:admin"} {

		if rec := f.post(principal); rec.Code != http.StatusSeeOther {

			t.Errorf("%s: status = %d, want 303", principal, rec.Code)
		}
	}
	for _, principal := range []string{"person:viewer", identity.PlatformPrincipal} {

		if rec := f.post(principal); rec.Code != http.StatusForbidden {

			t.Errorf("%s: status = %d, want 403", principal, rec.Code)
		}
	}
}

func TestAdminHandoffExplainsAMissingSeat(t *testing.T) {

	f := newAdminFixture(t)
	pb, err := sql.Open("sqlite", "file:"+filepath.Join(f.dataDir, "data.db"))
	if err != nil {

		t.Fatal(err)
	}
	if _, err := pb.Exec(`DELETE FROM _superusers`); err != nil {

		t.Fatal(err)
	}
	_ = pb.Close()

	rec := f.post("person:owner")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/t/demo?") || !strings.Contains(loc, "re-created") {

		t.Fatalf("status %d, location %q: want back to the tenant page with an explanation", rec.Code, loc)
	}
}
