package portal

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func templates(t *testing.T) *template.Template {

	t.Helper()
	tpl, err := template.New("portal").Funcs(funcs()).ParseFS(assets, "templates/*.html")
	if err != nil {

		t.Fatal(err)
	}
	return tpl
}

// Templates are compiled at parse time but only *type-checked* at execution, so
// a wrong field name is a blank page at runtime and nothing at build time. This
// renders every page with representative data, which is the only thing that
// catches it before a tenant does.
func TestEveryTemplateRenders(t *testing.T) {

	tpl := templates(t)
	now := time.Now().UTC()
	deployed := now.Add(-time.Hour)

	tenant := store.Tenant{
		ID: "demo", Slug: "demo", Hostname: "demo.apps.localhost",
		RuntimeVersion: "0.40.4", DiskMiB: 2048, CurrentRelease: "rel-1",
	}
	view := tenantView{
		Tenant:    tenant,
		Instance:  store.Instance{TenantID: "demo", ObservedState: store.ObservedHealthy, LastHealthAt: &now},
		Owner:     "person:alice",
		Role:      identity.RoleOwner,
		CanDeploy: true,
		CanManage: true,
		CanAdmin:  true,
		Releases: []store.Release{
			{ID: "rel-1", Sha256: "0123456789abcdef", Status: store.ReleaseDeployed, CreatedAt: now, DeployedAt: &deployed},
			{ID: "rel-0", Sha256: "fedcba9876543210", Status: store.ReleaseFailed, CreatedAt: now.Add(-48 * time.Hour)},
		},
		Backups: []store.Backup{{ID: "bk-1", Kind: store.BackupPreDeploy, PBVersion: "0.40.4", SizeBytes: 4 << 20, CreatedAt: now}},
		Egress: []egressRow{
			{Host: "api.stripe.com", State: store.DecisionAutoApproved, GrantID: "g-1", Expires: now.Add(24 * time.Hour), Tier: 1},
			{Host: "*.slack.com", State: store.DecisionPending, Reason: "wildcard", GrantID: "g-2", Expires: now, Tier: 2},
			{Host: "hooks.example.com", State: store.DecisionRevoked, GrantID: "g-3", Expires: now, Tier: 1},
		},
		Transfer: &store.OwnerTransfer{
			ID: "tr-1", TenantID: "demo", FromPrincipal: "person:alice",
			ToPrincipal: "person:bob", OfferedBy: "person:alice", OfferedAt: now, ExpiresAt: now.Add(72 * time.Hour),
		},
		History:  []identity.OwnerRow{{ID: "1", TenantID: "demo", PrincipalID: "person:alice", Role: "owner", GrantedBy: "platform", GrantedAt: now}},
		Audit:    []auditlog.Record{{Seq: 1, Action: auditlog.ActionReleaseDeployed, ActorID: "person:alice", OccurredAt: now}},
		DiskUsed: 1 << 20, DiskFree: 1 << 30,
		Manifest: `{"name":"demo"}`,
		Access: accessView{
			Reaffirm:    []reaffirmRow{{Grant: store.Grant{ID: "g-9", Kind: store.GrantEgressHost, Subject: "api.example.com"}, DueAt: now}},
			SigningNote: "signed",
		},
		Tab: "ownership",
	}

	cases := []struct {
		name string
		page page
		want string
	}{
		{"login.html", page{Title: "Sign in", Data: map[string]string{"Next": "/t/demo"}}, "Principal"},
		{"tenants.html", page{
			Title: "Projects", Actor: identity.Actor{ID: "person:alice", Kind: identity.KindPerson}, CSRF: "csrf",
			Data: map[string]any{"Projects": []tenantRow{{Tenant: tenant, Role: "owner", State: store.ObservedHealthy}}},
		}, "demo.apps.localhost"},
		{"tenants.html empty", page{Title: "Projects", Actor: identity.Actor{ID: "person:alice"}, Data: map[string]any{"Projects": []tenantRow{}}}, "No projects yet"},
		{"tenant.html", page{
			Title: "demo", Actor: identity.Actor{ID: "person:bob", Kind: identity.KindPerson}, CSRF: "csrf", Data: view,
		}, "Accept ownership"},
		{"grants.html", page{
			Title: "Approvals", Actor: identity.Actor{ID: "platform", Kind: identity.KindPlatform}, CSRF: "csrf",
			Data: map[string]any{"Operator": true, "Grants": []struct {
				Grant   store.Grant
				Visible bool
			}{{Grant: store.Grant{ID: "g-2", TenantID: "demo", Kind: store.GrantEgressHost,
				Subject: "*.slack.com", Tier: 2, RequestedBy: "person:alice", RequestedAt: now}, Visible: true}},
				"Auto": []struct {
					Grant store.Grant
					State string
				}{{Grant: store.Grant{ID: "g-3", TenantID: "demo", Kind: store.GrantEgressHost,
					Subject: "api.stripe.com", Tier: 1, RequestedBy: "person:alice", RequestedAt: now,
					DecidedBy: "platform", DecidedAt: &now}, State: store.DecisionAutoApproved}}},
		}, "citadel grant approve"},
		{"grants.html tier 1", page{
			Title: "Approvals", Actor: identity.Actor{ID: "platform", Kind: identity.KindPlatform}, CSRF: "csrf",
			Data: map[string]any{"Operator": true, "Auto": []struct {
				Grant store.Grant
				State string
			}{{Grant: store.Grant{ID: "g-3", TenantID: "demo", Kind: store.GrantEgressHost,
				Subject: "api.stripe.com", Tier: 1, RequestedBy: "person:alice", RequestedAt: now}, State: store.DecisionRevoked}}},
		}, "api.stripe.com"},
		{"attestations.html", page{
			Title: "Access", Actor: identity.Actor{ID: "platform", Kind: identity.KindPlatform}, CSRF: "csrf", Operator: true,
			Data: map[string]any{
				"Projects": []projectRow{
					{Tenant: tenant, Outcome: store.OutcomeMatch, Attested: now},
					{Tenant: store.Tenant{ID: "t-2", Slug: "other"}, BreakGlass: true},
				},
				"Mismatches": []store.Attestation{{TenantID: "demo", Outcome: store.OutcomeEnforcementWithoutGrant, GeneratedAt: now}},
				"AnchorAge":  "1m", "AnchoredSeq": int64(3),
				"EnforcementNote": store.OutcomeEnforcementWithoutGrant,
			},
		}, `action="/attestations/demo/check"`},
	}

	// Each tab renders its own section and none of another tab's.
	tabs := map[string]string{
		"overview":  "<h2>Resources</h2>",
		"releases":  `href="/t/demo/releases/rel-0/download"`,
		"snapshots": "bk-1",
		"runtime":   "<h2>Runtime</h2>",
		"access":    "Re-affirm",
		"activity":  "<h2>Logs</h2>",
		"ownership": "Accept ownership",
	}
	for tab := range tabs {

		tv := view
		tv.Tab = tab
		var b strings.Builder
		if err := tpl.ExecuteTemplate(&b, "tenant.html", page{
			Title: "demo", Actor: identity.Actor{ID: "person:bob", Kind: identity.KindPerson}, CSRF: "csrf", Data: tv,
		}); err != nil {

			t.Fatalf("render tab %s: %v", tab, err)
		}
		// Operator actions are on /attestations, never on a tenant's own page.
		for _, op := range []string{"/attest\"", "/breakglass\""} {

			if strings.Contains(b.String(), op) {

				t.Errorf("tab %s carries the operator form %s", tab, op)
			}
		}
		for other, marker := range tabs {

			if got := strings.Contains(b.String(), marker); got != (other == tab) {

				t.Errorf("tab %s: contains %q = %v", tab, marker, got)
			}
		}
	}

	for _, c := range cases {

		t.Run(c.name, func(t *testing.T) {

			var b strings.Builder
			name, _, _ := strings.Cut(c.name, " ")
			if err := tpl.ExecuteTemplate(&b, name, c.page); err != nil {

				t.Fatalf("render %s: %v", name, err)
			}
			if !strings.Contains(b.String(), c.want) {

				t.Errorf("%s does not contain %q", name, c.want)
			}
		})
	}
}

// Every mutating form must carry the CSRF token, or requireSession refuses the
// post and the button silently does nothing.
func TestEveryFormCarriesTheCSRFToken(t *testing.T) {

	for _, name := range []string{"templates/tenant.html", "templates/grants.html", "templates/layout.html", "templates/attestations.html"} {

		raw, err := assets.ReadFile(name)
		if err != nil {

			t.Fatal(err)
		}
		body := string(raw)
		forms := strings.Count(body, `method="post"`)
		tokens := strings.Count(body, `name="csrf"`)
		if forms != tokens {

			t.Errorf("%s has %d post forms and %d csrf fields", name, forms, tokens)
		}
	}
}

func TestHumanHelpersHandleNilAndBothIntWidths(t *testing.T) {

	if got := ago((*time.Time)(nil)); got != "—" {

		t.Errorf("ago(nil) = %q", got)
	}
	if got := stamp(time.Time{}); got != "—" {

		t.Errorf("stamp(zero) = %q", got)
	}
	if got := humanBytes(int64(2 << 20)); got != "2.0 MiB" {

		t.Errorf("humanBytes(int64) = %q", got)
	}
	if got := humanBytes(uint64(2 << 20)); got != "2.0 MiB" {

		t.Errorf("humanBytes(uint64) = %q", got)
	}
}

// A post from a tenant-page tab lands back on that tab; anything else does not
// leak into the redirect.
func TestBackKeepsTheTab(t *testing.T) {

	cases := []struct{ to, tab, want string }{
		{"/t/demo", "snapshots", "/t/demo?ok=done&tab=snapshots"},
		{"/t/demo", "overview", "/t/demo?ok=done"},
		{"/t/demo", "<script>", "/t/demo?ok=done"},
		{"/t/demo/upgrade/j1", "runtime", "/t/demo/upgrade/j1?ok=done"},
		{"/grants", "access", "/grants?ok=done"},
	}
	for _, c := range cases {

		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{"tab": {c.tab}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		back(rec, req, c.to, "done", nil)
		if loc := rec.Header().Get("Location"); loc != c.want {

			t.Errorf("back(%q, tab=%q) = %q, want %q", c.to, c.tab, loc, c.want)
		}
	}
}
