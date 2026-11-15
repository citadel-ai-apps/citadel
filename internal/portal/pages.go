package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/breakglass"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// page is what every template gets.
type page struct {
	Title string
	Actor identity.Actor
	CSRF  string
	OK    string
	Err   string
	Data  any
	// Operator gates the nav links that only a platform principal can open.
	// Without it a tenant is shown a link that answers 403, which reads as the
	// platform being broken rather than as a page that was never theirs.
	Operator bool
}

func (s *Server) render(w http.ResponseWriter, req *http.Request, name, title string, data any) {

	sess := current(req.Context())
	p := page{
		Title: title, Actor: sess.actor, CSRF: sess.csrf,
		OK:       req.URL.Query().Get("ok"),
		Err:      req.URL.Query().Get("err"),
		Data:     data,
		Operator: s.isOperator(sess.actor),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, p); err != nil {

		s.log.Error("template failed", "template", name, "err", err)
	}
}

// back redirects to where the action came from, carrying one line of outcome.
// A redirect after a POST, not a rendered response, so a reload does not
// re-deploy.
func back(w http.ResponseWriter, req *http.Request, to string, ok string, err error) {

	q := url.Values{}
	// Land back on the tenant-page tab the form was posted from.
	if strings.HasPrefix(to, "/t/") && strings.Count(to, "/") == 2 && !strings.Contains(to, "?") {

		if tab := req.FormValue("tab"); validTab(tab) && tab != tenantTabs[0] {

			q.Set("tab", tab)
		}
	}
	if err != nil {

		q.Set("err", err.Error())

	} else if ok != "" {

		q.Set("ok", ok)
	}
	http.Redirect(w, req, to+"?"+q.Encode(), http.StatusSeeOther)
}

// ---- authentication --------------------------------------------------------

func (s *Server) loginPage(w http.ResponseWriter, req *http.Request) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p := page{
		Title: "Sign in",
		Err:   req.URL.Query().Get("err"),
		Data:  map[string]string{"Next": req.URL.Query().Get("next")},
	}
	if err := s.tpl.ExecuteTemplate(w, "login.html", p); err != nil {

		s.log.Error("template failed", "template", "login.html", "err", err)
	}
}

func (s *Server) login(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	// The one unauthenticated POST: capped like every other form.
	req.Body = http.MaxBytesReader(w, req.Body, formBodyLimit)
	id, password := req.PostFormValue("principal"), req.PostFormValue("password")
	// Credentials are keyed by the stored id, so "alice" and "platform" must be
	// canonicalised before the lookup. An unparseable id is kept as typed: it
	// fails verify like any unknown principal and the audit row shows the claim.
	if canonical, err := identity.Canonical(id); err == nil {

		id = canonical
	}

	keys := []throttleKey{{"principal", id}, {"address", hostOnly(req.RemoteAddr)}}
	if !s.throttle.allowed(keys...) {

		s.log.Warn("portal login throttled", "claimed", id, "remote", hostOnly(req.RemoteAddr))
		http.Redirect(w, req, "/login?err="+url.QueryEscape("too many failed attempts; try again later"), http.StatusSeeOther)
		return
	}
	actor, err := s.verify(ctx, id, password)
	if err != nil {

		s.throttle.fail(keys...)
		s.recordLogin(ctx, id, false, req.RemoteAddr)
		// One message for every failure mode: an unknown principal and a wrong
		// password must not be distinguishable from outside.
		http.Redirect(w, req, "/login?err="+url.QueryEscape(authn.ErrBadCredentials.Error()), http.StatusSeeOther)
		return
	}
	s.throttle.succeed(keys[0])
	s.recordLogin(ctx, actor.ID, true, req.RemoteAddr)
	// The credential was just read to check the password; its epoch is the
	// one this session belongs to.
	cred, err := store.GetCredential(ctx, s.db.Reader(), actor.ID)
	if err != nil {

		http.Redirect(w, req, "/login?err="+url.QueryEscape(authn.ErrBadCredentials.Error()), http.StatusSeeOther)
		return
	}
	s.setCookie(w, s.sessions.IssueAt(actor.ID, cred.SessionEpoch))

	http.Redirect(w, req, safeNext(req.FormValue("next")), http.StatusSeeOther)
}

// safeNext is the post-login redirect target, kept on this origin.
//
// A leading slash is not enough: "//evil.example" is a scheme-relative URL to
// another host, and browsers read "/\evil.example" the same way. Anything that
// parses with a scheme or a host, or that a browser would, goes to "/".
func safeNext(next string) string {

	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {

		return "/"
	}
	if strings.ContainsAny(next, "\\\r\n\t") {

		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {

		return "/"
	}
	return next
}

func (s *Server) verify(ctx context.Context, id, password string) (identity.Actor, error) {

	if id == "" || password == "" {

		return identity.Actor{}, authn.ErrBadCredentials
	}
	cred, credErr := store.GetCredential(ctx, s.db.Reader(), id)
	// An unknown principal is hashed against a throwaway credential, so the
	// response time does not say which names have a password.
	hash := s.dummyHash
	if credErr == nil {

		hash = cred.Hash
	}
	ok := false
	if err := s.hashSlots.do(ctx, func() { ok = authn.VerifyPassword(hash, password) }); err != nil {

		return identity.Actor{}, authn.ErrBadCredentials
	}
	if credErr != nil || !ok {

		return identity.Actor{}, authn.ErrBadCredentials
	}
	actor, err := s.ident.ResolveActor(ctx, id)
	if err != nil {

		return identity.Actor{}, authn.ErrBadCredentials
	}
	return actor, nil
}

// recordLogin audits an authentication attempt (§14.4 audits control-plane
// authentication). A failure for an unknown principal is attributed to the
// platform, with the claimed id in the detail: the audit log's actor column is
// a foreign key to a real principal, and inventing one would be worse than
// naming the platform as the observer.
func (s *Server) recordLogin(ctx context.Context, id string, ok bool, remote string) {

	s.recordAuth(ctx, id, ok, remote, "portal")
}

// recordAuth is recordLogin for any password check; surface says which.
func (s *Server) recordAuth(ctx context.Context, id string, ok bool, remote, surface string) {

	action := auditlog.ActionLoginFailed
	if ok {

		action = auditlog.ActionLoginSucceeded
	}
	actor := identity.Platform()
	detail := map[string]any{"claimed": id, "surface": surface}
	if p, err := s.ident.Get(ctx, id); err == nil {

		actor = identity.Actor{ID: p.ID, Kind: p.Kind}
	}
	err := s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action: action, SubjectRef: "principal/" + id,
			Detail: detail, SourceIP: hostOnly(remote),
		})
		return err
	})
	if err != nil {

		s.log.Error("cannot record a login attempt", "principal", id, "err", err)
	}
}

func (s *Server) logout(w http.ResponseWriter, req *http.Request) {

	if c, err := req.Cookie(s.cookieName()); err == nil {

		if id, epoch, err := s.sessions.VerifyEpoch(c.Value); err == nil && s.currentEpoch(req.Context(), id, epoch) {

			if p, err := s.ident.Get(req.Context(), id); err == nil {

				// Signing out ends the session server-side, not just in this
				// browser: a copied cookie stops working too. The epoch is per
				// principal, so every other portal session of theirs ends with
				// it.
				err := s.db.Tx(req.Context(), func(tx bun.Tx) error {

					if err := store.BumpSessionEpoch(req.Context(), tx, p.ID); err != nil {

						return err
					}
					_, err := s.audit.Append(req.Context(), tx, auditlog.Event{
						ActorID: p.ID, ActorKind: p.Kind,
						Action: auditlog.ActionLogout, SubjectRef: "principal/" + p.ID,
					})
					return err
				})
				if err != nil {

					s.log.Error("sign-out could not end the session server-side", "principal", p.ID, "err", err)
				}
			}
		}
	}
	s.clearCookie(w)
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func hostOnly(remote string) string {

	for i := len(remote) - 1; i >= 0; i-- {

		if remote[i] == ':' {

			return remote[:i]
		}
	}
	return remote
}

// ---- pages -----------------------------------------------------------------

type tenantRow struct {
	Tenant store.Tenant
	Role   string
	State  string
}

func (s *Server) tenantsPage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	roles, err := s.ident.TenantsFor(ctx, sess.actor.ID)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]tenantRow, 0, len(roles))
	for _, tr := range roles {

		t, err := store.GetTenant(ctx, s.db.Reader(), tr.TenantID)
		if err != nil {

			continue
		}
		state := "unknown"
		if in, err := store.GetInstance(ctx, s.db.Reader(), t.ID); err == nil {

			state = in.ObservedState
		}
		rows = append(rows, tenantRow{Tenant: t, Role: tr.Role, State: state})
	}
	var held []heldRow
	if sess.actor.CanBreakglass() {

		grants, _ := store.ActiveBreakglassHeld(ctx, s.db.Reader(), sess.actor.ID, time.Now().UTC())
		for _, g := range grants {

			if t, err := store.GetTenant(ctx, s.db.Reader(), g.TenantID); err == nil {

				held = append(held, heldRow{Tenant: t, Grant: g})
			}
		}
	}
	s.render(w, req, "tenants.html", "Projects", map[string]any{"Projects": rows, "Breakglass": held})
}

type heldRow struct {
	Tenant store.Tenant
	Grant  store.Grant
}

// tenantView is everything the detail page shows. Assembled in the handler
// rather than in the template: a template that queries is a template nobody can
// test.
type tenantView struct {
	Tenant    store.Tenant
	Instance  store.Instance
	Owner     string
	Role      string
	CanDeploy bool
	CanManage bool
	CanAdmin  bool
	Releases  []store.Release
	Backups   []store.Backup
	Egress    []egressRow
	Transfer  *store.OwnerTransfer
	History   []identity.OwnerRow
	Audit     []auditlog.Record
	Drift     []reconcile.Drift
	Stats     *driver.Stats
	DiskUsed  uint64
	DiskFree  uint64
	Manifest  string
	// Upgrades, Versions and EOL are §12's tenant-facing half: what the tenant
	// runs, what they could move to, and how long they have before the platform
	// moves them.
	Upgrades []store.UpgradeJob
	Versions []store.RuntimeVersion
	EOL      *eolView
	// QuarantineReason is shown to the tenant verbatim (§14.6). An operator
	// action that makes someone's application unreachable with no stated cause
	// is exactly the kind of thing the audit record exists to prevent.
	QuarantineReason string
	// Access is §14.6: what this tenant can reach, who authorised it, and every
	// platform read of its data. Shown without being asked for.
	Access accessView
	// Tab is which section of the page is shown; one of tenantTabs.
	Tab string
	// Breakglass is the session this page is open under, nil for a stored
	// role. The page says so above everything else (§14.3).
	Breakglass *store.Grant
}

// tenantTabs are the sections of the tenant page, in tab-bar order. The first
// is the default.
var tenantTabs = []string{"overview", "releases", "snapshots", "runtime", "access", "activity", "ownership"}

func validTab(tab string) bool {

	for _, t := range tenantTabs {

		if t == tab {

			return true
		}
	}
	return false
}

type egressRow struct {
	Host    string
	State   string
	Reason  string
	GrantID string
	Expires time.Time
	Tier    int
	// Denials and LastDenied come from the PROXY's own log, not from the grant
	// table. A row that reads "allowed" and still shows denials is the platform
	// and the record disagreeing, which is worth seeing on the page the tenant
	// already looks at rather than only in an attestation (§14.5).
	Denials    int
	LastDenied time.Time
}

func (s *Server) tenantPage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	a, err := s.resolveTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.auditBreakglassView(ctx, sess.actor, a); err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, role := a.Tenant, a.Role

	v := tenantView{
		Tenant:     t,
		Role:       role,
		CanDeploy:  identity.RoleAllows(role, identity.CapDeploy),
		CanManage:  identity.RoleAllows(role, identity.CapTransfer),
		CanAdmin:   identity.RoleAllows(role, identity.CapInstanceAdmin) && sess.actor.Kind != identity.KindPlatform,
		Breakglass: a.Breakglass,
	}
	if a.Breakglass != nil && pbauth.IsLegacy(t.RuntimeVersion) {

		// A pre-0.23 admin token cannot be made to stop with the session.
		v.CanAdmin = false
	}
	v.Tab = req.URL.Query().Get("tab")
	if !validTab(v.Tab) {

		v.Tab = tenantTabs[0]
	}

	// Always shown: the header and the alert flashes above the tabs.
	v.Instance, _ = store.GetInstance(ctx, s.db.Reader(), t.ID)
	v.Owner, _ = s.ident.CurrentOwner(ctx, t.ID)
	v.Versions = s.upgradeTargets(ctx, t)
	v.EOL = s.eolFor(ctx, t, v.Versions)
	for _, d := range s.rec.Drift().List() {

		if d.TenantID == t.ID {

			v.Drift = append(v.Drift, d)
		}
	}
	if tr, ok, _ := s.ident.PendingTransfer(ctx, t.ID); ok {

		v.Transfer = &tr
	}
	// §14.6: the tenant sees every platform action on their instance without
	// having to ask for it.
	if t.Quarantined || v.Tab == "overview" || v.Tab == "activity" {

		v.Audit, _ = auditlog.Select(ctx, s.db.Reader(), auditlog.Query{TenantID: t.ID, Limit: 25})
	}
	if t.Quarantined {

		// Read back from the audit chain rather than stored on the tenant row:
		// the reason belongs to the decision, and the decision is already an
		// append-only record with an actor on it.
		v.QuarantineReason = quarantineReason(v.Audit)
	}

	switch v.Tab {

	case "overview":
		v.Releases, _ = store.ListReleases(ctx, s.db.Reader(), t.ID)
		if used, avail, err := s.fs.Usage(t.ID); err == nil {

			v.DiskUsed, v.DiskFree = used, avail
		}
		if v.Instance.ObservedState == store.ObservedHealthy || v.Instance.ObservedState == store.ObservedStarting {

			if st, err := s.drv.Stats(ctx, driver.Handle{TenantID: t.ID, Name: config.ContainerName(t.Slug)}); err == nil {

				v.Stats = &st
			}
		}
		if len(v.Audit) > 5 {

			v.Audit = v.Audit[:5]
		}

	case "releases":
		v.Releases, _ = store.ListReleases(ctx, s.db.Reader(), t.ID)
		if t.CurrentRelease != "" {

			if rel, err := store.GetRelease(ctx, s.db.Reader(), t.CurrentRelease); err == nil {

				if man, err := release.Manifest(rel); err == nil {

					if b, err := json.MarshalIndent(man, "", "  "); err == nil {

						v.Manifest = string(b)
					}
				}
			}
		}

	case "snapshots":
		v.Backups, _ = store.ListBackups(ctx, s.db.Reader(), t.ID)

	case "runtime":
		v.Upgrades, _ = store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{TenantID: t.ID, Limit: 10})

	case "access":
		v.Egress = s.egressRows(ctx, t)
		v.Access = s.access(req, t)

	case "ownership":
		v.History, _ = s.ident.History(ctx, t.ID)
	}
	s.render(w, req, "tenant.html", t.Slug, v)
}

// egressRows renders the four §9.4 states, with what the proxy actually did.
//
// The states come from the grants; the counts come from the host. Keeping them
// side by side is the point: "approved" plus a rising denial count is a
// different problem from "awaiting approval" plus the same count, and a
// developer should be able to tell them apart without opening a ticket.
func (s *Server) egressRows(ctx context.Context, t store.Tenant) []egressRow {

	grants, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{
		TenantID: t.ID, Kind: store.GrantEgressHost,
	})
	if err != nil {

		return nil
	}
	hits := map[string]int{}
	last := map[string]time.Time{}
	if denials, err := store.ListDenials(ctx, s.db.Reader(), t.ID, time.Time{}); err == nil {

		for _, d := range denials {

			hits[d.Host] += d.Hits
			if d.LastSeenAt.After(last[d.Host]) {

				last[d.Host] = d.LastSeenAt
			}
		}
	}

	now := time.Now().UTC()
	seen := map[string]bool{}
	out := make([]egressRow, 0, len(grants))
	for _, g := range grants {

		if seen[g.Subject] {

			continue
		}
		seen[g.Subject] = true
		out = append(out, egressRow{
			Host: g.Subject, State: g.State(now), Reason: g.Justification,
			GrantID: g.ID, Expires: g.ExpiresAt, Tier: g.Tier,
			Denials: hits[g.Subject], LastDenied: last[g.Subject],
		})
	}
	// A host nothing ever requested, that the app called anyway — usually a
	// dependency reaching somewhere its caller did not know about. Showing it
	// is most of the value of a default-deny posture.
	for host, n := range hits {

		if seen[host] {

			continue
		}
		out = append(out, egressRow{
			Host: host, State: "never_requested", Denials: n, LastDenied: last[host],
		})
	}
	return out
}

// quarantineReason pulls the stated reason off the most recent quarantine
// event. Records arrive oldest first, so the last match wins.
func quarantineReason(records []auditlog.Record) string {

	reason := ""
	for _, r := range records {

		if r.Action != auditlog.ActionTenantQuarantined {

			continue
		}
		if v, ok := r.Detail["reason"].(string); ok {

			reason = v
		}
	}
	return reason
}

func (s *Server) grantQueuePage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	rows, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{Decision: store.DecisionPending})
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mine := map[string]bool{}
	roles, _ := s.ident.TenantsFor(ctx, sess.actor.ID)
	for _, r := range roles {

		mine[r.TenantID] = true
	}
	type queued struct {
		Grant   store.Grant
		Visible bool
	}
	operator := s.isOperator(sess.actor)
	out := make([]queued, 0, len(rows))
	for _, g := range rows {

		if !operator && !mine[g.TenantID] {

			continue
		}
		out = append(out, queued{Grant: g, Visible: operator})
	}
	// Oldest first: this is a queue, and queues rot unseen (§15).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {

		out[i], out[j] = out[j], out[i]
	}

	// Tier 1 is recorded, not gated (§14.3): no person decided it, so the page
	// shows what the platform granted on its own. State, not Decision, so a
	// Tier-1 host revoked or lapsed since reads that way.
	autoRows, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{Decision: store.DecisionAutoApproved})
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type granted struct {
		Grant store.Grant
		State string
	}
	now := time.Now().UTC()
	since := now.Add(-recentAutoWindow)
	auto := make([]granted, 0)
	for _, g := range autoRows {

		if len(auto) == recentAutoCap || g.RequestedAt.Before(since) {

			break // newest first, so nothing after this is wanted
		}
		if !operator && !mine[g.TenantID] {

			continue
		}
		auto = append(auto, granted{Grant: g, State: g.State(now)})
	}
	s.render(w, req, "grants.html", "Approvals", map[string]any{"Grants": out, "Auto": auto, "Operator": operator})
}

// How far back, and how many, Tier-1 grants the Approvals page lists.
const (
	recentAutoWindow = 7 * 24 * time.Hour
	recentAutoCap    = 100
)

// isOperator gates the portal's operator pages: the fleet view, the grant
// queue, attestations and the on-demand re-check. None of them decides
// anything a person is accountable for, so the shared platform login sees them
// as well as a named operator (a person with the operator flag).
//
// Break-glass and its review need a named person (INV-16), so they check
// Actor.CanBreakglass instead, which the platform principal never passes.
// Tier-2 decisions are still citadel over the unix socket.
func (s *Server) isOperator(a identity.Actor) bool {

	return a.Kind == identity.KindPlatform || a.CanBreakglass()
}

// ---- actions ---------------------------------------------------------------

func (s *Server) upload(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	to := "/t/" + t.ID

	file, header, err := req.FormFile("package")
	if err != nil {

		back(w, req, to, "", fmt.Errorf("choose a package zip: %w", err))
		return
	}
	defer file.Close()

	rel, err := s.rel.Ingest(ctx, sess.actor, t, file, header.Size)
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	if req.FormValue("deploy") == "" {

		back(w, req, to, "uploaded "+rel.ID+" — validated, not deployed", nil)
		return
	}
	res, err := s.rec.Deploy(ctx, sess.actor, t, rel.ID)
	back(w, req, to, deployMessage(res), deployError(res, err))
}

// downloadRelease hands back the zip a release was uploaded as. Same gate as
// uploading one: whoever may ship the code may read it back.
func (s *Server) downloadRelease(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	d, err := s.rel.OpenDownload(ctx, sess.actor, t, mux.Vars(req)["rid"])
	if errors.Is(err, store.ErrReleaseNotFound) || errors.Is(err, release.ErrUploadMissing) {

		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Serve(w, req)
}

func (s *Server) deploy(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	res, err := s.rec.Deploy(ctx, sess.actor, t, req.FormValue("release"))
	back(w, req, "/t/"+t.ID, deployMessage(res), deployError(res, err))
}

func (s *Server) rollback(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	res, err := s.rec.Rollback(ctx, sess.actor, t, req.FormValue("release"))
	back(w, req, "/t/"+t.ID, deployMessage(res), deployError(res, err))
}

// deployMessage and deployError turn a DeployResult into one line each.
//
// A deploy that failed and rolled back is not an internal error: the platform
// did what it promised. It is reported as the failure it is, with the step that
// broke, and the tenant's data is back where it started.
func deployMessage(res reconcile.DeployResult) string {

	if !res.Deployed {

		return ""
	}
	msg := "deployed " + res.ReleaseID
	pending := 0
	for _, g := range res.Grants {

		if g.Decision == store.DecisionPending {

			pending++
		}
	}
	if pending > 0 {

		msg += fmt.Sprintf(" — %d egress host(s) awaiting approval and unreachable until then", pending)
	}
	return msg
}

func deployError(res reconcile.DeployResult, err error) error {

	if err != nil {

		return err
	}
	if res.Deployed {

		return nil
	}
	if res.RolledBack {

		return fmt.Errorf("deploy failed at %s and was rolled back (data restored from snapshot %s): %s",
			res.FailedStep, res.Snapshot, res.Error)
	}
	return errors.New(res.Error)
}

func (s *Server) restart(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			RestartCount: new(0), LastError: new(""),
		}); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionTenantRestarted, SubjectRef: "tenant/" + t.ID,
		})
		return err
	})
	if err == nil {

		err = s.rec.Materialise(ctx, t)
	}
	back(w, req, "/t/"+t.ID, "restarted", err)
}

func (s *Server) backup(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	b, err := s.rec.Snapshot(ctx, sess.actor, t, store.BackupManual)
	back(w, req, "/t/"+t.ID, "snapshot "+b.ID, err)
}

func (s *Server) revokeGrant(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapRequestGrant)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	gid := mux.Vars(req)["gid"]
	g, err := store.GetGrant(ctx, s.db.Reader(), gid)
	if err != nil || g.TenantID != t.ID {

		back(w, req, "/t/"+t.ID, "", fmt.Errorf("%w: %s", store.ErrGrantNotFound, gid))
		return
	}
	if g.Tier == grantpolicy.TierBreakGlass {

		back(w, req, "/t/"+t.ID+"?tab=access", "", breakglass.ErrTenantRevoke)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.RevokeGrant(ctx, tx, gid, sess.actor.ID); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionGrantRevoked, SubjectRef: "grant/" + gid,
			Detail: map[string]any{"kind": g.Kind, "subject": g.Subject},
		})
		return err
	})
	// §14.7 in one sentence, where the tenant is looking when it matters.
	back(w, req, "/t/"+t.ID, "revoked "+g.Subject+" — re-requesting it later needs a human decision", err)
}

// reenableGrant asks for a revoked egress host back.
//
// §14.7: the revoked row is never un-revoked. This files a fresh request that
// points at it, and PreviouslyRefused puts that request in front of a named
// approver whatever its tier would otherwise be.
func (s *Server) reenableGrant(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapRequestGrant)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	to := "/t/" + t.ID
	// A re-enable files a grant request, and a frozen tenant's access does not
	// move until an operator lifts the freeze (§14.5).
	if t.FrozenReason != "" {

		back(w, req, to, "", fmt.Errorf("%w: %s", reconcile.ErrFrozen, t.FrozenReason))
		return
	}
	gid := mux.Vars(req)["gid"]
	old, err := store.GetGrant(ctx, s.db.Reader(), gid)
	if err != nil || old.TenantID != t.ID || old.Kind != store.GrantEgressHost {

		back(w, req, to, "", fmt.Errorf("%w: %s", store.ErrGrantNotFound, gid))
		return
	}
	now := time.Now().UTC()
	if old.State(now) != store.DecisionRevoked {

		back(w, req, to, "", fmt.Errorf("%s is %s, not revoked; only a revoked host can be re-enabled", old.Subject, old.State(now)))
		return
	}
	reason := req.FormValue("reason")
	if reason == "" {

		back(w, req, to, "", errors.New("re-enabling needs a reason; the approver sees it"))
		return
	}
	// The newest row for a subject is what the page shows, so a second submit
	// (or a release that re-requested it meanwhile) must not queue a duplicate.
	existing, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{
		TenantID: t.ID, Kind: old.Kind, Subject: old.Subject,
	})
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	for _, e := range existing {

		if e.Active(now) || (e.Decision == store.DecisionPending && e.RevokedAt == nil) {

			back(w, req, to, "", fmt.Errorf("%s already has a live grant or a pending request (%s)", old.Subject, e.ID))
			return
		}
	}

	d := grantpolicy.Classify(
		grantpolicy.Request{Kind: old.Kind, Subject: old.Subject},
		grantpolicy.TenantContext{PlatformDomains: []string{s.cfg.AppsDomain}, PreviouslyRefused: true})
	if d.Tier == grantpolicy.TierDenied {

		back(w, req, to, "", errors.New(d.Reason))
		return
	}
	g := store.Grant{
		ID:            store.NewID("g"),
		TenantID:      t.ID,
		Kind:          old.Kind,
		Direction:     grantpolicy.Direction(old.Kind),
		Subject:       old.Subject,
		Tier:          d.Tier,
		Decision:      grantpolicy.DecisionFor(d.Tier),
		RequestedBy:   sess.actor.ID,
		RequestedAt:   now,
		PolicyVersion: d.PolicyVersion,
		Justification: reason,
		EvidenceRef:   "grant/" + old.ID,
		ExpiresAt:     now.Add(d.TTL),
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertGrant(ctx, tx, g); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionGrantRequested, SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"kind": g.Kind, "subject": g.Subject, "tier": g.Tier,
				"decision": g.Decision, "policy_version": g.PolicyVersion,
				"reenables": old.ID,
			},
		}); err != nil {

			return err
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceOperator,
			Kind: store.NotifyGrantPending, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s requests %s access to %s. %s",
				t.Slug, g.Kind, g.Subject, d.Reason),
		})
	})
	back(w, req, to, "re-enable of "+g.Subject+" requested — waiting for a platform operator", err)
}

func (s *Server) ownerAction(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	id := mux.Vars(req)["id"]
	t, role, err := s.tenantFor(ctx, sess.actor, id)
	if err == nil && identity.IsBreakglassRole(role) {

		// Break-glass never takes part in who owns the tenant.
		err = fmt.Errorf("%w: break-glass access is read-only", identity.ErrForbidden)
	}
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	to := "/t/" + t.ID
	switch mux.Vars(req)["action"] {

	case "transfer":
		err = s.db.Tx(ctx, func(tx bun.Tx) error {

			if _, err := s.ident.Require(ctx, t.ID, sess.actor.ID, identity.CapTransfer); err != nil {

				return err
			}
			_, err := s.ident.OfferTransfer(ctx, tx, sess.actor, t.ID, req.FormValue("to"), req.FormValue("reason"))
			return err
		})
		back(w, req, to, "offered to "+req.FormValue("to")+" — ownership moves when they accept", err)

	case "accept":
		var inherited []store.Grant
		err = s.db.Tx(ctx, func(tx bun.Tx) error {

			var err error
			_, inherited, err = s.ident.AcceptTransfer(ctx, tx, sess.actor, t.ID)
			return err
		})
		msg := "you now own " + t.Slug
		if len(inherited) > 0 {

			msg += fmt.Sprintf(" — re-affirm the %d inherited grant(s) on the Access tab within %d days, "+
				"or they stop being enforced", len(inherited), int(store.ReaffirmWindow.Hours()/24))
		}
		back(w, req, to, msg, err)

	case "decline":
		err = s.db.Tx(ctx, func(tx bun.Tx) error {

			return s.ident.CloseTransfer(ctx, tx, sess.actor, t.ID, store.TransferDeclined)
		})
		back(w, req, to, "transfer declined", err)

	case "cancel":
		// Withdrawing an offer is the offering side's call, as it is over the
		// API (owner.go): a viewer must not be able to cancel the owner's
		// handover, and CloseTransfer itself checks only the declining side.
		if !identity.RoleAllows(role, identity.CapTransfer) {

			back(w, req, to, "", fmt.Errorf("%w: only the owner may withdraw the offer", identity.ErrForbidden))
			return
		}
		err = s.db.Tx(ctx, func(tx bun.Tx) error {

			return s.ident.CloseTransfer(ctx, tx, sess.actor, t.ID, store.TransferCancelled)
		})
		back(w, req, to, "offer withdrawn", err)

	default:
		http.Error(w, "unknown ownership action", http.StatusNotFound)
	}
}

// tenantLogs serves the tail of a tenant's container output as plain text, for
// the htmx-polled <pre> on the detail page.
//
// Container stdout is the whole observability path: the image has no shell, so
// there is nothing to exec into (§15).
func (s *Server) tenantLogs(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	a, err := s.resolveTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	t := a.Tenant
	if a.Breakglass != nil {

		// Container output is the tenant's: under break-glass, reading it is a
		// platform read of their data and lands on their Access tab. Once per
		// session; the tail polls.
		if err := s.auditBreakglassOnce(ctx, sess.actor, *a.Breakglass, auditlog.ActionLogRead,
			map[string]any{"what": "container_logs"}); err != nil {

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// The collected file first. A deploy destroys and recreates the container,
	// so the output explaining why the previous release failed is gone from
	// Docker at exactly the moment someone wants to read it — the host-side
	// copy outlives the container that wrote it (§15).
	if b, err := s.logs.Tail(t.ID, 256<<10); err == nil && len(b) > 0 {

		_, _ = w.Write(b)
		return
	}
	rc, err := s.drv.Logs(ctx, driver.Handle{TenantID: t.ID, Name: config.ContainerName(t.Slug)},
		driver.LogOpts{Tail: "200"})
	if err != nil {

		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer rc.Close()
	_, _ = io.Copy(w, io.LimitReader(rc, 256<<10))
}

// ---- helpers ---------------------------------------------------------------

// lookupTenant resolves a tenant by id or slug, with no authorisation at all.
// Callers decide who may see it: tenantFor by role, operatorTenant by kind.
func (s *Server) lookupTenant(ctx context.Context, id string) (store.Tenant, error) {

	t, err := store.GetTenant(ctx, s.db.Reader(), id)
	if err != nil {

		if t, err = store.GetTenantBySlug(ctx, s.db.Reader(), id); err != nil {

			return store.Tenant{}, err
		}
	}
	return t, nil
}

// tenantAccess is how a principal reaches a tenant: a stored role, or an active
// break-glass session.
type tenantAccess struct {
	Tenant store.Tenant
	Role   string
	// Breakglass is the session the access comes from, nil for a stored role.
	Breakglass *store.Grant
}

// resolveTenant resolves a tenant the principal may see, by id or slug.
//
// A stored role wins. With none, a named operator holding an active break-glass
// grant on the tenant gets a synthetic break-glass role (§14.3): the pages
// read-only, plus the admin handoff when breakglass.OpensAdmin. It is re-checked
// on every request, so expiry, an early close and a cleared operator flag all
// end it on the next click.
//
// The platform principal is not special-cased: it sees a tenant only while it
// holds a real role row on it, as it does after taking custody of an orphan
// (§14.1), and it can never hold break-glass. Anything else would be standing
// access to every tenant's page, logs and releases.
func (s *Server) resolveTenant(ctx context.Context, actor identity.Actor, id string) (tenantAccess, error) {

	t, err := s.lookupTenant(ctx, id)
	if err != nil {

		return tenantAccess{}, err
	}
	role, err := s.ident.Role(ctx, t.ID, actor.ID)
	if err == nil {

		return tenantAccess{Tenant: t, Role: role}, nil
	}
	if actor.CanBreakglass() {

		g, ok, err := store.ActiveBreakglassFor(ctx, s.db.Reader(), t.ID, actor.ID, time.Now().UTC())
		if err != nil {

			return tenantAccess{}, err
		}
		if ok {

			role := identity.RoleBreakglassView
			if breakglass.OpensAdmin(g) {

				role = identity.RoleBreakglassData
			}
			return tenantAccess{Tenant: t, Role: role, Breakglass: &g}, nil
		}
	}
	// Same answer as "no such tenant": a principal with no role must not be
	// able to probe which slugs exist.
	return tenantAccess{}, fmt.Errorf("%w: %s", store.ErrTenantNotFound, id)
}

// tenantFor is resolveTenant for callers that only need the tenant and role.
func (s *Server) tenantFor(ctx context.Context, actor identity.Actor, id string) (store.Tenant, string, error) {

	a, err := s.resolveTenant(ctx, actor, id)
	if err != nil {

		return store.Tenant{}, "", err
	}
	return a.Tenant, a.Role, nil
}

// operatorTenant resolves a tenant for an operator action on the Access page
// (on-demand attestation, opening break-glass), with no role check.
//
// Only for actions that show none of the tenant's data by themselves: the
// operator needs no role on a tenant to make the host re-check it or to open
// break-glass. The tenant page that break-glass then opens is resolveTenant's,
// checked per request against the session.
func (s *Server) operatorTenant(ctx context.Context, actor identity.Actor, id string) (store.Tenant, error) {

	if !s.isOperator(actor) {

		return store.Tenant{}, fmt.Errorf("%w: an operator action", identity.ErrForbidden)
	}
	return s.lookupTenant(ctx, id)
}

func (s *Server) tenantWithCap(ctx context.Context, actor identity.Actor, id, capability string) (store.Tenant, error) {

	t, role, err := s.tenantFor(ctx, actor, id)
	if err != nil {

		return store.Tenant{}, err
	}
	if !identity.RoleAllows(role, capability) {

		return store.Tenant{}, fmt.Errorf("%w: %s is %s on %s", identity.ErrForbidden, actor.ID, role, t.Slug)
	}
	return t, nil
}

// TierLabel renders a grant tier the way §14.3 describes it.
func TierLabel(tier int) string {

	switch tier {

	case grantpolicy.TierAuto:
		return "auto-granted"
	case grantpolicy.TierHuman:
		return "needs an approver"
	case grantpolicy.TierBreakGlass:
		return "break-glass"
	default:
		return "denied"
	}
}
