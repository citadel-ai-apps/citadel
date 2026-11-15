package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// reportFrom rebuilds a Report from a stored row.
//
// The stored signature is carried through rather than recomputed: it covers the
// report as it was generated, and the exact signed bytes live in the file under
// audit/attestations for anyone who wants to check it independently.
func reportFrom(row store.Attestation, slug string) (attest.Report, error) {

	rep := attest.Report{
		TenantID: row.TenantID, Slug: slug, GeneratedAt: row.GeneratedAt,
		Outcome: row.Outcome, Signature: row.Signature,
	}
	if err := json.Unmarshal([]byte(row.ObservedJSON), &rep.Observed); err != nil {

		return attest.Report{}, err
	}
	if row.MismatchJSON != "" {

		if err := json.Unmarshal([]byte(row.MismatchJSON), &rep.Findings); err != nil {

			return attest.Report{}, err
		}
	}
	return rep, nil
}

// accessView is the tenant-facing half of §14.6: what the platform has done to
// this tenant's data, and what the tenant can reach.
//
// Summarised rather than the full report (D17). The full version names bridge
// interfaces, subnets, chain positions and the proxy's address — platform
// topology handed to a party the model treats as fully compromised. Everything
// the accountability story needs survives the trim.
type accessView struct {
	Report      *attest.Report
	Attested    time.Time
	NoReport    bool
	Accesses    []auditlog.Record
	BreakGlass  []breakglassRow
	Notices     []store.Notification
	Reaffirm    []reaffirmRow
	Signature   string
	PublicKey   string
	SigningNote string
}

type breakglassRow struct {
	Grant    store.Grant
	Open     bool
	Reviewed bool
	Review   store.BreakglassReview
	Overdue  bool
}

type reaffirmRow struct {
	Grant  store.Grant
	DueAt  time.Time
	Lapsed bool
}

// access assembles the tenant's Access card.
//
// Built here rather than queried from the template, like every other view in
// this package: a template that reaches into the database is a template that
// can show one tenant another's row. Always the summarised report: the tenant
// page is tenant-facing, and the operator's view is /attestations.
func (s *Server) access(req *http.Request, t store.Tenant) accessView {

	ctx := req.Context()
	var v accessView

	if row, err := store.LatestAttestation(ctx, s.db.Reader(), t.ID); err == nil {

		if rep, err := reportFrom(row, t.Slug); err == nil {

			rep = attest.Summarise(rep)
			v.Report, v.Attested = &rep, row.GeneratedAt
			v.Signature, v.PublicKey = row.Signature, rep.PublicKey
		}

	} else {

		v.NoReport = true
	}
	if s.signer != nil {

		v.PublicKey = s.signer.PublicKey()
		v.SigningNote = "Signed on this host; only history before the last replicated anchor is fixed."
	}

	for _, action := range auditlog.DataAccessActions {

		rows, _ := auditlog.Select(ctx, s.db.Reader(), auditlog.Query{
			TenantID: t.ID, Action: action, Limit: 100,
		})
		v.Accesses = append(v.Accesses, rows...)
	}
	// Newest first: "who looked at my data" is a question about recent events.
	for i := 1; i < len(v.Accesses); i++ {

		for j := i; j > 0 && v.Accesses[j].Seq > v.Accesses[j-1].Seq; j-- {

			v.Accesses[j], v.Accesses[j-1] = v.Accesses[j-1], v.Accesses[j]
		}
	}

	now := time.Now().UTC()
	sessions, _ := store.BreakglassGrants(ctx, s.db.Reader(), t.ID)
	for _, g := range sessions {

		row := breakglassRow{Grant: g, Open: g.Active(now)}
		if rev, err := store.GetReview(ctx, s.db.Reader(), g.ID); err == nil {

			row.Reviewed, row.Review = true, rev

		} else {

			row.Overdue = store.ReviewOverdue(g, now)
		}
		v.BreakGlass = append(v.BreakGlass, row)
	}

	pending, _ := store.PendingReaffirmations(ctx, s.db.Reader(), t.ID)
	for _, ra := range pending {

		if g, err := store.GetGrant(ctx, s.db.Reader(), ra.GrantID); err == nil {

			v.Reaffirm = append(v.Reaffirm, reaffirmRow{
				Grant: g, DueAt: ra.DueAt, Lapsed: ra.Lapsed(now),
			})
		}
	}

	v.Notices, _ = store.ListNotifications(ctx, s.db.Reader(), store.NotificationFilter{
		TenantID: t.ID, Audience: store.AudienceTenant, Limit: 25,
	})
	return v
}

// projectRow is one tenant on the operator's Access page: where its latest
// attestation stands, and whether break-glass is open on it.
type projectRow struct {
	Tenant     store.Tenant
	Outcome    string
	Attested   time.Time
	BreakGlass bool
}

type reviewRow struct {
	Grant   store.Grant
	Open    bool
	Overdue bool
}

// attestationsPage is the operator's fleet view of §14.5, mismatches first.
//
// It is also where the operator's per-tenant actions live: the re-check, and,
// for a named operator, opening, closing and reviewing break-glass. The tenant
// page is role-checked like any other principal's, so an operator with no role
// on a tenant acts on it from here; break-glass is what then opens its page.
func (s *Server) attestationsPage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	if !s.isOperator(sess.actor) {

		http.Error(w, "attestation reports are an operator surface; your own is on your project page",
			http.StatusForbidden)
		return
	}
	mismatches, err := store.Mismatches(ctx, s.db.Reader())
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	openBG, _ := store.OpenBreakglass(ctx, s.db.Reader(), now)
	overdueBG, _ := store.OverdueBreakglass(ctx, s.db.Reader(), now)
	unreviewed, _ := store.UnreviewedBreakglass(ctx, s.db.Reader())
	review := make([]reviewRow, 0, len(unreviewed))
	for _, g := range unreviewed {

		review = append(review, reviewRow{Grant: g, Open: g.Active(now), Overdue: store.ReviewOverdue(g, now)})
	}

	anchorAge, head := "never anchored", int64(0)
	if last, err := store.LatestAnchor(ctx, s.db.Reader()); err == nil {

		anchorAge = time.Since(last.AnchoredAt).Round(time.Second).String()
		head = last.Seq
	}
	notices, _ := store.ListNotifications(ctx, s.db.Reader(), store.NotificationFilter{
		Audience: store.AudienceOperator, Limit: 50,
	})
	open := map[string]bool{}
	for _, g := range openBG {

		open[g.TenantID] = true
	}
	tenants, err := store.ListTenants(ctx, s.db.Reader())
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	projects := make([]projectRow, 0, len(tenants))
	for _, t := range tenants {

		if t.DesiredState == store.DesiredDeleted {

			continue
		}
		row := projectRow{Tenant: t, BreakGlass: open[t.ID]}
		if a, err := store.LatestAttestation(ctx, s.db.Reader(), t.ID); err == nil {

			row.Outcome, row.Attested = a.Outcome, a.GeneratedAt
		}
		projects = append(projects, row)
	}
	s.render(w, req, "attestations.html", "Access", map[string]any{
		"Projects":        projects,
		"Mismatches":      mismatches,
		"BreakGlassOpen":  openBG,
		"BreakGlassLate":  overdueBG,
		"Unreviewed":      review,
		"AnchorAge":       anchorAge,
		"AnchoredSeq":     head,
		"Notices":         notices,
		"EnforcementNote": store.OutcomeEnforcementWithoutGrant,
	})
}

// attestNow regenerates one tenant's report from the host.
func (s *Server) attestNow(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	// On-demand attestation is operator-only (§8.4), as it is over the API,
	// where it lives under /admin. A viewer can read the latest report; it
	// cannot make the host walk netfilter and the proxy on request.
	if !s.isOperator(sess.actor) {

		back(w, req, "/", "", fmt.Errorf("%w: on-demand attestation is an operator action", identity.ErrForbidden))
		return
	}
	const to = "/attestations"
	t, err := s.operatorTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	if s.attest == nil {

		back(w, req, to, "", errors.New("attestation is not configured on this control plane"))
		return
	}
	rep, err := s.attest.Generate(ctx, t.ID)
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	back(w, req, to, t.Slug+" attested: "+rep.Outcome, nil)
}

// reaffirmGrant is a new owner confirming access inherited with the project.
func (s *Server) reaffirmGrant(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDownloadBackup)
	if err != nil {

		back(w, req, "/", "", err)
		return
	}
	to := "/t/" + t.ID
	// A grant decision, so it waits out a freeze like the API's (§14.5).
	if t.FrozenReason != "" {

		back(w, req, to, "", fmt.Errorf("%w: %s", reconcile.ErrFrozen, t.FrozenReason))
		return
	}
	g, err := store.GetGrant(ctx, s.db.Reader(), mux.Vars(req)["gid"])
	if err != nil || g.TenantID != t.ID {

		back(w, req, to, "", store.ErrGrantNotFound)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.Affirm(ctx, tx, g.ID, sess.actor.ID, time.Now().UTC()); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionGrantReaffirmed, SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{"kind": g.Kind, "subject": g.Subject},
		})
		return err
	})
	back(w, req, to, "re-affirmed "+g.Subject, err)
}
