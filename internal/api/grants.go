package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func (s *Server) listGrants(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rows, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{
		TenantID: t.ID, Decision: req.URL.Query().Get("decision"),
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	now := time.Now().UTC()
	out := make([]map[string]any, 0, len(rows))
	for _, g := range rows {

		out = append(out, map[string]any{"grant": g, "state": g.State(now), "active": g.Active(now)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "grants": out})
}

// GrantRequest is POST /tenants/{id}/grants: a capability asked for outside the
// manifest path, which is how every non-egress kind is requested.
type GrantRequest struct {
	Kind          string `json:"kind"`
	Subject       string `json:"subject"`
	Justification string `json:"justification,omitempty"`
}

func (s *Server) requestGrant(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapRequestGrant)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body GrantRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if t.FrozenReason != "" {

		writeErr(w, statusFor(reconcile.ErrFrozen), fmt.Errorf("%w: %s", reconcile.ErrFrozen, t.FrozenReason))
		return
	}

	ctx := req.Context()
	refused, err := store.SubjectWasRefused(ctx, s.db.Reader(), t.ID, body.Kind, body.Subject)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	d := grantpolicy.Classify(
		grantpolicy.Request{Kind: body.Kind, Subject: body.Subject},
		grantpolicy.TenantContext{PlatformDomains: []string{s.cfg.AppsDomain}, PreviouslyRefused: refused})
	if d.Tier == grantpolicy.TierDenied {

		writeErr(w, http.StatusUnprocessableEntity, fmt.Errorf("api: %s", d.Reason))
		return
	}
	// Tier 3 is break-glass, and break-glass has exactly one door: the
	// operator endpoint that time-boxes it, notifies the tenant and a second
	// operator, and enforces review (§14.3). A Tier-3 row created here would
	// be pending, and an ordinary approval could then open it for days with
	// none of that.
	if d.Tier == grantpolicy.TierBreakGlass {

		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"api: %s is break-glass; an operator opens it with `citadel breakglass`, never as an ordinary grant", body.Kind))
		return
	}

	now := time.Now().UTC()
	g := store.Grant{
		ID:            store.NewID("g"),
		TenantID:      t.ID,
		Kind:          body.Kind,
		Direction:     grantpolicy.Direction(body.Kind),
		Subject:       body.Subject,
		Tier:          d.Tier,
		Decision:      grantpolicy.DecisionFor(d.Tier),
		RequestedBy:   actor.ID,
		RequestedAt:   now,
		PolicyVersion: d.PolicyVersion,
		Justification: body.Justification,
		ExpiresAt:     now.Add(d.TTL),
	}
	action := auditlog.ActionGrantRequested
	if g.Decision == store.DecisionAutoApproved {

		g.DecidedBy = identity.PlatformPrincipal
		g.DecidedAt = &now
		action = auditlog.ActionGrantAutoApproved
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertGrant(ctx, tx, g); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     action,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"kind": g.Kind, "subject": g.Subject, "tier": g.Tier,
				"decision": g.Decision, "policy_version": g.PolicyVersion,
			},
		}); err != nil {

			return err
		}
		if g.Decision != store.DecisionPending {

			return nil
		}
		// A Tier-2 request that only appears in a queue somebody has to
		// remember to open is a request that ages. The queue is the operator's
		// working surface; this is what puts it in front of them.
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceOperator,
			Kind: store.NotifyGrantPending, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s requests %s access to %s. %s",
				t.Slug, g.Kind, g.Subject, d.Reason),
		})
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"grant": g, "reason": d.Reason})
}

// revokeGrant is a tenant withdrawing its own grant.
//
// §14.7: this is remembered. A later release re-declaring the same host gets a
// human decision rather than an automatic re-grant, so "revoke, then roll back"
// cannot quietly undo it.
func (s *Server) revokeGrant(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapRequestGrant)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	ctx := req.Context()
	g, err := store.GetGrant(ctx, s.db.Reader(), mux.Vars(req)["gid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if g.TenantID != t.ID {

		writeErr(w, http.StatusNotFound, fmt.Errorf("%w: %s", store.ErrGrantNotFound, g.ID))
		return
	}
	if err := s.revoke(ctx, actor, g); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": g.ID, "revoked": true})
}

func (s *Server) revoke(ctx context.Context, actor identity.Actor, g store.Grant) error {

	return s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.RevokeGrant(ctx, tx, g.ID, actor.ID); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action:     auditlog.ActionGrantRevoked,
			SubjectRef: "grant/" + g.ID,
			Detail:     map[string]any{"kind": g.Kind, "subject": g.Subject},
		})
		return err
	})
}

// adminGrants is the Tier-2 approval queue (§15: a queue that rots unseen is
// the failure mode, so it is oldest first).
func (s *Server) adminGrants(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	decision := req.URL.Query().Get("decision")
	if decision == "" {

		decision = store.DecisionPending
	}
	rows, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{
		TenantID: req.URL.Query().Get("tenant"), Decision: decision,
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {

		rows[i], rows[j] = rows[j], rows[i]
	}
	writeJSON(w, http.StatusOK, map[string]any{"decision": decision, "grants": rows})
}

// DecideGrantRequest is POST /admin/grants/{gid}/approve or /deny.
type DecideGrantRequest struct {
	Justification string `json:"justification,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

func (s *Server) approveGrant(w http.ResponseWriter, req *http.Request) { s.decideGrant(w, req, true) }

func (s *Server) denyGrant(w http.ResponseWriter, req *http.Request) { s.decideGrant(w, req, false) }

func (s *Server) decideGrant(w http.ResponseWriter, req *http.Request, approve bool) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body DecideGrantRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	g, err := store.GetGrant(ctx, s.db.Reader(), mux.Vars(req)["gid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// Break-glass is reviewed, never approved: it is self-approved and
	// time-boxed at the moment it is opened (§14.3).
	if g.Tier == grantpolicy.TierBreakGlass {

		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"api: %s is break-glass; it is opened and reviewed through the break-glass endpoints, not decided here", g.ID))
		return
	}
	// A frozen tenant's access does not change until the investigation is
	// over (§14.5) — in either direction, since a denial changes it too.
	if ft, err := store.GetTenant(ctx, s.db.Reader(), g.TenantID); err != nil {

		writeErr(w, statusFor(err), err)
		return

	} else if ft.FrozenReason != "" {

		writeErr(w, statusFor(reconcile.ErrFrozen), fmt.Errorf("%w: %s", reconcile.ErrFrozen, ft.FrozenReason))
		return
	}
	// Tier 2 is a NAMED HUMAN approver (§14.3). The platform principal and
	// service accounts decide nothing a person is accountable for.
	if actor.Kind != identity.KindPerson {

		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"%w: a grant decision is made by a named person, not by %s (%s)", identity.ErrForbidden, actor.ID, actor.Kind))
		return
	}

	decision, action := store.DecisionApproved, auditlog.ActionGrantApproved
	note := body.Justification
	if !approve {

		decision, action = store.DecisionDenied, auditlog.ActionGrantDenied
		note = body.Reason
	}
	// Tier 2 means a named approver AND a justification (§14.3). A denial's
	// reason is shown to the tenant verbatim, so an empty one is not acceptable
	// either: "denied" with no reason is what makes a platform feel arbitrary.
	if note == "" {

		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("api: a %s decision needs a justification; it is recorded and shown to the tenant", decision))
		return
	}
	// An approver may shorten a grant's life, never extend it past the §14.2
	// expiry for its kind: every grant expires, and the table is the ceiling.
	expires := time.Time{}
	if body.ExpiresInDays < 0 {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: expires_in_days cannot be negative"))
		return
	}
	if body.ExpiresInDays > 0 {

		now := time.Now().UTC()
		expires = now.AddDate(0, 0, body.ExpiresInDays)
		if ceiling := grantpolicy.DefaultTTL(g.Kind); ceiling > 0 && expires.After(now.Add(ceiling)) {

			writeErr(w, http.StatusUnprocessableEntity, fmt.Errorf(
				"api: %s grants expire after at most %s; %d days is longer", g.Kind, ceiling, body.ExpiresInDays))
			return
		}
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.DecideGrant(ctx, tx, g.ID, decision, actor.ID, note, expires); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action:     action,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"kind": g.Kind, "subject": g.Subject, "tier": g.Tier,
				"reason": note,
			},
		}); err != nil {

			return err
		}
		// The reason reaches the tenant verbatim, including on a denial. A
		// denial the requester only discovers as a connection that keeps
		// failing is the shape §9.4 exists to avoid.
		return store.Notify(ctx, tx, store.Notification{
			TenantID: g.TenantID, Audience: store.AudienceTenant,
			Kind: store.NotifyGrantDecided, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s access to %s was %s by %s: %s",
				g.Kind, g.Subject, decision, actor.ID, note),
		})
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	out, err := store.GetGrant(ctx, s.db.Reader(), g.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
