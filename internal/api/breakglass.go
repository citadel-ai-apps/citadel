package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// BreakglassRequest is POST /admin/tenants/{id}/breakglass.
type BreakglassRequest struct {
	Reason string `json:"reason"`
	// Scope is what is being opened: pb_data, a snapshot id, or a portal
	// session for support_impersonation. Recorded as the grant subject.
	Scope string `json:"scope,omitempty"`
	Kind  string `json:"kind,omitempty"`
}

// breakglass opens a Tier-3 grant: an operator needs a tenant's data now,
// mid-incident, and waiting for a second approver is not viable.
//
// The honest design does not pretend to prevent this. A root operator can read
// the bind mount regardless, so pretending otherwise would buy nothing and cost
// the restore path. What this makes it instead is loud and expensive:
//
//   - a reason is mandatory and is shown to the tenant verbatim;
//   - the box is hard, 60 minutes, and not extendable — ask again;
//   - the tenant AND a second operator are told at grant time, not at review
//     time, which is the property that makes the whole path honest rather than
//     merely logged;
//   - an unreviewed past session blocks the same principal from opening another.
func (s *Server) breakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	t, err := s.tenantFrom(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body BreakglassRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Reason == "" {

		writeErr(w, http.StatusBadRequest, fmt.Errorf(
			"api: break-glass needs a reason; it is shown to the tenant verbatim"))
		return
	}
	kind := body.Kind
	if kind == "" {

		kind = store.GrantOperatorDataAccess
	}
	if kind != store.GrantOperatorDataAccess && kind != store.GrantSupportImpersonate {

		writeErr(w, http.StatusBadRequest, fmt.Errorf(
			"api: %s is not a break-glass kind; use %s or %s",
			kind, store.GrantOperatorDataAccess, store.GrantSupportImpersonate))
		return
	}
	scope := body.Scope
	if scope == "" {

		scope = "pb_data"
	}

	// The block. Cleared by someone OTHER than the requester reviewing the
	// earlier session, so it is not something the operator can dismiss for
	// themselves.
	now := time.Now().UTC()
	outstanding, err := store.UnreviewedBreakglass(ctx, s.db.Reader(), actor.ID, now)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if len(outstanding) > 0 {

		ids := make([]string, 0, len(outstanding))
		for _, g := range outstanding {

			ids = append(ids, g.ID)
		}
		writeErr(w, http.StatusConflict, fmt.Errorf(
			"api: %s has break-glass sessions past their 24h review (%s); another operator must review them first",
			actor.ID, strings.Join(ids, ", ")))
		return
	}

	g := store.Grant{
		ID:            store.NewID("g"),
		TenantID:      t.ID,
		Kind:          kind,
		Direction:     store.DirectionInbound,
		Subject:       scope,
		Tier:          grantpolicy.TierBreakGlass,
		Decision:      store.DecisionApproved,
		RequestedBy:   actor.ID,
		RequestedAt:   now,
		DecidedBy:     actor.ID, // self-approved, and the record says so
		DecidedAt:     &now,
		PolicyVersion: grantpolicy.PolicyVersion,
		Justification: body.Reason,
		// Hard box. Not derived from grantpolicy's default TTL, because that is
		// a policy knob and this one is not negotiable.
		ExpiresAt: now.Add(store.BreakglassTTL),
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertGrant(ctx, tx, g); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionBreakglassOpened,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"kind": g.Kind, "scope": g.Subject, "reason": g.Justification,
				"expires_at": g.ExpiresAt.Format(time.RFC3339),
			},
		}); err != nil {

			return err
		}
		// Both notices in this transaction, with the grant itself. An operator
		// opening a customer's database learns the customer is being told as it
		// happens — which is only true if the telling cannot fail separately
		// from the opening.
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassOpened, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s opened break-glass access to your %s until %s. Reason given: %s",
				actor.ID, g.Subject, g.ExpiresAt.Format(time.RFC3339), g.Justification),
		}); err != nil {

			return err
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceOperator,
			Kind: store.NotifyBreakglassOpened, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s opened break-glass on %s (%s). Review it within 24h: %s",
				actor.ID, t.Slug, g.Subject, g.Justification),
		})
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"grant":       g,
		"expires_at":  g.ExpiresAt,
		"notified":    []string{"tenant", "operators"},
		"review_due":  g.RequestedAt.Add(store.ReviewWindow),
		"extendable":  false,
		"review_note": "not extendable; request again if 60 minutes is not enough",
	})
}

// ReviewRequest is POST /admin/grants/{gid}/review.
type ReviewRequest struct {
	Outcome string `json:"outcome"` // justified | unjustified
	Notes   string `json:"notes"`
}

// reviewBreakglass records the 24-hour review.
//
// Refused from the requester. A self-reviewed break-glass is not a review, and
// letting one clear the block would make the block decorative.
func (s *Server) reviewBreakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body ReviewRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Outcome != store.ReviewJustified && body.Outcome != store.ReviewUnjustified {

		writeErr(w, http.StatusBadRequest, fmt.Errorf(
			"api: outcome must be %s or %s", store.ReviewJustified, store.ReviewUnjustified))
		return
	}
	if strings.TrimSpace(body.Notes) == "" {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: a review needs notes"))
		return
	}
	g, err := store.GetGrant(ctx, s.db.Reader(), mux.Vars(req)["gid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if g.Tier != grantpolicy.TierBreakGlass {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: %s is not a break-glass grant", g.ID))
		return
	}
	if g.RequestedBy == actor.ID {

		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"api: a break-glass session is reviewed by someone other than the operator who opened it"))
		return
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertReview(ctx, tx, store.BreakglassReview{
			GrantID: g.ID, ReviewedBy: actor.ID, Outcome: body.Outcome, Notes: body.Notes,
		}); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action:     auditlog.ActionBreakglassReviewed,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"outcome": body.Outcome, "opened_by": g.RequestedBy, "notes": body.Notes,
			},
		}); err != nil {

			return err
		}
		// The tenant sees the verdict on the access to their own data, not just
		// the access.
		return store.Notify(ctx, tx, store.Notification{
			TenantID: g.TenantID, Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassOpened, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("The break-glass access %s took to your %s was reviewed by %s and found %s: %s",
				g.RequestedBy, g.Subject, actor.ID, body.Outcome, body.Notes),
		})
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": g.ID, "reviewed_by": actor.ID, "outcome": body.Outcome})
}

// breakglassList is the fleet's open and overdue sessions (§15).
func (s *Server) breakglassList(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	now := time.Now().UTC()
	open, err := store.OpenBreakglass(ctx, s.db.Reader(), now)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	overdue, err := store.OverdueBreakglass(ctx, s.db.Reader(), now)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "unreviewed_past_24h": overdue})
}
