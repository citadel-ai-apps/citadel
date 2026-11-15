package api

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/citadel-ai-apps/citadel/internal/breakglass"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// BreakglassRequest is POST /admin/tenants/{id}/breakglass.
type BreakglassRequest = breakglass.Request

// breakglass opens a Tier-3 grant. The terms live in internal/breakglass,
// shared with the portal's open form so the two doors cannot drift.
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
	g, err := s.bg.Open(ctx, actor, t, body)
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
		"portal_path": "/t/" + t.Slug,
	})
}

// ReviewRequest is POST /admin/grants/{gid}/review.
type ReviewRequest struct {
	Outcome string `json:"outcome"` // justified | unjustified
	Notes   string `json:"notes"`
}

// reviewBreakglass records the verdict on a session (breakglass.Review).
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
	g, err := s.bg.Review(ctx, actor, mux.Vars(req)["gid"], body.Outcome, body.Notes)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": g.ID, "reviewed_by": actor.ID, "outcome": body.Outcome})
}

// CloseRequest is POST /admin/grants/{gid}/close.
type CloseRequest struct {
	Reason string `json:"reason,omitempty"`
}

// closeBreakglass ends a session before its box runs out: the requester, done
// early, or another operator. Never the tenant (see breakglass.Close).
func (s *Server) closeBreakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body CloseRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	g, err := s.bg.Close(ctx, actor, mux.Vars(req)["gid"], body.Reason)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": g.ID, "closed_by": actor.ID, "opened_by": g.RequestedBy})
}

// breakglassList is the fleet's open sessions and every unreviewed one, with
// the overdue subset that blocks its openers (§15).
func (s *Server) breakglassList(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	now := time.Now().UTC()
	open, err := store.OpenBreakglass(ctx, s.db.Reader(), now)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	unreviewed, err := store.UnreviewedBreakglass(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	overdue := make([]store.Grant, 0, len(unreviewed))
	for _, g := range unreviewed {

		if store.ReviewOverdue(g, now) {

			overdue = append(overdue, g)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "unreviewed": unreviewed, "overdue": overdue})
}
