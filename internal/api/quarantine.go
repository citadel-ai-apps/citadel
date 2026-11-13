package api

import (
	"errors"
	"net/http"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// quarantineTenant makes the edge return 503 for a tenant without touching its
// data (design §8.4, §12).
//
// This is the operator's alternative to a forced upgrade during a security
// incident. A force-upgrade ships the fix and may leave the instance broken on
// hooks written for an older binary; quarantine stops the exposure immediately
// and leaves the tenant to ship compatible code. D11 (design.md §12) makes
// quarantine the default and reserves force-upgrade for active exploitation.
//
// A reason is mandatory and is surfaced to the tenant verbatim. An operator
// action that makes someone's application unreachable with no stated cause is
// the kind of thing that erodes the record §14 exists to keep.
func (s *Server) quarantineTenant(w http.ResponseWriter, req *http.Request) {

	s.setQuarantine(w, req, true)
}

// unquarantineTenant lifts a quarantine. Also audited: the decision to expose
// an instance again is as accountable as the decision to hide it.
func (s *Server) unquarantineTenant(w http.ResponseWriter, req *http.Request) {

	s.setQuarantine(w, req, false)
}

type quarantineRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) setQuarantine(w http.ResponseWriter, req *http.Request, on bool) {

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
	// Lifting a quarantine carries no body, so an absent one is not an error
	// here the way it is on a create.
	var body quarantineRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	if on && body.Reason == "" {

		writeErr(w, http.StatusBadRequest,
			errors.New("a reason is required: it is shown to the tenant verbatim"))
		return
	}
	if t.Quarantined == on {

		writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "quarantined": on, "changed": false})
		return
	}

	action := auditlog.ActionTenantQuarantined
	if !on {

		action = auditlog.ActionTenantUnquarantined
	}
	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetQuarantined(ctx, tx, t.ID, on); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: action, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{"reason": body.Reason},
		})
		return err
	}); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}

	// Applied now rather than on the next tick: quarantine exists for the
	// moments when five seconds of continued exposure is the thing being
	// argued about.
	t.Quarantined = on
	if err := s.rec.RepublishRoute(ctx, t); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.ID, "quarantined": on, "changed": true, "reason": body.Reason,
	})
}

// unfreezeTenant lifts a §14.5 freeze. There is no API to set one: a freeze is
// what an attestation finding does, not an operator's choice. Lifting it is,
// and needs a reason, because it says the investigation is over.
func (s *Server) unfreezeTenant(w http.ResponseWriter, req *http.Request) {

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
	var body quarantineRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	if body.Reason == "" {

		writeErr(w, http.StatusBadRequest,
			errors.New("a reason is required: lifting a freeze records that the investigation is over"))
		return
	}
	if t.FrozenReason == "" {

		writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "frozen": false, "changed": false})
		return
	}
	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetFrozen(ctx, tx, t.ID, ""); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionTenantUnfrozen, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{"reason": body.Reason, "was": t.FrozenReason},
		})
		return err
	}); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "frozen": false, "changed": true})
}
