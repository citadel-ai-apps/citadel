package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// TransferRequest is POST /tenants/{id}/owner/transfer.
type TransferRequest struct {
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

// offerTransfer records an offer. It does NOT change who owns the tenant: the
// target has to accept (§14.1).
func (s *Server) offerTransfer(w http.ResponseWriter, req *http.Request) {

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
	var body TransferRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// An operator may reassign a tenant they do not own — the departed-owner
	// case — but identity.OfferTransfer then demands a reason, which the tenant
	// sees. Only the owner may transfer without one. Over TCP there is no
	// operator, so a reason is no substitute for the capability: without this a
	// token with no role could offer the tenant to itself and accept.
	if !isOperator(req) || (actor.Kind != identity.KindPlatform && body.Reason == "") {

		if err := s.requireCap(ctx, actor, t.ID, identity.CapTransfer); err != nil {

			err = s.hideForeignTenant(req, actor, t, err)
			writeErr(w, statusFor(err), err)
			return
		}
	}

	var tr store.OwnerTransfer
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		tr, err = s.ident.OfferTransfer(ctx, tx, actor, t.ID, body.To, body.Reason)
		if err != nil {

			return err
		}
		// An operator can reassign a tenant, but not quietly (§14.1). The
		// notice carries the reason verbatim and lands in the tenant's own feed.
		note := fmt.Sprintf("%s offered ownership of %s to %s.", actor.ID, t.Slug, body.To)
		if body.Reason != "" {

			note += " Reason given: " + body.Reason
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant,
			Kind: store.NotifyTransferOffered, SubjectRef: "transfer/" + tr.ID,
			Body: note,
		})
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, tr)
}

// acceptTransfer is the second party of the two-party operation. Only the
// principal the tenant was offered to can call it.
func (s *Server) acceptTransfer(w http.ResponseWriter, req *http.Request) {

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
	var (
		tr        store.OwnerTransfer
		inherited []store.Grant
	)
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		tr, inherited, err = s.ident.AcceptTransfer(ctx, tx, actor, t.ID)
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"transfer":  tr,
		"inherited": inherited,
		"note": fmt.Sprintf("Tier-2 access inherited with this project lapses in %d days "+
			"unless you re-affirm it", int(store.ReaffirmWindow.Hours()/24)),
	})
}

// reaffirmGrant is the new owner confirming one inherited grant.
func (s *Server) reaffirmGrant(w http.ResponseWriter, req *http.Request) {

	// CapDownloadBackup, not CapRequestGrant. A deployer may request Tier-1
	// access, and re-affirming is a Tier-2 act — the whole point of §14.7 is
	// that somebody senior enough to be accountable looks at the inherited set.
	// CapDownloadBackup is the capability that already separates owner/admin
	// from deployer.
	actor, t, err := s.authedTenant(req, identity.CapDownloadBackup)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// Re-affirming keeps an inherited grant in force past its due date, so it
	// is a grant decision, and a frozen tenant's access does not move (§14.5).
	if t.FrozenReason != "" {

		writeErr(w, statusFor(reconcile.ErrFrozen), fmt.Errorf("%w: %s", reconcile.ErrFrozen, t.FrozenReason))
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
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.Affirm(ctx, tx, g.ID, actor.ID, time.Now().UTC()); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionGrantReaffirmed,
			SubjectRef: "grant/" + g.ID,
			Detail:     map[string]any{"kind": g.Kind, "subject": g.Subject},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": g.ID, "reaffirmed_by": actor.ID})
}

// SuspendRequest is POST /admin/principals/{id}/suspend.
type SuspendRequest struct {
	// ReassignToPlatform passes custody of any tenants this principal owns to
	// the platform principal. Without it the suspension is REFUSED while they
	// own anything: INV-17 is never broken, and an orphaned tenant becomes a
	// visible backlog item rather than a NULL nobody notices.
	ReassignToPlatform bool `json:"reassign_to_platform"`
}

func (s *Server) suspendPrincipal(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body SuspendRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	id, err := identity.Canonical(pathID(req))
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		return s.ident.Suspend(ctx, tx, actor, id, body.ReassignToPlatform)
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"principal": id, "suspended": true, "reassigned": body.ReassignToPlatform,
	})
}

func (s *Server) declineTransfer(w http.ResponseWriter, req *http.Request) {

	s.closeTransfer(w, req, store.TransferDeclined)
}

func (s *Server) cancelTransfer(w http.ResponseWriter, req *http.Request) {

	s.closeTransfer(w, req, store.TransferCancelled)
}

func (s *Server) closeTransfer(w http.ResponseWriter, req *http.Request, outcome string) {

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
	// Declining is the target's, and identity.CloseTransfer checks that.
	// Cancelling is the offering side's: over TCP it needs the capability that
	// made the offer, or any token could void another tenant's handover.
	if outcome == store.TransferCancelled {

		if err := s.requireCapOverTCP(req, actor, t, identity.CapTransfer); err != nil {

			writeErr(w, statusFor(err), err)
			return
		}
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		return s.ident.CloseTransfer(ctx, tx, actor, t.ID, outcome)
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "outcome": outcome})
}
