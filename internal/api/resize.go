package api

import (
	"net/http"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

type resizeRequest struct {
	MemMiB int `json:"mem_mib"`
}

// resizeTenant changes a tenant's memory limit (operator only).
//
// Only the row changes here. On its next tick the reconciler sees that the
// running container's limit differs from the spec and recreates the container.
// The data is on a bind mount, so it survives; the tenant is down for as long
// as a recreate takes. Create and resize share the same validation, so a
// tenant cannot be resized below the floor that create refuses.
func (s *Server) resizeTenant(w http.ResponseWriter, req *http.Request) {

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
	var body resizeRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := reconcile.ValidateMemMiB(s.cfg.TenantRuntime, body.MemMiB); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if t.MemMiB == body.MemMiB {

		writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "mem_mib": t.MemMiB, "changed": false})
		return
	}

	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetMemMiB(ctx, tx, t.ID, body.MemMiB); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionTenantResized, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{"from_mem_mib": t.MemMiB, "to_mem_mib": body.MemMiB},
		})
		return err
	}); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.ID, "mem_mib": body.MemMiB, "from_mem_mib": t.MemMiB, "changed": true,
	})
}
