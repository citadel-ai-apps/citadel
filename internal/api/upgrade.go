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

// UpgradeRequest is the body of POST /tenants/{id}/upgrade (§8.4).
type UpgradeRequest struct {
	To string `json:"to"`
	// Rehearse is a pointer so its ABSENCE means yes. A rehearsal is the
	// default, and a caller who wants to skip it has to say so — which, being
	// operator-only, they can only do on the admin listener.
	Rehearse     *bool `json:"rehearse,omitempty"`
	RehearseOnly bool  `json:"rehearse_only,omitempty"`
	Force        bool  `json:"force,omitempty"`
}

// upgradeTenant opens an upgrade job and answers 202 with it.
//
// 202, not 200: the job has started, and the work is minutes away from done.
// GET /upgrade/{jobid} is how the caller finds out what happened.
func (s *Server) upgradeTenant(w http.ResponseWriter, req *http.Request) {

	// An upgrade is at least as consequential as a deploy and no more so: both
	// replace what the tenant's users talk to. A fifth capability would mean
	// changing §14.1's role table for no added safety.
	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body UpgradeRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.To == "" {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("`to` is required: name the version to upgrade to"))
		return
	}
	skip := body.Rehearse != nil && !*body.Rehearse
	if (skip || body.Force) && !isOperator(req) {

		// Skipping the rehearsal or overriding the compatibility gate is an
		// operator decision taken with the consequences in view, not something
		// a tenant token can do to itself.
		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"`rehearse: false` and `force` are operator-only; a tenant upgrade always rehearses first"))
		return
	}
	job, err := s.rec.StartUpgrade(req.Context(), actor, t, reconcile.UpgradeRequest{
		To:            body.To,
		RehearseOnly:  body.RehearseOnly,
		SkipRehearsal: skip,
		Forced:        body.Force,
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// upgradeJob returns one job, which is how a caller follows the ladder.
func (s *Server) upgradeJob(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	job, err := store.GetUpgradeJob(ctx, s.db.Reader(), mux.Vars(req)["jobid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if job.TenantID != t.ID {

		// Answered as not-found rather than forbidden: confirming that a job id
		// exists under another tenant is itself information.
		writeErr(w, http.StatusNotFound, store.ErrUpgradeJobNotFound)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// listUpgrades returns a tenant's recent jobs, newest first.
func (s *Server) listUpgrades(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	jobs, err := store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{TenantID: t.ID})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "upgrades": jobs})
}

// adminUpgrades is the operator's cross-tenant queue.
func (s *Server) adminUpgrades(w http.ResponseWriter, req *http.Request) {

	f := store.UpgradeJobFilter{State: req.URL.Query().Get("state"), Limit: 100}
	if req.URL.Query().Get("active") == "true" {

		f.Active = true
	}
	jobs, err := store.ListUpgradeJobs(req.Context(), s.db.Reader(), f)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"upgrades": jobs})
}

// RestoreRequest is the body of POST /tenants/{id}/backups/{bid}/restore.
type RestoreRequest struct {
	// Force overrides the pb_version guard. Operator-only. A forced restore
	// across runtime versions leaves the instance stopped: the operator pins
	// the runtime to the snapshot's version before starting it (design.md §12).
	Force bool `json:"force,omitempty"`
}

// restoreBackup writes a snapshot back over a tenant's data.
//
// Destructive and deliberately not reversible-by-default: the data currently in
// pb_data is replaced. It is gated on CapDeploy for the same reason an upgrade
// is, and the version guard in internal/backup is what stops the most damaging
// version of the mistake — an old snapshot re-triggering the one-way migration
// on a newer binary (INV-4).
func (s *Server) restoreBackup(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body RestoreRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	if body.Force && !isOperator(req) {

		writeErr(w, http.StatusForbidden, fmt.Errorf(
			"`force` is operator-only: it disables the check that stops an older snapshot re-triggering the one-way migration"))
		return
	}
	b, err := store.GetBackup(ctx, s.db.Reader(), mux.Vars(req)["bid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if b.TenantID != t.ID {

		writeErr(w, http.StatusNotFound, store.ErrBackupNotFound)
		return
	}
	out, err := s.rec.RestoreBackup(ctx, actor, t, b, body.Force)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.ID, "backup": b.ID, "restored": true, "forced": body.Force,
		"left_stopped": out.LeftStopped, "hint": out.Hint,
	})
}

// PinRuntimeRequest is the body of POST /admin/tenants/{id}/pin-runtime.
type PinRuntimeRequest struct {
	Version       string `json:"version"`
	Justification string `json:"justification"`
}

// pinRuntime points a stopped tenant at a registered runtime version (INV-4,
// INV-11). Operator-only by virtue of the /admin subrouter.
func (s *Server) pinRuntime(w http.ResponseWriter, req *http.Request) {

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
	var body PinRuntimeRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Version == "" {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: version is required"))
		return
	}
	out, err := s.rec.PinRuntime(ctx, actor, t.ID, body.Version, body.Justification)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": out.ID, "runtime_version": out.RuntimeVersion, "image_digest": out.ImageDigest,
	})
}

// SetVersionStateRequest is the body of POST
// /admin/runtime-versions/{version}/state.
type SetVersionStateRequest struct {
	State string `json:"state"`
	// EOLAt is required when entering `deprecated`: §12 publishes the date on
	// entry to the state, because a deprecation with no date is a nag nobody
	// can plan around.
	EOLAt string `json:"eol_at,omitempty"`
}

// setRuntimeVersionState moves a version along the §12 lifecycle.
func (s *Server) setRuntimeVersionState(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body SetVersionStateRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	version := mux.Vars(req)["version"]
	var eolAt *time.Time
	if body.EOLAt != "" {

		parsed, err := parseDate(body.EOLAt)
		if err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
		eolAt = &parsed
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetVersionState(ctx, tx, version, body.State, eolAt); err != nil {

			return err
		}
		detail := map[string]any{"state": body.State}
		if eolAt != nil {

			detail["eol_at"] = eolAt.Format(time.RFC3339)
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action:     auditlog.ActionVersionStateChanged,
			SubjectRef: "runtime_version/" + version,
			Detail:     detail,
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rv, err := store.GetRuntimeVersion(ctx, s.db.Reader(), version)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, rv)
}

// parseDate accepts a date or a full timestamp, so an operator can write
// `--eol-at 2026-12-01` without looking up a format.
func parseDate(s string) (time.Time, error) {

	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {

		if t, err := time.Parse(layout, s); err == nil {

			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not a date (YYYY-MM-DD) or an RFC3339 timestamp", s)
}

// orNone renders an empty id for an audit detail, which rejects nothing but
// reads badly when a field is silently absent.
func orNone(s string) string {

	if s == "" {

		return "(none)"
	}
	return s
}
