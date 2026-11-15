package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// routes registers the §8.4 surface.
//
// The admin and tenant halves are separate subrouters because §8.4 gives them
// different audiences. Authentication is not per-subrouter middleware: it
// happens once, per listener, in SocketHandler and APIHandler, so a route
// cannot be added to the wrong half and silently skip it. The operator gate IS
// on the admin subrouter, for the same reason: any route added there is
// operator-only without its handler having to remember.
func (s *Server) routes() {

	v1 := s.router.PathPrefix("/api/v1").Subrouter()

	admin := v1.PathPrefix("/admin").Subrouter()
	admin.Use(operatorOnly)
	admin.HandleFunc("/tenants", s.createTenant).Methods(http.MethodPost)
	admin.HandleFunc("/tenants", s.listTenants).Methods(http.MethodGet)
	admin.HandleFunc("/tenants/{id}", s.destroyTenant).Methods(http.MethodDelete)
	admin.HandleFunc("/tenants/{id}/resize", s.resizeTenant).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}/quarantine", s.quarantineTenant).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}/quarantine", s.unquarantineTenant).Methods(http.MethodDelete)
	admin.HandleFunc("/tenants/{id}/pin-runtime", s.pinRuntime).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}/freeze", s.unfreezeTenant).Methods(http.MethodDelete)
	admin.HandleFunc("/fleet", s.fleet).Methods(http.MethodGet)
	admin.HandleFunc("/runtime-versions", s.addRuntimeVersion).Methods(http.MethodPost)
	admin.HandleFunc("/runtime-versions", s.listRuntimeVersions).Methods(http.MethodGet)
	admin.HandleFunc("/runtime-versions/{version}/state", s.setRuntimeVersionState).Methods(http.MethodPost)
	admin.HandleFunc("/upgrades", s.adminUpgrades).Methods(http.MethodGet)
	admin.HandleFunc("/principals", s.createPrincipal).Methods(http.MethodPost)
	admin.HandleFunc("/principals", s.listPrincipals).Methods(http.MethodGet)
	admin.HandleFunc("/principals/{id}/password", s.setPassword).Methods(http.MethodPost)
	admin.HandleFunc("/principals/{id}/operator", s.setOperator).Methods(http.MethodPost)
	admin.HandleFunc("/audit", s.queryAudit).Methods(http.MethodGet)
	admin.HandleFunc("/audit/verify", s.verifyAudit).Methods(http.MethodGet)
	admin.HandleFunc("/audit/export", s.exportAudit).Methods(http.MethodGet)
	admin.HandleFunc("/principals/{id}/suspend", s.suspendPrincipal).Methods(http.MethodPost)
	admin.HandleFunc("/attestations", s.adminAttestations).Methods(http.MethodGet)
	admin.HandleFunc("/breakglass", s.breakglassList).Methods(http.MethodGet)
	admin.HandleFunc("/tenants/{id}/attestation", s.adminAttestation).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}/breakglass", s.breakglass).Methods(http.MethodPost)
	admin.HandleFunc("/grants/{gid}/review", s.reviewBreakglass).Methods(http.MethodPost)
	admin.HandleFunc("/grants/{gid}/close", s.closeBreakglass).Methods(http.MethodPost)
	admin.HandleFunc("/grants", s.adminGrants).Methods(http.MethodGet)
	admin.HandleFunc("/grants/{gid}/approve", s.approveGrant).Methods(http.MethodPost)
	admin.HandleFunc("/grants/{gid}/deny", s.denyGrant).Methods(http.MethodPost)
	admin.HandleFunc("/tokens", s.createToken).Methods(http.MethodPost)
	admin.HandleFunc("/tokens", s.listTokens).Methods(http.MethodGet)
	admin.HandleFunc("/tokens/{id}", s.revokeToken).Methods(http.MethodDelete)

	tenants := v1.PathPrefix("/tenants").Subrouter()
	tenants.HandleFunc("/{id}", s.tenantStatus).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/start", s.startTenant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/stop", s.stopTenant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/restart", s.restartTenant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/logs", s.tenantLogs).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/owner", s.tenantOwner).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/owner/transfer", s.offerTransfer).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/owner/accept", s.acceptTransfer).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/owner/decline", s.declineTransfer).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/owner/cancel", s.cancelTransfer).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/releases", s.uploadRelease).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/releases", s.listReleases).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/releases/{rid}", s.tenantReleaseManifest).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/releases/{rid}/download", s.downloadRelease).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/releases/{rid}/deploy", s.deployRelease).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/rollback", s.rollbackTenant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/backups", s.listBackups).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/backups", s.createBackup).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/backups/{bid}/restore", s.restoreBackup).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/upgrade", s.upgradeTenant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/upgrade", s.listUpgrades).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/upgrade/{jobid}", s.upgradeJob).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/egress", s.tenantEgress).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/grants", s.listGrants).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/grants", s.requestGrant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/grants/{gid}", s.revokeGrant).Methods(http.MethodDelete)
	tenants.HandleFunc("/{id}/grants/{gid}/reaffirm", s.reaffirmGrant).Methods(http.MethodPost)
	tenants.HandleFunc("/{id}/attestation", s.tenantAttestation).Methods(http.MethodGet)
	tenants.HandleFunc("/{id}/access-log", s.tenantAccessLog).Methods(http.MethodGet)

	// Gorilla's defaults are plain text. citadel decodes every response as the
	// apiError envelope, so an unrouted request must speak the same shape.
	s.router.NotFoundHandler = http.HandlerFunc(s.noRoute)
	s.router.MethodNotAllowedHandler = http.HandlerFunc(s.methodNotAllowed)
}

// probeMethods are the verbs noRoute re-tries a request with.
var probeMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete,
}

// noRoute answers a request that matched nothing, distinguishing "wrong verb"
// from "no such endpoint".
//
// Gorilla clears its own method-mismatch signal as soon as any matcher on a
// later sibling route matches — and every route under a subrouter inherits that
// subrouter's path-prefix matcher, so PUT /api/v1/admin/tenants reaches here as
// a plain 404. The stdlib ServeMux this API replaced answered 405, which is the
// more useful of the two for an operator reading citadel output, so the check is
// redone here: re-match the same path under the other verbs.
func (s *Server) noRoute(w http.ResponseWriter, req *http.Request) {

	for _, m := range probeMethods {

		if m == req.Method {

			continue
		}
		probe := req.Clone(req.Context())
		probe.Method = m
		var match mux.RouteMatch
		// MatchErr nil means a real route, not the fallback handlers below.
		if s.router.Match(probe, &match) && match.MatchErr == nil {

			s.methodNotAllowed(w, req)
			return
		}
	}
	writeErr(w, http.StatusNotFound, fmt.Errorf("api: no route for %s %s", req.Method, req.URL.Path))
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, req *http.Request) {

	writeErr(w, http.StatusMethodNotAllowed,
		fmt.Errorf("api: %s is not allowed on %s", req.Method, req.URL.Path))
}

// pathID returns the {id} path variable.
func pathID(req *http.Request) string { return mux.Vars(req)["id"] }

// CreateTenantRequest is POST /admin/tenants.
type CreateTenantRequest struct {
	Slug      string  `json:"slug"`
	PBVersion string  `json:"pb_version"`
	Owner     string  `json:"owner"`
	AppDir    string  `json:"app_dir,omitempty"`
	CPUs      float64 `json:"cpus,omitempty"`
	MemMiB    int     `json:"mem_mib,omitempty"`
	DiskMiB   int     `json:"disk_mib,omitempty"`
	BodyCap   string  `json:"body_cap,omitempty"`
}

func (s *Server) createTenant(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body CreateTenantRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	owner := body.Owner
	if owner == "" {

		// A tenant cannot exist without an accountable owner. The creator is
		// the natural default, and it is still a real principal.
		owner = actor.ID
	}
	t, err := s.rec.Provision(ctx, actor, reconcile.ProvisionRequest{
		Slug:      body.Slug,
		PBVersion: body.PBVersion,
		OwnerID:   owner,
		AppDir:    body.AppDir,
		CPUs:      body.CPUs,
		MemMiB:    body.MemMiB,
		DiskMiB:   body.DiskMiB,
		BodyCap:   body.BodyCap,
	})
	if err != nil {

		// The tenant row may exist even on error: the reconciler keeps
		// converging, so the caller is told what went wrong AND what exists.
		writeJSON(w, statusFor(err), map[string]any{"error": err.Error(), "tenant": t})
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) listTenants(w http.ResponseWriter, req *http.Request) {

	tenants, err := store.ListTenants(req.Context(), s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	out := make([]map[string]any, 0, len(tenants))
	for _, t := range tenants {

		in, _ := store.GetInstance(req.Context(), s.db.Reader(), t.ID)
		owner, _ := s.ident.CurrentOwner(req.Context(), t.ID)
		out = append(out, map[string]any{"tenant": t, "instance": in, "owner": owner})
	}
	writeJSON(w, http.StatusOK, out)
}

// DestroyRequest is DELETE /admin/tenants/{id}.
type DestroyRequest struct {
	// NoBackup skips the final snapshot §8.3 takes on delete.
	//
	// An opt-out, not an acknowledgement: the snapshot happens by default, and
	// a caller who does not want one has to say so. It outlives the tenant per
	// D10, which is the point — "destroy" and "destroy irrecoverably" should
	// not be the same request.
	NoBackup bool `json:"no_backup"`
	// Purge destroys the tenant's data image, mount point and encryption keys
	// instead of retaining them. Default is to retain (D10).
	Purge bool `json:"purge"`
}

func (s *Server) destroyTenant(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body DestroyRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	t, err := s.tenantFrom(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}

	// The final snapshot is taken HERE rather than in the reconciler's teardown,
	// and synchronously. Two reasons: it is attributed to the principal who
	// asked for the destruction rather than to the platform, and a snapshot that
	// fails must abort the destroy — which it cannot do once the row says
	// `deleted` and the tick owns what happens next.
	finalBackup := ""
	if !body.NoBackup {

		b, err := s.rec.Snapshot(ctx, actor, t, store.BackupManual)
		if err != nil {

			writeErr(w, statusFor(err), fmt.Errorf(
				"the final snapshot failed, so nothing was destroyed: %w; pass --no-backup to destroy without one", err))
			return
		}
		finalBackup = b.ID
	}

	// The reconciler owns teardown, so the sequence and its ordering live in one
	// place. The API records the intent and the decision behind it.
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetDesiredState(ctx, tx, t.ID, store.DesiredDeleted); err != nil {

			return err
		}
		if body.Purge {

			if err := store.SetPurgeOnDelete(ctx, tx, t.ID); err != nil {

				return err
			}
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionTenantDesiredState,
			SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{
				"desired_state": store.DesiredDeleted,
				"final_backup":  orNone(finalBackup),
				"purge_data":    body.Purge,
			},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"tenant": t.ID, "desired_state": store.DesiredDeleted, "purge_data": body.Purge,
		"final_backup": finalBackup,
		"note":         "teardown happens on the next reconcile tick; the tenant's audit rows are retained",
	})
}

func (s *Server) setDesired(w http.ResponseWriter, req *http.Request, state, action string) {

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
	if err := s.requireCapOverTCP(req, actor, t, identity.CapDeploy); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetDesiredState(ctx, tx, t.ID, state); err != nil {

			return err
		}
		if state == store.DesiredRunning {

			// Clear the restart ladder: an operator asking for a start is
			// saying "try again", and a failed instance must be startable.
			if err := store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
				RestartCount:  new(0),
				ObservedState: new(store.ObservedStopped),
				LastError:     new(""),
			}); err != nil {

				return err
			}
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     action,
			SubjectRef: "tenant/" + t.ID,
			Detail:     map[string]any{"desired_state": state},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"tenant": t.ID, "desired_state": state})
}

func (s *Server) startTenant(w http.ResponseWriter, req *http.Request) {

	s.setDesired(w, req, store.DesiredRunning, auditlog.ActionTenantDesiredState)
}

func (s *Server) stopTenant(w http.ResponseWriter, req *http.Request) {

	s.setDesired(w, req, store.DesiredStopped, auditlog.ActionTenantDesiredState)
}

// restartTenant stops and re-materialises the tenant in one operation.
//
// Synchronous rather than a desired-state flip, because "restart" means the
// caller wants to know whether it came back.
func (s *Server) restartTenant(w http.ResponseWriter, req *http.Request) {

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
	if err := s.requireCapOverTCP(req, actor, t, identity.CapDeploy); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpdateInstance(ctx, tx, t.ID, store.InstanceUpdate{
			RestartCount: new(0),
			LastError:    new(""),
		}); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionTenantRestarted, SubjectRef: "tenant/" + t.ID,
		})
		return err
	}); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if err := s.rec.Materialise(ctx, t); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "restarted": true})
}

func (s *Server) tenantStatus(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	in, err := store.GetInstance(ctx, s.db.Reader(), t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	owner, _ := s.ident.CurrentOwner(ctx, t.ID)

	out := map[string]any{"tenant": t, "instance": in, "owner": owner}

	// Usable space, not the image size: data.img is sized above the nominal
	// quota for filesystem overhead, so the two differ (design.md §7).
	if used, avail, err := s.fs.Usage(t.ID); err == nil {

		out["disk"] = map[string]any{"used_bytes": used, "available_bytes": avail}
	}

	// Per-tenant CPU and memory (§15). Best-effort: a stopped instance has no
	// stats, and that is not an error worth failing the whole status call over.
	if in.ObservedState == store.ObservedHealthy || in.ObservedState == store.ObservedStarting {

		if st, err := s.drv.Stats(ctx, driver.Handle{TenantID: t.ID, Name: containerName(t)}); err == nil {

			out["stats"] = st
		}
	}

	// Per-tenant drift, so `citadel tenant status` shows a digest drift
	// rather than only the fleet view doing so.
	var mine []reconcile.Drift
	for _, d := range s.rec.Drift().List() {

		if d.TenantID == t.ID {

			mine = append(mine, d)
		}
	}
	out["drift"] = mine
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) tenantLogs(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	follow := req.URL.Query().Get("follow") == "1"
	tail := req.URL.Query().Get("tail")
	if tail == "" {

		tail = "200"
	}
	// Container stdout/stderr is the whole observability path: the image has no
	// shell, so there is nothing to exec into (§15).
	rc, err := s.drv.Logs(ctx, driver.Handle{TenantID: t.ID, Name: containerName(t)},
		driver.LogOpts{Follow: follow, Tail: tail})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {

		n, err := rc.Read(buf)
		if n > 0 {

			if _, werr := w.Write(buf[:n]); werr != nil {

				return
			}
			if flusher != nil {

				flusher.Flush()
			}
		}
		if err != nil {

			return
		}
	}
}

func (s *Server) tenantOwner(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	current, err := s.ident.CurrentOwner(ctx, t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// The full history, not just the current owner: "who owned this in March"
	// has to be a query (§14.1), which is why ownership is a history table.
	history, err := s.ident.History(ctx, t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	pending, hasPending, err := s.ident.PendingTransfer(ctx, t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	transfers, err := s.ident.Transfers(ctx, t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	out := map[string]any{
		"tenant": t.ID, "current_owner": current,
		"orphaned": t.OwnerOrphaned, "history": history,
		"transfers": transfers,
	}
	if hasPending {

		out["pending_transfer"] = pending
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) fleet(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	tenants, err := store.ListTenants(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	byVersion := map[string]int{}
	var failed, unhealthy, orphaned, quarantined, withEgress []string
	for _, t := range tenants {

		byVersion[t.RuntimeVersion]++
		if t.OwnerOrphaned {

			orphaned = append(orphaned, t.ID)
		}
		if t.Quarantined {

			quarantined = append(quarantined, t.ID)
		}
		if t.EgressEnabled {

			// §14.5's fleet attestation in miniature: the set of tenants that
			// can reach anything outside the sandbox at all is the platform's
			// real outbound blast radius, and it belongs on one screen.
			withEgress = append(withEgress, t.ID)
		}
		in, err := store.GetInstance(ctx, s.db.Reader(), t.ID)
		if err != nil {

			continue
		}
		switch in.ObservedState {

		case store.ObservedFailed:
			failed = append(failed, t.ID)
		case store.ObservedUnhealthy:
			unhealthy = append(unhealthy, t.ID)
		}
	}
	// Anchors, not a bare recompute. A recompute that agrees with itself is
	// exactly what a wholesale rewrite looks like, so the fleet view's chain
	// row would otherwise read green through the one failure it exists to show.
	anchors, err := store.ListAnchors(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	pub := ""
	if s.signer != nil {

		pub = s.signer.PublicKey()
	}
	chain, err := s.verifyChain(ctx, anchors, pub)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	anchorAge := "never anchored"
	if last, err := store.LatestAnchor(ctx, s.db.Reader()); err == nil {

		anchorAge = time.Since(last.AnchoredAt).Round(time.Second).String()
	}

	now := time.Now().UTC()
	pending, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{Decision: store.DecisionPending})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// Oldest first. The list is a work queue, and a queue sorted newest-first
	// buries exactly the request that has been waiting longest (§15).
	slices.Reverse(pending)
	// Grants expiring in the next 30 days, so renewals are discovered as a list
	// rather than as an outage.
	var expiring []store.Grant
	soon, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	for _, g := range soon {

		if g.Active(now) && g.ExpiresAt.Before(now.AddDate(0, 0, 30)) {

			expiring = append(expiring, g)
		}
	}
	openBG, err := store.OpenBreakglass(ctx, s.db.Reader(), now)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	unreviewedBG, err := store.UnreviewedBreakglass(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	overdueBG := make([]store.Grant, 0, len(unreviewedBG))
	for _, g := range unreviewedBG {

		if store.ReviewOverdue(g, now) {

			overdueBG = append(overdueBG, g)
		}
	}
	mismatches, err := store.Mismatches(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// Top egress denials: both a security signal and a support signal (§15).
	// One tenant suddenly refusing a thousand calls to a host it never asked
	// for reads very differently from ten tenants refusing one each.
	denials, err := store.TopDenials(ctx, s.db.Reader(), 20)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	upgrades, err := s.upgradeFleet(ctx, tenants)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	backups, err := s.backupFleet(ctx, tenants)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenants":                len(tenants),
		"by_version":             byVersion,
		"versions":               upgrades["versions"],
		"eol_exposure":           upgrades["eol_exposure"],
		"upgrades_active":        upgrades["active"],
		"upgrades_failed":        upgrades["failed_rehearsal"],
		"backups":                backups,
		"failed":                 failed,
		"unhealthy":              unhealthy,
		"owner_orphaned":         orphaned,
		"quarantined":            quarantined,
		"egress_enabled":         withEgress,
		"top_denials":            denials,
		"drift":                  s.rec.Drift().List(),
		"audit_chain_head":       chain,
		"anchor_age":             anchorAge,
		"pending_grants":         pending,
		"grants_expiring_30d":    expiring,
		"breakglass_open":        openBG,
		"breakglass_unreviewed":  unreviewedBG,
		"breakglass_overdue":     overdueBG,
		"attestation_mismatches": mismatches,
	})
}

// AddRuntimeVersionRequest is POST /admin/runtime-versions.
type AddRuntimeVersionRequest struct {
	Version      string `json:"version"`
	HardeningRev int    `json:"hardening_rev,omitempty"`
	Arch         string `json:"arch,omitempty"`
	// ImageDigest is optional. It is always resolved from
	// images/pb-hardened/digests.txt, which is the hand-off from the image
	// build (§5) and the only place a version becomes a digest; when given, it
	// must equal that entry.
	ImageDigest string `json:"image_digest,omitempty"`
	State       string `json:"state,omitempty"`
}

func (s *Server) addRuntimeVersion(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body AddRuntimeVersionRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rev := body.HardeningRev
	if rev == 0 {

		rev = s.cfg.HardeningRev
	}
	arch := body.Arch
	if arch == "" {

		arch = s.cfg.Arch
	}
	// Every runtime digest comes from digests.txt, the hand-off from the
	// platform's own image build (§5). An explicit image_digest is accepted
	// only when it IS that entry: the binary is platform-owned (INV-2), and a
	// digest typed into a request is whatever image somebody pointed at.
	entries, err := store.ParseDigestsFile(s.cfg.DigestsFile)
	if err != nil {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("%s is unreadable: %w", s.cfg.DigestsFile, err))
		return
	}
	digest, err := store.SelectDigest(entries, body.Version, rev, arch)
	if err != nil {

		writeErr(w, http.StatusNotFound, err)
		return
	}
	if body.ImageDigest != "" && body.ImageDigest != digest {

		writeErr(w, http.StatusUnprocessableEntity, fmt.Errorf(
			"image_digest %s is not the %s h%d %s entry in %s (%s); runtime images are the platform's own build (INV-2)",
			body.ImageDigest, body.Version, rev, arch, s.cfg.DigestsFile, digest))
		return
	}
	rv := store.RuntimeVersion{
		Version: body.Version, HardeningRev: rev, ImageDigest: digest, State: body.State,
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.UpsertRuntimeVersion(ctx, tx, rv); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action:     auditlog.ActionRuntimeVersionAdded,
			SubjectRef: "runtime_version/" + rv.Version,
			Detail:     map[string]any{"digest": digest, "hardening_rev": rev, "arch": arch},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, rv)
}

func (s *Server) listRuntimeVersions(w http.ResponseWriter, req *http.Request) {

	out, err := store.ListRuntimeVersions(req.Context(), s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// CreatePrincipalRequest is POST /admin/principals.
type CreatePrincipalRequest struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

func (s *Server) createPrincipal(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	var body CreatePrincipalRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Bootstrap: the very first principal cannot be created by an existing one,
	// so an unresolvable actor here falls back to the platform principal. The
	// audit row then honestly says the platform created it, and every later
	// mutation still demands a real named actor.
	actor, err := s.actor(ctx, req)
	if err != nil {

		if !errors.Is(err, identity.ErrNoActor) && !errors.Is(err, identity.ErrNotFound) {

			writeErr(w, statusFor(err), err)
			return
		}
		actor = identity.Platform()
	}
	var p identity.Principal
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		var err error
		p, err = s.ident.Create(ctx, tx, actor, identity.CreateOptions{
			ID: body.ID, DisplayName: body.DisplayName, Email: body.Email,
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) listPrincipals(w http.ResponseWriter, req *http.Request) {

	out, err := s.ident.List(req.Context())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) queryAudit(w http.ResponseWriter, req *http.Request) {

	q := auditlog.Query{
		TenantID: req.URL.Query().Get("tenant"),
		ActorID:  req.URL.Query().Get("actor"),
		Action:   req.URL.Query().Get("action"),
	}
	if v := req.URL.Query().Get("limit"); v != "" {

		q.Limit, _ = strconv.Atoi(v)
	}
	if v := req.URL.Query().Get("since"); v != "" {

		q.Since, _ = time.Parse(time.RFC3339, v)
	}
	out, err := auditlog.Select(req.Context(), s.db.Reader(), q)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) verifyAudit(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	anchors, err := store.ListAnchors(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	pub := ""
	if s.signer != nil {

		pub = s.signer.PublicKey()
	}
	// Both checks, always. Recomputing catches a row edited in place; only the
	// anchors catch a table rewritten wholesale with every hash recomputed,
	// because that chain verifies clean against itself.
	res, err := s.verifyChain(ctx, anchors, pub)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	status := http.StatusOK
	if !res.OK {

		// A broken chain is a security alert, not an operational one (§15): it
		// pages, and it is never auto-remediated.
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

// verifyChain recomputes the chain against the anchors in the database AND the
// anchor files on disk. The rows alone live in the database being checked; a
// rewrite that also deleted them would otherwise verify clean.
func (s *Server) verifyChain(ctx context.Context, rows []store.Anchor, pub string) (auditlog.VerifyResult, error) {

	files, err := auditlog.LoadAnchorFiles(s.cfg.AnchorsDir())
	if err != nil {

		return auditlog.VerifyResult{}, err
	}
	return auditlog.VerifyAll(ctx, s.db.Reader(), rows, files, pub)
}

// tenantFrom resolves the {id} path segment, accepting either a tenant id or a
// slug so citadel can take whichever the operator has in hand.
func (s *Server) tenantFrom(ctx context.Context, req *http.Request) (store.Tenant, error) {

	id := pathID(req)
	t, err := store.GetTenant(ctx, s.db.Reader(), id)
	if err == nil {

		return t, nil
	}
	if !errors.Is(err, store.ErrTenantNotFound) {

		return store.Tenant{}, err
	}
	return store.GetTenantBySlug(ctx, s.db.Reader(), id)
}

func containerName(t store.Tenant) string { return "pb-" + t.Slug }
