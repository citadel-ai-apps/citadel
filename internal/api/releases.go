package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// PackageField is the multipart field name carrying the zip.
const PackageField = "package"

// uploadRelease validates and stores a package. It does not deploy it: upload
// and deploy are separate so a tenant can see what passed validation before
// anything restarts (§8.5).
func (s *Server) uploadRelease(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}

	// Not decodeBody: that caps at 1 MiB and expects JSON. The cap here is the
	// §6 package cap, applied at the socket so a 5 GiB upload is refused while
	// it is still on the wire rather than after it has been spooled to disk.
	req.Body = http.MaxBytesReader(w, req.Body, s.cfg.MaxPackageBytes+(1<<20))
	if err := req.ParseMultipartForm(8 << 20); err != nil {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: %s must be a multipart upload with a %q field: %w",
			req.URL.Path, PackageField, err))
		return
	}
	defer func() { _ = req.MultipartForm.RemoveAll() }()

	file, header, err := req.FormFile(PackageField)
	if err != nil {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: no %q field in the upload: %w", PackageField, err))
		return
	}
	defer file.Close()

	rel, err := s.rel.Ingest(req.Context(), actor, t, file, header.Size)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, rel)
}

func (s *Server) listReleases(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rows, err := store.ListReleases(ctx, s.db.Reader(), t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.ID, "current": t.CurrentRelease, "releases": rows,
	})
}

func (s *Server) deployRelease(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	res, err := s.rec.Deploy(req.Context(), actor, t, mux.Vars(req)["rid"])
	writeDeploy(w, res, err)
}

// RollbackRequest is POST /tenants/{id}/rollback. An empty release_id means the
// release deployed before the current one.
type RollbackRequest struct {
	ReleaseID string `json:"release_id,omitempty"`
}

func (s *Server) rollbackTenant(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body RollbackRequest
	if req.ContentLength > 0 {

		if err := decodeBody(req, &body); err != nil {

			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	res, err := s.rec.Rollback(req.Context(), actor, t, body.ReleaseID)
	writeDeploy(w, res, err)
}

// writeDeploy renders a deploy outcome.
//
// A deploy that failed and rolled back is not a 500: the platform did exactly
// what it promised. It is a 422 carrying the whole report — which step failed,
// the container logs, and the snapshot the data came back from — because that
// report is the product (§8.5).
func writeDeploy(w http.ResponseWriter, res reconcile.DeployResult, err error) {

	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if !res.Deployed {

		writeJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listBackups(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rows, err := store.ListBackups(ctx, s.db.Reader(), t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t.ID, "backups": rows})
}

func (s *Server) createBackup(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	b, err := s.rec.Snapshot(req.Context(), actor, t, store.BackupManual)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

// EgressEntry is one host and why it is, or is not, reachable.
//
// The states are distinct on purpose (§9.4): a developer debugging a failing
// integration needs "awaiting approval" and "denied — <reason>" to look
// different, not an opaque timeout.
type EgressEntry struct {
	Host      string `json:"host"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	GrantID   string `json:"grant_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Requested bool   `json:"requested_by_release"`
	// Denials is how many times the proxy actually turned this host away, and
	// when it last did. A host the tenant believes is allowed but that shows
	// denials is the single most useful line on this page.
	Denials    int    `json:"denials,omitempty"`
	LastDenied string `json:"last_denied,omitempty"`
}

// StateNeverRequested is the state of a host the current release does not name
// and no grant exists for.
const StateNeverRequested = "never_requested"

func (s *Server) tenantEgress(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	grants, err := store.ListGrants(ctx, s.db.Reader(), store.GrantFilter{
		TenantID: t.ID, Kind: store.GrantEgressHost,
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}

	requested := map[string]bool{}
	if t.CurrentRelease != "" {

		if rel, err := store.GetRelease(ctx, s.db.Reader(), t.CurrentRelease); err == nil {

			var hosts []string
			if err := json.Unmarshal([]byte(orEmptyArray(rel.EgressHosts)), &hosts); err == nil {

				for _, h := range hosts {

					requested[h] = true
				}
			}
		}
	}

	// Denials come from the host — the proxy's own access log — not from the
	// decision table. That is what makes them evidence: a host that appears
	// approved and still shows denials means the enforcement and the record
	// disagree, which is exactly the divergence §14.5 exists to surface.
	denials, err := store.ListDenials(ctx, s.db.Reader(), t.ID, time.Time{})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	hits := map[string]int{}
	last := map[string]time.Time{}
	for _, d := range denials {

		hits[d.Host] += d.Hits
		if d.LastSeenAt.After(last[d.Host]) {

			last[d.Host] = d.LastSeenAt
		}
	}

	now := time.Now().UTC()
	out := make([]EgressEntry, 0, len(grants))
	seen := map[string]bool{}
	entry := func(host, state, reason, grantID, expires string) EgressEntry {

		e := EgressEntry{
			Host: host, State: state, Reason: reason, GrantID: grantID,
			ExpiresAt: expires, Requested: requested[host], Denials: hits[host],
		}
		if t, ok := last[host]; ok {

			e.LastDenied = t.Format(time.RFC3339)
		}
		return e
	}
	for _, g := range grants {

		if seen[g.Subject] {

			continue // the newest row for a subject wins; ListGrants is newest first
		}
		seen[g.Subject] = true
		out = append(out, entry(g.Subject, g.State(now), g.Justification, g.ID,
			g.ExpiresAt.Format(time.RFC3339)))
	}
	// A host the release asks for with no grant row at all: the release was
	// never deployed, or the request predates the grant pipeline.
	for host := range requested {

		if !seen[host] {

			seen[host] = true
			out = append(out, entry(host, StateNeverRequested, "", "", ""))
		}
	}
	// A host nothing ever asked for, that the app called anyway. Usually a
	// dependency reaching somewhere its caller did not know about, which is
	// precisely the thing a default-deny posture is for.
	for host := range hits {

		if !seen[host] {

			out = append(out, entry(host, StateNeverRequested, "", "", ""))
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.ID,
		"hosts":  out,
		// Whether a DOCKER-USER accept and a proxy ACL exist for this tenant
		// right now, derived from its active grants on the last reconcile tick.
		"enforced": t.EgressEnabled,
		"denials":  denials,
	})
}

func (s *Server) tenantReleaseManifest(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rel, err := store.GetRelease(ctx, s.db.Reader(), mux.Vars(req)["rid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if rel.TenantID != t.ID {

		// The role check above was on {id}; the release must belong to it, or
		// any member of one tenant reads any other tenant's manifest. Answered
		// as not-found, like the job, backup and grant handlers.
		writeErr(w, http.StatusNotFound, fmt.Errorf("%w: %s", store.ErrReleaseNotFound, rel.ID))
		return
	}
	man, err := release.Manifest(rel)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"release": rel, "manifest": man})
}

// downloadRelease streams the zip a release was ingested from. Gated on deploy:
// the package is the tenant's code, and whoever may ship code may read it back.
func (s *Server) downloadRelease(w http.ResponseWriter, req *http.Request) {

	actor, t, err := s.authedTenant(req, identity.CapDeploy)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	d, err := s.rel.OpenDownload(req.Context(), actor, t, mux.Vars(req)["rid"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	d.Serve(w, req)
}

func orEmptyArray(s string) string {

	if s == "" {

		return "[]"
	}
	return s
}
