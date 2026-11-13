package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// tenantAttestation serves the tenant's own view of what it can reach.
//
// Summarised rather than the full report (D17). The full version names bridge
// interfaces, chain positions, subnets and the proxy's address — platform
// topology handed to a party the model treats as fully compromised. What the
// tenant is owed is the accountability content, and that survives the trim.
func (s *Server) tenantAttestation(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	row, err := store.LatestAttestation(ctx, s.db.Reader(), t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	rep, err := reportFrom(row, t.Slug)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, attest.Summarise(rep))
}

// adminAttestation generates a report on demand and returns it in full.
func (s *Server) adminAttestation(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.tenantFrom(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	if s.attest == nil {

		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf(
			"api: attestation is not configured on this control plane"))
		return
	}
	rep, err := s.attest.Generate(ctx, t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	status := http.StatusOK
	if rep.Outcome == store.OutcomeEnforcementWithoutGrant {

		// Not a 200 with a field set. This is the outcome that pages, and a
		// caller that only checks the status code must not read it as fine.
		status = http.StatusConflict
	}
	writeJSON(w, status, rep)
}

// adminAttestations is the fleet's mismatch list, security outcome first (§15).
func (s *Server) adminAttestations(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	if tenant := req.URL.Query().Get("tenant"); tenant != "" {

		rows, err := store.ListAttestations(ctx, s.db.Reader(), tenant, 25)
		if err != nil {

			writeErr(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"attestations": rows})
		return
	}
	rows, err := store.Mismatches(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mismatches": rows})
}

// reportFrom rebuilds a Report from a stored row.
//
// The signature covers the report as it was generated, so a row re-rendered
// here is NOT re-signed: the stored signature is carried through and a consumer
// checks it against the file under audit/attestations, which holds the exact
// signed bytes.
func reportFrom(row store.Attestation, slug string) (attest.Report, error) {

	rep := attest.Report{
		TenantID: row.TenantID, Slug: slug, GeneratedAt: row.GeneratedAt,
		Outcome: row.Outcome, Signature: row.Signature,
	}
	if err := json.Unmarshal([]byte(row.ObservedJSON), &rep.Observed); err != nil {

		return attest.Report{}, fmt.Errorf("api: stored attestation %s is unreadable: %w", row.ID, err)
	}
	if row.MismatchJSON != "" {

		if err := json.Unmarshal([]byte(row.MismatchJSON), &rep.Findings); err != nil {

			return attest.Report{}, fmt.Errorf("api: stored attestation %s is unreadable: %w", row.ID, err)
		}
	}
	// Rows written before grants were stored carry none; the signed file under
	// audit/attestations still has them.
	if row.GrantsJSON != "" {

		if err := json.Unmarshal([]byte(row.GrantsJSON), &rep.Grants); err != nil {

			return attest.Report{}, fmt.Errorf("api: stored attestation %s is unreadable: %w", row.ID, err)
		}
	}
	return rep, nil
}

// tenantAccessLog is every platform access to THIS tenant's data (§14.6).
//
// Visible to the tenant by default, not on request. An operator opening a
// customer's database learns that the customer is being told as it happens,
// which is the property that makes break-glass honest rather than merely
// logged.
func (s *Server) tenantAccessLog(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	t, err := s.readTenant(req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var out []auditlog.Record
	for _, action := range auditlog.DataAccessActions {

		rows, err := auditlog.Select(ctx, s.db.Reader(), auditlog.Query{
			TenantID: t.ID, Action: action, Limit: 200,
		})
		if err != nil {

			writeErr(w, statusFor(err), err)
			return
		}
		out = append(out, rows...)
	}
	sortRecordsNewestFirst(out)

	sessions, err := store.BreakglassGrants(ctx, s.db.Reader(), t.ID)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	notices, err := store.ListNotifications(ctx, s.db.Reader(), store.NotificationFilter{
		TenantID: t.ID, Audience: store.AudienceTenant,
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":        t.ID,
		"accesses":      out,
		"break_glass":   sessions,
		"notifications": notices,
	})
}

func sortRecordsNewestFirst(rows []auditlog.Record) {

	for i := 1; i < len(rows); i++ {

		for j := i; j > 0 && rows[j].Seq > rows[j-1].Seq; j-- {

			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}

// exportAudit is a tenant-scoped export with the chain segment around it.
//
// One global chain means a tenant's own rows are not independently verifiable:
// their hashes commit to rows belonging to other tenants. So the export ships
// the SEGMENT — every row from the first to the last relevant seq — and the
// signed head, which together let a recipient recompute the chain across the
// range and check the tip. Whether that is good enough, or whether per-tenant
// chains or inclusion proofs are needed, is still open (D14a).
func (s *Server) exportAudit(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	tenant := req.URL.Query().Get("tenant")
	rows, err := auditlog.Select(ctx, s.db.Reader(), auditlog.Query{TenantID: tenant, Limit: 1000})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var segment []auditlog.Record
	if len(rows) > 0 {

		segment, err = auditlog.Segment(ctx, s.db.Reader(), rows[0].Seq, rows[len(rows)-1].Seq)
		if err != nil {

			writeErr(w, statusFor(err), err)
			return
		}
	}
	anchors, err := store.ListAnchors(ctx, s.db.Reader())
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	pub := ""
	if s.signer != nil {

		pub = s.signer.PublicKey()
	}
	if err := s.auditExported(ctx, actor, tenant, len(rows)); err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":      tenant,
		"exported_at": time.Now().UTC(),
		"events":      rows,
		"segment":     segment,
		"anchors":     anchors,
		"public_key":  pub,
		"note": "the segment is the surrounding chain range; a tenant's own rows commit to " +
			"rows belonging to other tenants, so verification needs both",
	})
}

func (s *Server) auditExported(ctx context.Context, actor identity.Actor, tenant string, n int) error {

	return s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenant,
			Action:     auditlog.ActionAuditExported,
			SubjectRef: "audit/export",
			Detail:     map[string]any{"events": n},
		})
		return err
	})
}
