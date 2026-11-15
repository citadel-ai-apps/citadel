package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func tw() *tabwriter.Writer {

	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}

type tenantRow struct {
	Tenant   store.Tenant   `json:"tenant"`
	Instance store.Instance `json:"instance"`
	Owner    string         `json:"owner"`
}

func decodeTenant(b []byte) (store.Tenant, error) {

	var t store.Tenant
	err := json.Unmarshal(b, &t)
	return t, err
}

func decodeRuntimeVersion(b []byte) (store.RuntimeVersion, error) {

	var rv store.RuntimeVersion
	err := json.Unmarshal(b, &rv)
	return rv, err
}

func renderTenantList(b []byte) error {

	var rows []tenantRow
	if err := json.Unmarshal(b, &rows); err != nil {

		return printJSON(b)
	}
	if len(rows) == 0 {

		fmt.Println("no tenants")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "SLUG\tPB\tDESIRED\tOBSERVED\tOWNER\tSUBNET\tHOSTNAME")
	for _, r := range rows {

		owner := r.Owner
		if r.Tenant.OwnerOrphaned {

			owner += " (orphaned)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Tenant.Slug, r.Tenant.RuntimeVersion, r.Tenant.DesiredState,
			r.Instance.ObservedState, owner, r.Tenant.Subnet, r.Tenant.Hostname)
	}
	return w.Flush()
}

type statusPayload struct {
	Tenant   store.Tenant      `json:"tenant"`
	Instance store.Instance    `json:"instance"`
	Owner    string            `json:"owner"`
	Drift    []reconcile.Drift `json:"drift"`
	Disk     *struct {
		UsedBytes      uint64 `json:"used_bytes"`
		AvailableBytes uint64 `json:"available_bytes"`
	} `json:"disk"`
}

func renderTenantStatus(b []byte) error {

	var p statusPayload
	if err := json.Unmarshal(b, &p); err != nil {

		return printJSON(b)
	}
	t, in := p.Tenant, p.Instance
	fmt.Printf("%s\n", t.Slug)
	fmt.Printf("  hostname     %s\n", t.Hostname)
	fmt.Printf("  owner        %s%s\n", p.Owner, orphanNote(t.OwnerOrphaned))
	fmt.Printf("  pb version   %s\n", t.RuntimeVersion)
	fmt.Printf("  digest       %s\n", t.ImageDigest)
	fmt.Printf("  desired      %s\n", t.DesiredState)
	fmt.Printf("  observed     %s\n", in.ObservedState)
	if in.LastHealthAt != nil {

		fmt.Printf("  last healthy %s\n", in.LastHealthAt.Format(time.RFC3339))
	}
	if in.RestartCount > 0 {

		fmt.Printf("  restarts     %d of %d before failed\n", in.RestartCount, reconcile.MaxRestarts)
	}
	if in.LastError != "" {

		fmt.Printf("  last error   %s\n", in.LastError)
	}
	fmt.Printf("  network      %s  subnet %s  tenant %s  edge %s\n",
		t.NetworkName, t.Subnet, t.ContainerIP, t.EdgeIP)
	fmt.Printf("  resources    %.1f cpu, %d MiB, %d MiB disk, body cap %s\n",
		t.CPUs, t.MemMiB, t.DiskMiB, t.BodyCap)
	if p.Disk != nil {

		// Usable bytes, not the image size: data.img is sized above the nominal
		// quota to absorb filesystem overhead.
		fmt.Printf("  disk usage   %s used, %s available\n",
			humanBytes(p.Disk.UsedBytes), humanBytes(p.Disk.AvailableBytes))
	}
	if t.CurrentArtifact != "" {

		fmt.Printf("  artifact     %s\n", t.CurrentArtifact)
	}
	if len(p.Drift) > 0 {

		fmt.Println("\n  DRIFT:")
		for _, d := range p.Drift {

			fmt.Printf("    %s\n", formatDrift(d))
		}
	}
	return nil
}

func orphanNote(orphaned bool) string {

	if orphaned {

		return "  (ORPHANED — custody is with the platform principal)"
	}
	return ""
}

type fleetPayload struct {
	Tenants        int                   `json:"tenants"`
	ByVersion      map[string]int        `json:"by_version"`
	Failed         []string              `json:"failed"`
	Unhealthy      []string              `json:"unhealthy"`
	OwnerOrphaned  []string              `json:"owner_orphaned"`
	Quarantined    []string              `json:"quarantined"`
	EgressEnabled  []string              `json:"egress_enabled"`
	TopDenials     []store.Denial        `json:"top_denials"`
	Drift          []reconcile.Drift     `json:"drift"`
	AuditChainHead auditlog.VerifyResult `json:"audit_chain_head"`
}

func renderFleet(b []byte) error {

	var f fleetPayload
	if err := json.Unmarshal(b, &f); err != nil {

		return printJSON(b)
	}
	fmt.Printf("tenants: %d\n", f.Tenants)
	if len(f.ByVersion) > 0 {

		fmt.Println("\nby runtime version:")
		w := tw()
		for v, n := range f.ByVersion {

			fmt.Fprintf(w, "  %s\t%d\n", v, n)
		}
		_ = w.Flush()
	}
	printList("failed", f.Failed)
	printList("unhealthy", f.Unhealthy)
	printList("owner orphaned", f.OwnerOrphaned)
	printList("quarantined", f.Quarantined)
	// The full set of tenants that can reach anything outside the sandbox is
	// the platform's real outbound blast radius (§14.5), so it gets a line of
	// its own rather than being buried per tenant.
	printList("outbound access enforced", f.EgressEnabled)

	if len(f.TopDenials) > 0 {

		fmt.Println("\ntop egress denials:")
		w := tw()
		fmt.Fprintln(w, "  TENANT\tHOST\tPORT\tHITS\tLAST")
		for _, d := range f.TopDenials {

			fmt.Fprintf(w, "  %s\t%s\t%d\t%d\t%s\n",
				d.TenantID, d.Host, d.Port, d.Hits, d.LastSeenAt.UTC().Format(time.RFC3339))
		}
		_ = w.Flush()
	}

	fmt.Printf("\naudit chain: %d rows, head seq %d", f.AuditChainHead.Rows, f.AuditChainHead.HeadSeq)
	if f.AuditChainHead.OK {

		fmt.Printf(" — verified\n")

	} else {

		fmt.Printf(" — FAILED at seq %d: %s\n", f.AuditChainHead.FailedSeq, f.AuditChainHead.Reason)
	}

	if len(f.Drift) == 0 {

		fmt.Println("\ndrift: none")
		return nil
	}
	fmt.Println("\ndrift:")
	for _, d := range f.Drift {

		fmt.Printf("  %s\n", formatDrift(d))
	}
	return nil
}

// formatDrift makes the security/operational split visible at a glance: an
// extra rule or a digest mismatch is a different class of problem from a route
// that needed re-publishing (§14.5).
func formatDrift(d reconcile.Drift) string {

	tag := "DRIFT"
	if d.Security {

		tag = "SECURITY"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", tag, d.Kind)
	if d.TenantID != "" {

		fmt.Fprintf(&b, " tenant=%s", d.TenantID)
	}
	fmt.Fprintf(&b, ": %s", d.Detail)
	if d.Repaired {

		b.WriteString(" (repaired)")

	} else {

		b.WriteString(" (NOT auto-repaired)")
	}
	fmt.Fprintf(&b, " since %s", d.DetectedAt.Format(time.RFC3339))
	return b.String()
}

func printList(label string, items []string) {

	if len(items) == 0 {

		return
	}
	fmt.Printf("\n%s: %s\n", label, strings.Join(items, ", "))
}

func renderPrincipals(b []byte) error {

	var ps []struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
		Email       string `json:"email"`
		Operator    bool   `json:"operator"`
	}
	if err := json.Unmarshal(b, &ps); err != nil {

		return printJSON(b)
	}
	w := tw()
	fmt.Fprintln(w, "ID\tKIND\tSTATUS\tOPERATOR\tNAME\tEMAIL")
	for _, p := range ps {

		op := "-"
		if p.Operator {

			op = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.Kind, p.Status, op, p.DisplayName, p.Email)
	}
	return w.Flush()
}

func renderRuntimeVersions(b []byte) error {

	var vs []store.RuntimeVersion
	if err := json.Unmarshal(b, &vs); err != nil {

		return printJSON(b)
	}
	if len(vs) == 0 {

		fmt.Println("no runtime versions registered (citadel runtime-version add <ver>)")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "VERSION\tREV\tSTATE\tDIGEST")
	for _, v := range vs {

		fmt.Fprintf(w, "%s\th%d\t%s\t%s\n", v.Version, v.HardeningRev, v.State, v.ImageDigest)
	}
	return w.Flush()
}

func renderOwner(b []byte) error {

	var p struct {
		Tenant       string `json:"tenant"`
		CurrentOwner string `json:"current_owner"`
		Orphaned     bool   `json:"orphaned"`
		History      []struct {
			PrincipalID string     `json:"principal_id"`
			Role        string     `json:"role"`
			GrantedBy   string     `json:"granted_by"`
			GrantedAt   time.Time  `json:"granted_at"`
			RevokedBy   string     `json:"revoked_by"`
			RevokedAt   *time.Time `json:"revoked_at"`
		} `json:"history"`
	}
	if err := json.Unmarshal(b, &p); err != nil {

		return printJSON(b)
	}
	fmt.Printf("%s current owner: %s%s\n\n", p.Tenant, p.CurrentOwner, orphanNote(p.Orphaned))
	w := tw()
	fmt.Fprintln(w, "PRINCIPAL\tROLE\tGRANTED BY\tGRANTED AT\tREVOKED")
	for _, h := range p.History {

		revoked := "—"
		if h.RevokedAt != nil {

			revoked = h.RevokedAt.Format(time.RFC3339) + " by " + h.RevokedBy
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			h.PrincipalID, h.Role, h.GrantedBy, h.GrantedAt.Format(time.RFC3339), revoked)
	}
	return w.Flush()
}

func renderAudit(b []byte) error {

	var recs []auditlog.Record
	if err := json.Unmarshal(b, &recs); err != nil {

		return printJSON(b)
	}
	if len(recs) == 0 {

		fmt.Println("no matching audit events")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "SEQ\tWHEN\tACTOR\tKIND\tACTION\tTENANT\tSUBJECT")
	for _, r := range recs {

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Seq, r.OccurredAt.Format(time.RFC3339), r.ActorID, r.ActorKind,
			r.Action, dash(r.TenantID), dash(r.SubjectRef))
	}
	return w.Flush()
}

func renderVerify(b []byte) error {

	var v auditlog.VerifyResult
	if err := json.Unmarshal(b, &v); err != nil {

		return printJSON(b)
	}
	if v.OK {

		fmt.Printf("audit chain OK: %d rows, head seq %d, head hash %s\n", v.Rows, v.HeadSeq, v.HeadHash)
		printAnchorNote(v)
		return nil
	}
	if v.Reason != "" {

		fmt.Printf("audit chain FAILED at seq %d: %s\n", v.FailedSeq, v.Reason)

	} else {

		// A clean recompute that contradicts an anchor IS the wholesale-rewrite
		// signature: the table agrees with itself, and disagrees with a head
		// that was signed before the rewrite and copied where it could not be
		// reached.
		fmt.Printf("audit chain CONTRADICTS the anchor at seq %d: %s\n", v.ContradictedSeq, v.AnchorReason)
		fmt.Println("  the chain recomputes cleanly, which is what a wholesale rewrite looks like")
	}
	fmt.Printf("  %d rows scanned, %d anchors checked\n", v.Rows, v.AnchorsChecked)
	return nil
}

// printAnchorNote says what the verification does and does not prove.
//
// Worth stating every time rather than in a doc nobody reads mid-incident: with
// no anchors, a pass means only that nobody edited a row in place. It says
// nothing about a table rewritten wholesale with every hash recomputed.
func printAnchorNote(v auditlog.VerifyResult) {

	if v.AnchorsChecked == 0 {

		fmt.Println("note: recomputed locally with NO anchors to compare against, so this detects")
		fmt.Println("      an edited row but not a wholesale rewrite.")
		return
	}
	fmt.Printf("  %d anchor(s) agree; last anchored %s\n",
		v.AnchorsChecked, v.LastAnchoredAt.UTC().Format(time.RFC3339))
	fmt.Println("note: the signing key lives on this host, so an operator with root can sign")
	fmt.Println("      whatever they like going forward. What bounds the tampering is an anchor")
	fmt.Println("      already replicated off the host — and that replication is not built yet.")
}

func dash(s string) string {

	if s == "" {

		return "—"
	}
	return s
}

func humanBytes(n uint64) string {

	const unit = 1024
	if n < unit {

		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {

		v /= unit
		if v < unit {

			return fmt.Sprintf("%.1f %s", v, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", v/unit)
}
