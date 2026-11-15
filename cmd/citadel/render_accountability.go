package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

func renderAttestation(b []byte) error {

	var rep attest.Report
	if err := json.Unmarshal(b, &rep); err != nil {

		return printJSON(b)
	}
	name := rep.Slug
	if name == "" {

		name = rep.TenantID
	}
	fmt.Printf("Tenant %s · attested %s · outcome: %s\n\n",
		name, rep.GeneratedAt.UTC().Format(time.RFC3339), rep.Outcome)

	fmt.Println("Can reach outside its sandbox:")
	shown := 0
	for _, g := range rep.Grants {

		if g.State != store.DecisionApproved && g.State != store.DecisionAutoApproved {

			continue
		}
		by := g.DecidedBy
		if by == "" {

			by = "—"
		}
		mark := " "
		switch {

		case !g.Enforcible:
			mark = "?" // recorded, but nothing here can put it into effect
		case !g.Enforced:
			mark = "!" // approved and NOT in effect
		}
		fmt.Printf("  %s %-24s grant %-12s approved by %-16s expires %s\n",
			mark, g.Subject, g.ID, by, g.ExpiresAt.UTC().Format("2006-01-02"))
		shown++
	}
	if shown == 0 {

		fmt.Println("  nothing")
	}

	if rep.Observed.ProxyReadable {

		fmt.Printf("\nThe running proxy is enforcing: %v\n", rep.Observed.Reachable)

	} else if len(rep.Observed.ObserveErrors) > 0 {

		// A partial observation must never read as an empty one.
		fmt.Println("\nNot everything could be observed:")
		for _, e := range rep.Observed.ObserveErrors {

			fmt.Println("  " + e)
		}
	}

	if len(rep.Findings) == 0 {

		fmt.Println("\nHost and grants agree.")
		return nil
	}
	fmt.Println("\nFindings:")
	for _, f := range rep.Findings {

		tag := "  "
		if f.Security {

			tag = "!!"
		}
		fmt.Printf("%s %s: %s\n", tag, f.Subject, f.Detail)
		if f.Where != "" && f.Where != "none" {

			fmt.Printf("     seen in %s\n", f.Where)
		}
	}
	if rep.Outcome == store.OutcomeEnforcementWithoutGrant {

		fmt.Println("\nDo NOT remove these by hand. The rule is the evidence; removing it hides a")
		fmt.Println("recurring intrusion behind a self-healing loop. Record it first; remove it only once its origin is understood.")
	}
	return nil
}

func renderMismatches(b []byte) error {

	var payload struct {
		Mismatches   []store.Attestation `json:"mismatches"`
		Attestations []store.Attestation `json:"attestations"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	rows := payload.Mismatches
	if rows == nil {

		rows = payload.Attestations
	}
	if len(rows) == 0 {

		fmt.Println("every tenant's host matches its grants")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "TENANT\tOUTCOME\tGENERATED\tFINDINGS")
	for _, a := range rows {

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.TenantID, a.Outcome,
			a.GeneratedAt.UTC().Format(time.RFC3339), a.MismatchJSON)
	}
	return w.Flush()
}

func renderBreakglass(b []byte) error {

	var payload struct {
		Open       []store.Grant `json:"open"`
		Unreviewed []store.Grant `json:"unreviewed"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Open) == 0 && len(payload.Unreviewed) == 0 {

		fmt.Println("no open or unreviewed break-glass sessions")
		return nil
	}
	if len(payload.Open) > 0 {

		fmt.Println("OPEN RIGHT NOW")
		w := tw()
		fmt.Fprintln(w, "GRANT\tTENANT\tSCOPE\tOPENED BY\tEXPIRES\tREASON")
		for _, g := range payload.Open {

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.TenantID, g.Subject,
				g.RequestedBy, g.ExpiresAt.UTC().Format(time.RFC3339), g.Justification)
		}
		if err := w.Flush(); err != nil {

			return err
		}
	}
	if len(payload.Unreviewed) > 0 {

		fmt.Println("\nNOT YET REVIEWED — OVERDUE ones (past 24h) block their opener from opening another")
		now := time.Now()
		w := tw()
		fmt.Fprintln(w, "GRANT\tTENANT\tOPENED BY\tOPENED\tREVIEW\tREASON")
		for _, g := range payload.Unreviewed {

			due := "due " + g.RequestedAt.Add(store.ReviewWindow).UTC().Format(time.RFC3339)
			if store.ReviewOverdue(g, now) {

				due = "OVERDUE"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.TenantID, g.RequestedBy,
				g.RequestedAt.UTC().Format(time.RFC3339), due, g.Justification)
		}
		if err := w.Flush(); err != nil {

			return err
		}
		fmt.Println("review with: citadel breakglass review <grant-id> --outcome justified --notes <text>")
	}
	return nil
}

func renderBreakglassOpen(b []byte) error {

	var payload struct {
		Grant     store.Grant `json:"grant"`
		ExpiresAt time.Time   `json:"expires_at"`
		ReviewDue time.Time   `json:"review_due"`
		Portal    string      `json:"portal_path"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	fmt.Printf("break-glass %s open on %s until %s\n",
		payload.Grant.ID, payload.Grant.TenantID, payload.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Println("  the tenant has already been told, with your reason verbatim")
	fmt.Println("  not extendable: request again if 60 minutes is not enough")
	if payload.Portal != "" {

		fmt.Printf("  sign in to the portal as %s and open %s; end it early with `citadel breakglass close %s`\n",
			payload.Grant.RequestedBy, payload.Portal, payload.Grant.ID)
	}
	fmt.Printf("  self-approved: access is open now; somebody other than you reviews it afterwards, by %s\n",
		payload.ReviewDue.UTC().Format(time.RFC3339))
	return nil
}
