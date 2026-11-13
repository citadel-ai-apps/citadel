package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// decodeInto is the shared "read the response or fall back to raw JSON" step.
func decodeInto(b []byte, v any) error {

	if err := json.Unmarshal(b, v); err != nil {

		return printJSON(b)
	}
	return nil
}

func renderRelease(b []byte, out *struct {
	ID     string `json:"id"`
	Sha256 string `json:"sha256"`
}) error {

	var rel store.Release
	if err := json.Unmarshal(b, &rel); err != nil {

		return printJSON(b)
	}
	out.ID, out.Sha256 = rel.ID, rel.Sha256
	fmt.Printf("uploaded %s\n", rel.ID)
	fmt.Printf("  artifact   %s\n", short(rel.Sha256))
	fmt.Printf("  pocketbase %s–%s\n", dash(rel.PBMin), dash(rel.PBMax))
	fmt.Printf("  status     %s (validated, not deployed)\n", rel.Status)
	return nil
}

func renderReleases(b []byte) error {

	var payload struct {
		Tenant   string          `json:"tenant"`
		Current  string          `json:"current"`
		Releases []store.Release `json:"releases"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Releases) == 0 {

		fmt.Println("no releases yet (citadel release upload <slug> --app-dir ./app)")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "RELEASE\tARTIFACT\tPOCKETBASE\tSTATUS\tDEPLOYED\tLIVE")
	for _, r := range payload.Releases {

		live := ""
		if r.ID == payload.Current {

			live = "*"
		}
		deployed := "—"
		if r.DeployedAt != nil {

			deployed = r.DeployedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s–%s\t%s\t%s\t%s\n",
			r.ID, short(r.Sha256), dash(r.PBMin), dash(r.PBMax), r.Status, deployed, live)
	}
	return w.Flush()
}

// renderDeploy prints the §8.5 report. A failed deploy is reported with the
// step that broke, the snapshot the data came back from, and the tail of the
// container's own output — that report is the product, not an error string.
func renderDeploy(b []byte) error {

	var res reconcile.DeployResult
	if err := json.Unmarshal(b, &res); err != nil {

		return printJSON(b)
	}
	if res.Deployed {

		fmt.Printf("deployed %s (artifact %s)\n", res.ReleaseID, short(res.Artifact))

	} else if res.RolledBack {

		fmt.Printf("DEPLOY FAILED at %s — rolled back, data restored from snapshot %s\n",
			dash(res.FailedStep), dash(res.Snapshot))

	} else {

		fmt.Printf("DEPLOY FAILED at %s\n", dash(res.FailedStep))
	}
	if res.Error != "" {

		fmt.Printf("  %s\n", res.Error)
	}
	for _, g := range res.Grants {

		switch g.Decision {

		case store.DecisionAutoApproved:
			fmt.Printf("  egress %s: granted\n", g.Subject)
		default:
			fmt.Printf("  egress %s: %s — unreachable until then\n", g.Subject, g.Decision)
			fmt.Printf("    %s\n", g.Reason)
		}
	}
	if res.Logs != "" {

		fmt.Println("  --- container output ---")
		for _, line := range lastLines(res.Logs, 20) {

			fmt.Printf("    %s\n", line)
		}
	}
	return nil
}

func lastLines(s string, n int) []string {

	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {

		lines = lines[len(lines)-n:]
	}
	return lines
}

func renderBackups(b []byte) error {

	var payload struct {
		Backups []store.Backup `json:"backups"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Backups) == 0 {

		fmt.Println("no snapshots yet")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "BACKUP\tKIND\tPOCKETBASE\tSIZE\tTAKEN\tRETAIN UNTIL")
	for _, bk := range payload.Backups {

		retain := "—"
		if bk.RetainUntil != nil {

			retain = bk.RetainUntil.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", bk.ID, bk.Kind, bk.PBVersion,
			humanBytes(uint64(bk.SizeBytes)), bk.CreatedAt.UTC().Format(time.RFC3339), retain)
	}
	return w.Flush()
}

func renderEgress(b []byte) error {

	var payload struct {
		Tenant   string `json:"tenant"`
		Enforced bool   `json:"enforced"`
		Hosts    []struct {
			Host       string `json:"host"`
			State      string `json:"state"`
			Reason     string `json:"reason"`
			GrantID    string `json:"grant_id"`
			ExpiresAt  string `json:"expires_at"`
			Denials    int    `json:"denials"`
			LastDenied string `json:"last_denied"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Hosts) == 0 {

		fmt.Println("no outbound path at all, which is the default")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "HOST\tSTATE\tGRANT\tEXPIRES\tREFUSED\tREASON")
	for _, h := range payload.Hosts {

		refused := "-"
		if h.Denials > 0 {

			refused = fmt.Sprintf("%d (last %s)", h.Denials, dash(h.LastDenied))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			h.Host, h.State, dash(h.GrantID), dash(h.ExpiresAt), refused, h.Reason)
	}
	if err := w.Flush(); err != nil {

		return err
	}
	if !payload.Enforced {

		// Distinct from "denied": there is no egress network attachment and no
		// accept rule for this tenant at all, so nothing here is a route.
		fmt.Println("\nthis instance has no enforced outbound path: no approved grant is active,")
		fmt.Println("so it is not attached to the egress network and has no accept rule.")
	}
	return nil
}

func renderGrants(b []byte) error {

	var payload struct {
		Grants []struct {
			Grant  store.Grant `json:"grant"`
			State  string      `json:"state"`
			Active bool        `json:"active"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Grants) == 0 {

		fmt.Println("no grants")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "GRANT\tKIND\tSUBJECT\tTIER\tSTATE\tDECIDED BY\tEXPIRES")
	for _, row := range payload.Grants {

		g := row.Grant
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", g.ID, g.Kind, g.Subject, g.Tier,
			row.State, dash(g.DecidedBy), g.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func renderGrantQueue(b []byte) error {

	var payload struct {
		Decision string        `json:"decision"`
		Grants   []store.Grant `json:"grants"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Grants) == 0 {

		fmt.Printf("no %s grants\n", payload.Decision)
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "GRANT\tTENANT\tKIND\tSUBJECT\tTIER\tREQUESTED BY\tREQUESTED")
	for _, g := range payload.Grants {

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", g.ID, g.TenantID, g.Kind, g.Subject,
			g.Tier, g.RequestedBy, g.RequestedAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func renderToken(b []byte) error {

	var payload struct {
		Token  store.APIToken `json:"token"`
		Secret string         `json:"secret"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	fmt.Printf("token %s for %s\n", payload.Token.ID, payload.Token.PrincipalID)
	fmt.Printf("  expires %s\n\n", payload.Token.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Printf("  %s\n\n", payload.Secret)
	// Only place the secret ever exists outside the caller's memory: the
	// database holds a sha256 of it and nothing else.
	fmt.Println("  This is the only time the secret is shown. Store it now.")
	return nil
}

func renderTokens(b []byte) error {

	var payload struct {
		Tokens []store.APIToken `json:"tokens"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Tokens) == 0 {

		fmt.Println("no tokens")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "TOKEN\tPRINCIPAL\tNAME\tEXPIRES\tLAST USED\tREVOKED")
	for _, t := range payload.Tokens {

		last, revoked := "never", "—"
		if t.LastUsedAt != nil {

			last = t.LastUsedAt.UTC().Format(time.RFC3339)
		}
		if t.RevokedAt != nil {

			revoked = t.RevokedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.PrincipalID, t.Name,
			t.ExpiresAt.UTC().Format(time.RFC3339), last, revoked)
	}
	return w.Flush()
}

func short(s string) string {

	if len(s) > 12 {

		return s[:12]
	}
	return dash(s)
}
