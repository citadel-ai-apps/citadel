package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/api"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// tenantUpgrade drives `citadel tenant upgrade <slug> --to <ver>`.
//
// The API answers 202 with a job, because a rehearsal is minutes of work. This
// prints the job id and, with --watch, follows the ladder — which is the CLI's
// answer to an asynchronous operation: an operator who typed the command wants
// to see it finish, and polling a job id by hand is how people stop checking.
func (c *client) tenantUpgrade(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("tenant upgrade needs a slug")
	}
	slug, rest := args[0], args[1:]
	var req api.UpgradeRequest
	watch := false
	for i := 0; i < len(rest); i++ {

		var err error
		switch rest[i] {

		case "--to":
			req.To, err = next(rest, &i, "--to")
		case "--rehearse-only":
			req.RehearseOnly = true
		case "--no-rehearse":
			// Operator-only, and the API says so rather than this: a flag that
			// silently does nothing over the wire is worse than one refused.
			req.Rehearse = new(false)
		case "--force":
			req.Force = true
		case "--watch":
			watch = true
		default:
			err = fmt.Errorf("unknown flag %q", rest[i])
		}
		if err != nil {

			return err
		}
	}
	if req.To == "" {

		return errors.New("tenant upgrade needs --to <version>")
	}
	raw, err := c.call(ctx, http.MethodPost, "/api/v1/tenants/"+slug+"/upgrade", req)
	if err != nil {

		return err
	}
	var job store.UpgradeJob
	if err := decodeInto(raw, &job); err != nil {

		return printJSON(raw)
	}
	if c.json && !watch {

		return printJSON(raw)
	}
	fmt.Printf("%s: upgrade %s → %s started as %s\n", slug, job.FromVersion, job.ToVersion, job.ID)
	if !watch {

		fmt.Printf("  follow it with: citadel tenant upgrade-status %s %s\n", slug, job.ID)
		return nil
	}
	return c.watchUpgrade(ctx, slug, job.ID)
}

// watchUpgrade polls a job, printing each state as it is entered.
func (c *client) watchUpgrade(ctx context.Context, slug, jobID string) error {

	last := ""
	for {

		raw, err := c.call(ctx, http.MethodGet, "/api/v1/tenants/"+slug+"/upgrade/"+jobID, nil)
		if err != nil {

			return err
		}
		var job store.UpgradeJob
		if err := decodeInto(raw, &job); err != nil {

			return printJSON(raw)
		}
		if job.State != last {

			fmt.Printf("  %s\n", job.State)
			last = job.State
		}
		if job.Terminal() {

			return renderUpgradeJob(raw)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *client) upgradeStatus(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("tenant upgrade-status needs a slug")
	}
	slug := args[0]
	if len(args) == 1 {

		return c.printGet(ctx, "/api/v1/tenants/"+slug+"/upgrade", renderUpgradeList)
	}
	return c.printGet(ctx, "/api/v1/tenants/"+slug+"/upgrade/"+args[1], renderUpgradeJob)
}

// tenantPinRuntime is `citadel tenant pin-runtime <slug> --to <ver>
// --justification <text>`: the INV-4 rollback step that points a stopped tenant
// at the runtime a snapshot was taken on.
func (c *client) tenantPinRuntime(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("tenant pin-runtime needs a slug")
	}
	slug, rest := args[0], args[1:]
	var req api.PinRuntimeRequest
	for i := 0; i < len(rest); i++ {

		var err error
		switch rest[i] {

		case "--to":
			req.Version, err = next(rest, &i, "--to")
		case "--justification":
			req.Justification, err = next(rest, &i, "--justification")
		default:
			err = fmt.Errorf("unknown flag %q", rest[i])
		}
		if err != nil {

			return err
		}
	}
	if req.Version == "" || req.Justification == "" {

		return errors.New("tenant pin-runtime needs --to <version> and --justification <text>")
	}
	raw, err := c.call(ctx, http.MethodPost, "/api/v1/admin/tenants/"+slug+"/pin-runtime", req)
	if err != nil {

		return err
	}
	return c.emit(raw, func([]byte) error {

		fmt.Printf("%s: runtime pinned to %s; the tenant is still stopped\n", slug, req.Version)
		return nil
	})
}

// backupRestore is `citadel backup restore <slug> <bid> [--force]`.
func (c *client) backupRestore(ctx context.Context, args []string) error {

	if len(args) < 2 {

		return errors.New("backup restore needs a slug and a backup id")
	}
	slug, bid, rest := args[0], args[1], args[2:]
	var req api.RestoreRequest
	for _, a := range rest {

		if a != "--force" {

			return fmt.Errorf("unknown flag %q", a)
		}
		req.Force = true
	}
	raw, err := c.call(ctx, http.MethodPost,
		"/api/v1/tenants/"+slug+"/backups/"+bid+"/restore", req)
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var out struct {
			LeftStopped bool   `json:"left_stopped"`
			Hint        string `json:"hint"`
		}
		if err := json.Unmarshal(b, &out); err != nil {

			return err
		}
		fmt.Printf("%s: restored %s%s\n", slug, bid, forcedNote(req.Force))
		if out.LeftStopped {

			fmt.Printf("%s: left STOPPED: %s\n", slug, out.Hint)
		}
		return nil
	})
}

func forcedNote(forced bool) string {

	if forced {

		return " (FORCED past the pb_version guard)"
	}
	return ""
}

// versionSetState is `citadel runtime-version set-state <ver> --state <s>`.
func (c *client) versionSetState(ctx context.Context, args []string) error {

	if len(args) == 0 {

		return errors.New("runtime-version set-state needs a version")
	}
	version, rest := args[0], args[1:]
	var req api.SetVersionStateRequest
	for i := 0; i < len(rest); i++ {

		var err error
		switch rest[i] {

		case "--state":
			req.State, err = next(rest, &i, "--state")
		case "--eol-at":
			req.EOLAt, err = next(rest, &i, "--eol-at")
		default:
			err = fmt.Errorf("unknown flag %q", rest[i])
		}
		if err != nil {

			return err
		}
	}
	if req.State == "" {

		return errors.New("runtime-version set-state needs --state current|supported|deprecated|eol")
	}
	raw, err := c.call(ctx, http.MethodPost,
		"/api/v1/admin/runtime-versions/"+version+"/state", req)
	if err != nil {

		return err
	}
	return c.emit(raw, func(b []byte) error {

		var rv store.RuntimeVersion
		if err := decodeInto(b, &rv); err != nil {

			return printJSON(b)
		}
		fmt.Printf("%s is now %s", rv.Version, rv.State)
		if rv.EOLAt != nil {

			fmt.Printf(", end of life %s", rv.EOLAt.UTC().Format("2006-01-02"))
		}
		fmt.Println()
		return nil
	})
}

func renderUpgradeList(b []byte) error {

	var payload struct {
		Upgrades []store.UpgradeJob `json:"upgrades"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {

		return printJSON(b)
	}
	if len(payload.Upgrades) == 0 {

		fmt.Println("no upgrade jobs")
		return nil
	}
	w := tw()
	fmt.Fprintln(w, "JOB\tFROM\tTO\tSTATE\tREHEARSAL\tSNAPSHOT\tSTARTED")
	for _, j := range payload.Upgrades {

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", j.ID, j.FromVersion, j.ToVersion,
			j.State, dash(j.Rehearsal), dash(j.SnapshotID), j.CreatedAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

// renderUpgradeJob prints one job and, when there is one, its rehearsal report.
//
// The failures and the hook errors are printed verbatim and in full. This is
// the output an operator reads at 2am to decide whether to force an upgrade or
// quarantine a tenant, and a summary is not enough to decide either.
func renderUpgradeJob(b []byte) error {

	var j store.UpgradeJob
	if err := json.Unmarshal(b, &j); err != nil {

		return printJSON(b)
	}
	fmt.Printf("%s  %s → %s  [%s]\n", j.ID, j.FromVersion, j.ToVersion, j.State)
	if j.Forced {

		fmt.Println("  forced by the platform (the source version is end-of-life)")
	}
	fmt.Printf("  rehearsal: %s\n", dash(j.Rehearsal))
	if j.SnapshotID != "" {

		fmt.Printf("  pre-upgrade snapshot: %s (the only rollback path)\n", j.SnapshotID)
	}
	if j.RehearsalJSON != "" {

		var rep reconcile.RehearsalReport
		if err := json.Unmarshal([]byte(j.RehearsalJSON), &rep); err == nil {

			printRehearsal(rep)
		}
	}
	if j.Log != "" {

		fmt.Printf("\n%s\n", j.Log)
	}
	return nil
}

func printRehearsal(rep reconcile.RehearsalReport) {

	fmt.Printf("\n  rehearsal on %s (%s)\n", rep.TargetVersion, verdict(rep.Passed))
	for _, f := range rep.Failures {

		fmt.Printf("    ✗ %s\n", f)
	}
	if rep.Probe != nil {

		for _, s := range rep.Probe.Smoke {

			fmt.Printf("    %s %s %s → %s\n", mark(s.OK), s.Method, s.Path, okOr(s.OK, s.Error))
		}
		// Printed even when every one failed as intended, which is the normal
		// case: "no egress was reachable" is the claim, and a claim with no
		// evidence under it is just an assertion.
		for _, e := range rep.Probe.Egress {

			fmt.Printf("    %s egress %s: %s\n", mark(!e.Connected), e.Target,
				okOr(!e.Connected, "REACHED — the rehearsal was not isolated"))
		}
	}
	for _, h := range rep.HookErrors {

		fmt.Printf("    hook: %s\n", h)
	}
	if rep.Error != "" {

		fmt.Printf("    error: %s\n", rep.Error)
	}
	for _, r := range rep.Residue {

		fmt.Printf("    RESIDUE: %s\n", r)
	}
}

func verdict(ok bool) string {

	if ok {

		return "passed"
	}
	return "FAILED"
}

func mark(ok bool) string {

	if ok {

		return "✓"
	}
	return "✗"
}

func okOr(ok bool, msg string) string {

	if ok {

		return "ok"
	}
	return msg
}
