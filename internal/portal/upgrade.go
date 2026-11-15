package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// upgradeTargets lists the versions a tenant may move to, lowest first.
//
// Lowest first rather than newest first because §12 keeps three or four minor
// lines and hooks written for one are likelier to survive the next than the
// last: the default choice on the page should be the smallest step.
func (s *Server) upgradeTargets(ctx context.Context, t store.Tenant) []store.RuntimeVersion {

	all, err := store.ListRuntimeVersions(ctx, s.db.Reader())
	if err != nil {

		return nil
	}
	var out []store.RuntimeVersion
	for _, v := range all {

		if v.Version == t.RuntimeVersion || !v.Upgradable() {

			continue
		}
		if cmp, err := pkgvalidate.Compare(v.Version, t.RuntimeVersion); err != nil || cmp <= 0 {

			continue
		}
		out = append(out, v)
	}
	return out
}

// eolView is the banner a tenant on a retiring version sees.
type eolView struct {
	Version  string
	State    string
	EOLAt    time.Time
	DaysLeft int
	Target   string
}

func (s *Server) eolFor(ctx context.Context, t store.Tenant, targets []store.RuntimeVersion) *eolView {

	rv, err := store.GetRuntimeVersion(ctx, s.db.Reader(), t.RuntimeVersion)
	if err != nil || (rv.State != store.VersionDeprecated && rv.State != store.VersionEOL) {

		return nil
	}
	v := &eolView{Version: rv.Version, State: rv.State}
	if rv.EOLAt != nil {

		v.EOLAt = *rv.EOLAt
		v.DaysLeft = int(time.Until(*rv.EOLAt).Hours() / 24)
	}
	if len(targets) > 0 {

		v.Target = targets[0].Version
	}
	return v
}

// startUpgrade is the portal's Rehearse / Upgrade buttons.
func (s *Server) startUpgrade(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	to := req.FormValue("to")
	if to == "" {

		back(w, req, "/t/"+t.ID, "", errors.New("choose a version to upgrade to"))
		return
	}
	// The portal never offers "skip the rehearsal". That flag exists for an
	// operator holding an incident in their head, not for a button.
	job, err := s.rec.StartUpgrade(ctx, sess.actor, t, reconcile.UpgradeRequest{
		To:           to,
		RehearseOnly: req.FormValue("rehearse_only") == "1",
	})
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}
	back(w, req, "/t/"+t.ID+"/upgrade/"+job.ID,
		fmt.Sprintf("upgrade job %s started; this page refreshes as it runs", job.ID), nil)
}

// upgradeJobView is one job with its rehearsal report decoded.
type upgradeJobView struct {
	Job       store.UpgradeJob
	Tenant    store.Tenant
	Report    *reconcile.RehearsalReport
	Terminal  bool
	CanDeploy bool
}

// upgradePage shows one job, polling while it is still moving.
func (s *Server) upgradePage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	a, err := s.resolveTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.auditBreakglassView(ctx, sess.actor, a); err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, role := a.Tenant, a.Role
	job, err := store.GetUpgradeJob(ctx, s.db.Reader(), mux.Vars(req)["jobid"])
	if err != nil || job.TenantID != t.ID {

		http.Error(w, "no such upgrade job for this project", http.StatusNotFound)
		return
	}
	v := upgradeJobView{
		Job: job, Tenant: t, Terminal: job.Terminal(),
		CanDeploy: identity.RoleAllows(role, identity.CapDeploy),
	}
	if job.RehearsalJSON != "" {

		var rep reconcile.RehearsalReport
		if err := json.Unmarshal([]byte(job.RehearsalJSON), &rep); err == nil {

			v.Report = &rep
		}
	}
	s.render(w, req, "upgrade.html", "Upgrade "+job.ID, v)
}

// restoreBackup is the portal's restore button.
func (s *Server) restoreBackup(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapDeploy)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	b, err := store.GetBackup(ctx, s.db.Reader(), mux.Vars(req)["bid"])
	if err != nil || b.TenantID != t.ID {

		back(w, req, "/t/"+t.ID, "", errors.New("no such snapshot for this project"))
		return
	}
	// Never forced from the portal. The force flag disables the check that
	// stops an older snapshot re-triggering the one-way migration, and that is
	// a deliberate operator decision at a terminal (design.md §12), not
	// behind a button.
	_, err = s.rec.RestoreBackup(ctx, sess.actor, t, b, false)
	back(w, req, "/t/"+t.ID, "restored "+b.ID+"; your data is as it was at "+b.CreatedAt.Format(time.RFC822), err)
}

// fleetPage is §15's operator screen.
func (s *Server) fleetPage(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	if !s.isOperator(sess.actor) {

		http.Error(w, "the fleet view is an operator surface", http.StatusForbidden)
		return
	}
	tenants, err := store.ListTenants(ctx, s.db.Reader())
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	versions, _ := store.ListRuntimeVersions(ctx, s.db.Reader())
	active, _ := store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{Active: true, Limit: 50})
	recent, _ := store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{
		Since: time.Now().UTC().AddDate(0, 0, -7), Limit: 100,
	})
	newest, _ := store.NewestBackupPerTenant(ctx, s.db.Reader(), store.BackupRoutine)

	onVersion := map[string][]string{}
	for _, t := range tenants {

		if t.DesiredState != store.DesiredDeleted {

			onVersion[t.RuntimeVersion] = append(onVersion[t.RuntimeVersion], t.Slug)
		}
	}
	type backupRow struct {
		Tenant string
		Last   string
		Stale  bool
	}
	now := time.Now().UTC()
	stale := 2 * s.cfg.RoutineBackupInterval.D()
	var backups []backupRow
	for _, t := range tenants {

		if t.DesiredState != store.DesiredRunning {

			continue
		}
		row := backupRow{Tenant: t.Slug, Last: "never", Stale: true}
		if at, ok := newest[t.ID]; ok {

			row.Last = at.Format(time.RFC822)
			row.Stale = now.Sub(at) > stale
		}
		backups = append(backups, row)
	}
	var failed []store.UpgradeJob
	for _, j := range recent {

		if j.Rehearsal == store.RehearsalFailed {

			failed = append(failed, j)
		}
	}
	s.render(w, req, "fleet.html", "Fleet", map[string]any{
		"Tenants":   tenants,
		"Versions":  versions,
		"OnVersion": onVersion,
		"Active":    active,
		"Failed":    failed,
		"Backups":   backups,
		"Sweep":     s.rec.LastSweep(),
		"Drift":     s.rec.Drift().List(),
	})
}
