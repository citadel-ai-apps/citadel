package api

import (
	"context"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/store"
)

// upgradeFleet answers §15's version rows: the registry with its lifecycle
// states, who is blocking the next EOL date, and which upgrades are in flight
// or stopped by a rehearsal.
//
// The EOL row is the one that earns its place. A version's EOL date is
// published when it enters `deprecated`, and the question an operator has to
// answer from then on is not "when is the date" but "who is still on it" — a
// list of tenants, not a count, because the next step is talking to them.
func (s *Server) upgradeFleet(ctx context.Context, tenants []store.Tenant) (map[string]any, error) {

	versions, err := store.ListRuntimeVersions(ctx, s.db.Reader())
	if err != nil {

		return nil, err
	}
	onVersion := map[string][]string{}
	for _, t := range tenants {

		if t.DesiredState == store.DesiredDeleted {

			continue
		}
		onVersion[t.RuntimeVersion] = append(onVersion[t.RuntimeVersion], t.Slug)
	}

	now := time.Now().UTC()
	var exposure []map[string]any
	for _, v := range versions {

		if v.State != store.VersionDeprecated && v.State != store.VersionEOL {

			continue
		}
		if len(onVersion[v.Version]) == 0 {

			continue
		}
		row := map[string]any{
			"version": v.Version, "state": v.State, "tenants": onVersion[v.Version],
		}
		if v.EOLAt != nil {

			row["eol_at"] = v.EOLAt.Format(time.RFC3339)
			row["days_left"] = int(v.EOLAt.Sub(now).Hours() / 24)
		}
		exposure = append(exposure, row)
	}

	active, err := store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{Active: true, Limit: 100})
	if err != nil {

		return nil, err
	}
	// Failed rehearsals from the last week, with their reason. §15 names this
	// row explicitly: it is the list of tenants who tried to move and could
	// not, which is where support time goes.
	recent, err := store.ListUpgradeJobs(ctx, s.db.Reader(), store.UpgradeJobFilter{
		Since: now.AddDate(0, 0, -7), Limit: 200,
	})
	if err != nil {

		return nil, err
	}
	var failedRehearsal []map[string]any
	for _, j := range recent {

		if j.Rehearsal != store.RehearsalFailed {

			continue
		}
		failedRehearsal = append(failedRehearsal, map[string]any{
			"job": j.ID, "tenant": j.TenantID, "from": j.FromVersion, "to": j.ToVersion,
			"forced": j.Forced, "at": j.CreatedAt.Format(time.RFC3339), "log": j.Log,
		})
	}
	return map[string]any{
		"versions":         versions,
		"eol_exposure":     exposure,
		"active":           active,
		"failed_rehearsal": failedRehearsal,
	}, nil
}

// backupFleet answers "is anything still being backed up?".
//
// §15 alerts on a failed backup, and until now nothing could raise that alert:
// a routine backup that stops running changes nothing an operator would notice,
// because the tenant keeps serving perfectly well right up until the day
// somebody needs a restore. Backup AGE per tenant is the only signal there is.
func (s *Server) backupFleet(ctx context.Context, tenants []store.Tenant) (map[string]any, error) {

	newest, err := store.NewestBackupPerTenant(ctx, s.db.Reader(), store.BackupRoutine)
	if err != nil {

		return nil, err
	}
	now := time.Now().UTC()
	// Two intervals, not one: a single missed pass is a busy tenant or a
	// deploy holding the lock, and paging on that teaches people to ignore it.
	stale := 2 * s.cfg.RoutineBackupInterval.D()
	var overdue []map[string]any
	for _, t := range tenants {

		if t.DesiredState != store.DesiredRunning {

			continue
		}
		at, ok := newest[t.ID]
		if !ok {

			overdue = append(overdue, map[string]any{"tenant": t.Slug, "last": "never"})
			continue
		}
		if now.Sub(at) > stale {

			overdue = append(overdue, map[string]any{
				"tenant": t.Slug, "last": at.Format(time.RFC3339),
				"age": now.Sub(at).Round(time.Minute).String(),
			})
		}
	}
	out := map[string]any{
		"routine_interval": s.cfg.RoutineBackupInterval.D().String(),
		"overdue":          overdue,
	}
	if sweep := s.rec.LastSweep(); sweep != nil {

		out["last_sweep"] = sweep

	} else {

		// Distinguished from a sweep that deleted nothing: "no sweep has run
		// since this process started" is a different fact, and on a process
		// that has been up for days it is a problem.
		out["last_sweep"] = "not run since start-up"
	}
	return out, nil
}
