package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/rehearsal"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// RehearsalReport is what a rehearsal tells the tenant (§12, §16 task 6).
//
// It carries the probe's findings AND the rehearsal instance's own log, because
// the two answer different questions. The probe says "your smoke requests
// returned the wrong status"; the log says WHY — a hook that threw at
// registration time against an API the new binary no longer has.
type RehearsalReport struct {
	JobID         string            `json:"job_id"`
	TenantID      string            `json:"tenant_id"`
	FromVersion   string            `json:"from_version"`
	TargetVersion string            `json:"target_version"`
	TargetImage   string            `json:"target_image"`
	Passed        bool              `json:"passed"`
	Probe         *rehearsal.Report `json:"probe,omitempty"`
	HookErrors    []string          `json:"hook_errors,omitempty"`
	Failures      []string          `json:"failures,omitempty"`
	Logs          string            `json:"logs,omitempty"`
	Error         string            `json:"error,omitempty"`
	Network       map[string]any    `json:"network,omitempty"`
	Residue       []string          `json:"residue,omitempty"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
}

// egressProbeTargets are what a rehearsal must fail to reach.
//
// One public address, one DNS port and the platform's own egress proxy. The
// last is the interesting one: a tenant WITH an approved egress grant has a
// working path to that proxy in production, and the rehearsal must not — §12
// says a rehearsal has no egress "regardless of the tenant's manifest", because
// a hook that sends mail or charges a card must not do it from a rehearsal.
func (r *Reconciler) egressProbeTargets() []string {

	out := []string{"1.1.1.1:443", "1.1.1.1:53"}
	if ip, err := r.egress.ProxyIP(); err == nil {

		out = append(out, fmt.Sprintf("%s:%d", ip, r.cfg.EgressProxyPort))
	}
	return out
}

// Rehearse runs one upgrade rehearsal end to end (§12).
//
// Setup order is §8.3's, which applies here too: data, then network, then
// rules, then the container. Never a container first — that is a window in
// which a hook has whatever the unconfigured network allows.
//
// Teardown is the reverse and runs unconditionally, including on every failure
// path. Whatever it cannot remove is reported as residue rather than retried
// silently: a rehearsal that leaks a network leaks a subnet, and a platform
// that leaks subnets eventually cannot provision.
func (r *Reconciler) Rehearse(ctx context.Context, t store.Tenant, job store.UpgradeJob, target store.RuntimeVersion, man pkgvalidate.Manifest) RehearsalReport {

	rep := RehearsalReport{
		JobID:         job.ID,
		TenantID:      t.ID,
		FromVersion:   t.RuntimeVersion,
		TargetVersion: target.Version,
		TargetImage:   target.ImageDigest,
		StartedAt:     time.Now().UTC(),
	}
	defer func() { rep.FinishedAt = time.Now().UTC() }()

	if r.cfg.ProbeImage == "" {

		// Reported, never silently skipped. An upgrade that stops rehearsing
		// without saying so is the failure this whole phase exists to prevent.
		rep.Error = "no probe image is configured (probe_image); a rehearsal cannot be run"
		return rep
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.RehearsalTimeout.D())
	defer cancel()

	// Teardown is registered before the first resource is created, so a failure
	// anywhere below still cleans up.
	defer func() {

		rep.Residue = r.teardownRehearsal(context.WithoutCancel(ctx), job.ID)
		if len(rep.Residue) > 0 {

			detail := strings.Join(rep.Residue, "; ")
			r.log.Error("rehearsal teardown left residue behind", "job", job.ID, "residue", detail)
			r.drift.Record(Drift{Kind: DriftRehearsalResidue, TenantID: t.ID, Detail: detail, Security: true})
			r.auditTenant(ctx, t.ID, auditlog.ActionUpgradeRehearsalResidue, "upgrade/"+job.ID,
				map[string]any{"items": len(rep.Residue)})
		}
	}()
	// Registered after the teardown, so it runs before it on every return path.
	// Bounded by ctx, so a hold never outlives the rehearsal's budget. The
	// report's FinishedAt includes it; it is only ever non-zero in a test.
	if hold := r.cfg.RehearsalHold.D(); hold > 0 {

		defer func() {

			select {
			case <-time.After(hold):
			case <-ctx.Done():
			}
		}()
	}

	lock, err := r.fs.LockWait(ctx, t.ID, lockBudget)
	if err != nil {

		rep.Error = "cannot take the tenant lock for the data copy: " + err.Error()
		return rep
	}
	dataCopy, _, err := r.backup.RehearsalCopy(ctx, t, job.ID, lock, r.liveCopier(t, lock))
	// Released as soon as the copy is made, not held for the whole rehearsal:
	// the tenant keeps serving throughout, and holding its lock for minutes
	// would block its deploys and its routine backup for no reason.
	lock.Release()
	if err != nil {

		rep.Error = "cannot copy the tenant's data: " + err.Error()
		return rep
	}

	alloc, err := r.rehearsalSubnet(ctx)
	if err != nil {

		rep.Error = err.Error()
		return rep
	}
	if err := r.net.EnsureRehearsalNetwork(ctx, job.ID, alloc); err != nil {

		rep.Error = err.Error()
		return rep
	}
	if _, err := r.net.EnsureRehearsalRules(job.ID, netpolicy.Ingress{EdgeIP: alloc.EdgeIP, TenantIP: alloc.TenantIP}); err != nil {

		rep.Error = err.Error()
		return rep
	}
	rep.Network = map[string]any{
		"name":   config.NetworkName(netpolicy.RehearsalSlug(job.ID)),
		"subnet": alloc.Subnet.String(),
	}

	spec, err := r.rehearsalSpec(ctx, t, job, alloc, dataCopy)
	if err != nil {

		rep.Error = err.Error()
		return rep
	}
	// Signed from the copy BEFORE it boots, for the TARGET version's claims:
	// once the target binary starts it migrates the copy, and reading a
	// database mid-migration is reading a moving target. The 0.23 migration
	// keeps every superuser's id and token key and carries the token secret
	// over, so a token signed now verifies after it. The TTL covers the whole
	// ready budget, since the probe cannot sign a fresh one.
	token, err := r.mintFrom(ctx, t, dataCopy, target.Version, pbauth.AnySuperuser(),
		r.cfg.HealthTimeout.D()+5*time.Minute)
	if err != nil {

		rep.Error = "cannot sign a superuser token from the data copy: " + err.Error()
		return rep
	}
	handle, err := r.drv.Rehearse(ctx, spec, target.ImageDigest, dataCopy)
	if err != nil {

		rep.Error = err.Error()
		return rep
	}

	planPath, err := r.writePlan(t, job, target, man, alloc)
	if err != nil {

		rep.Error = err.Error()
		rep.Logs = r.tailLogs(ctx, handle)
		return rep
	}
	out, probeErr := r.drv.Probe(ctx, dockerdrv.ProbeOptions{
		JobID:    job.ID,
		Network:  spec.Network,
		IP:       alloc.EdgeIP.String(),
		Image:    r.cfg.ProbeImage,
		PlanPath: planPath,
		Env: map[string]string{
			rehearsal.EnvToken: token,
		},
	})
	// The instance's log is collected whatever the probe did: on the failure
	// this phase exists to catch, the log is where the answer is.
	rep.Logs = r.tailLogs(ctx, handle)
	rep.HookErrors = health.HookErrors(rep.Logs)

	if probeErr != nil {

		// The probe malfunctioned, which is not the same as a failed rehearsal
		// and must not be reported to the tenant as "your app is broken".
		rep.Error = "the rehearsal probe did not complete: " + probeErr.Error()
		return rep
	}
	var probe rehearsal.Report
	if err := json.Unmarshal([]byte(lastJSONLine(out)), &probe); err != nil {

		rep.Error = "cannot read the probe report: " + err.Error()
		return rep
	}
	rep.Probe = &probe
	rep.Failures = probe.Failures()
	for _, h := range rep.HookErrors {

		rep.Failures = append(rep.Failures, "hook: "+h)
	}
	// Hook errors alone fail the rehearsal even when every smoke request
	// passed. A tenant whose hooks silently stopped registering has an app that
	// answers HTTP and does none of its own work, and shipping that as a pass is
	// worse than failing.
	rep.Passed = probe.Verdict() && len(rep.HookErrors) == 0
	return rep
}

// rehearsalSubnet allocates a free /29 for one rehearsal.
//
// `taken` comes from Docker rather than the tenant table: a rehearsal subnet
// has no row, and a subnet a crashed rehearsal left behind is exactly the one a
// fresh allocation must not collide with.
func (r *Reconciler) rehearsalSubnet(ctx context.Context) (netpolicy.Allocation, error) {

	pool, err := r.net.Pool()
	if err != nil {

		return netpolicy.Allocation{}, err
	}
	reserved, err := r.net.ReservedPrefixes()
	if err != nil {

		return netpolicy.Allocation{}, err
	}
	taken, err := r.net.LiveSubnets(ctx)
	if err != nil {

		return netpolicy.Allocation{}, err
	}
	rows, err := store.AllocatedSubnets(ctx, r.db.Reader())
	if err != nil {

		return netpolicy.Allocation{}, err
	}
	for _, s := range rows {

		if p, err := netip.ParsePrefix(s); err == nil {

			taken = append(taken, p)
		}
	}
	return netpolicy.AllocateSubnet(pool, taken, reserved)
}

// rehearsalSpec derives the rehearsal container's spec from the tenant's.
//
// Two things are stripped rather than left to the driver's refusal: the egress
// attachment and the proxy environment. The driver refuses both as well, and
// the duplication is deliberate — the strip is what makes the rehearsal work,
// the refusal is what catches a future caller who forgets.
func (r *Reconciler) rehearsalSpec(ctx context.Context, t store.Tenant, job store.UpgradeJob, alloc netpolicy.Allocation, dataCopy string) (driver.InstanceSpec, error) {

	spec, err := r.specFor(ctx, t)
	if err != nil {

		return driver.InstanceSpec{}, err
	}
	spec.RehearsalJob = job.ID
	spec.Network = config.NetworkName(netpolicy.RehearsalSlug(job.ID))
	spec.IP = alloc.TenantIP.String()
	spec.DataDir = dataCopy
	spec.EgressNet, spec.EgressIP = "", ""
	for k := range spec.Env {

		if k != "PB_ENCRYPTION_KEY" {

			// specFor injects the proxy variables into every spec as
			// ergonomics. A rehearsal has no proxy to reach, and leaving them
			// would tell a cooperative hook that one exists.
			delete(spec.Env, k)
		}
	}
	return spec, nil
}

// writePlan stages the probe's instructions next to the rehearsal's data copy.
func (r *Reconciler) writePlan(t store.Tenant, job store.UpgradeJob, target store.RuntimeVersion, man pkgvalidate.Manifest, alloc netpolicy.Allocation) (string, error) {

	plan := rehearsal.Plan{
		Target:      fmt.Sprintf("%s:%s", alloc.TenantIP.String(), dockerdrv.HTTPPort),
		Hostname:    t.Hostname,
		PBVersion:   target.Version,
		Egress:      r.egressProbeTargets(),
		ReadyBudget: rehearsal.Duration(r.cfg.HealthTimeout.D()),
	}
	if man.Healthcheck.Path != "" && man.Healthcheck.Path != health.HealthPath {

		plan.Healthcheck = &health.SmokeRequest{
			Method: "GET", Path: man.Healthcheck.Path, ExpectStatus: man.Healthcheck.ExpectStatus,
		}
	}
	for _, s := range man.Smoke {

		plan.Smoke = append(plan.Smoke, health.SmokeRequest{Method: s.Method, Path: s.Path, ExpectStatus: s.ExpectStatus})
	}
	raw, err := json.Marshal(plan)
	if err != nil {

		return "", err
	}
	path := filepath.Join(r.fs.ScratchDir(hostfs.ScratchRehearse, job.ID), "plan.json")
	// 0644 because the probe reads it as an unprivileged UID inside the
	// container. It carries no credentials — those arrive in the environment —
	// precisely so this file can be readable and kept with the job.
	if err := os.WriteFile(path, raw, 0o644); err != nil {

		return "", err
	}
	return path, nil
}

// teardownRehearsal removes everything one rehearsal created, in reverse order.
//
// Every step runs even when an earlier one failed. Skipping the network removal
// because a container would not delete is how a subnet leaks, and the residue
// list is what makes a partial teardown visible instead of silent.
func (r *Reconciler) teardownRehearsal(ctx context.Context, jobID string) []string {

	var residue []string
	if err := r.drv.RemoveRehearsal(ctx, jobID); err != nil {

		residue = append(residue, "containers: "+err.Error())
	}
	if _, rules, err := r.net.TeardownRehearsal(ctx, jobID); err != nil {

		residue = append(residue, "rules: "+err.Error())

	} else {

		residue = append(residue, rules...)
	}
	if err := r.fs.RemoveScratch(hostfs.ScratchRehearse, jobID); err != nil {

		residue = append(residue, "scratch: "+err.Error())
	}
	return residue
}

// reapRehearsals removes the leftovers of rehearsals whose job is over.
//
// Run on Bootstrap and on the tick. This is the only path that makes "full
// teardown" true after a crash, which is the one case where the claim is
// actually tested: a control plane killed mid-rehearsal has a container, a
// network, a firewall rule and a mounted loop device with nothing left to
// remove them.
func (r *Reconciler) reapRehearsals(ctx context.Context) {

	live, err := store.ActiveUpgradeIDs(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot read active upgrade jobs", "err", err)
		return
	}
	stale := map[string]bool{}
	if containers, err := r.drv.RehearsalContainers(ctx); err == nil {

		for job := range containers {

			if _, ok := live[job]; !ok {

				stale[job] = true
			}
		}
	}
	if nets, err := r.net.RehearsalNetworks(ctx); err == nil {

		for job := range nets {

			if _, ok := live[job]; !ok {

				stale[job] = true
			}
		}
	}
	if dirs, err := r.fs.OrphanScratch(hostfs.ScratchRehearse, liveSet(live)); err == nil {

		for _, job := range dirs {

			stale[job] = true
		}
	}
	for job := range stale {

		r.log.Warn("reaping the leftovers of a rehearsal whose job is over", "job", job)
		if residue := r.teardownRehearsal(ctx, job); len(residue) > 0 {

			detail := strings.Join(residue, "; ")
			r.drift.Record(Drift{Kind: DriftRehearsalResidue, Detail: detail, Security: true})
			r.log.Error("cannot fully reap a rehearsal", "job", job, "residue", detail)
		}
	}
}

func liveSet(m map[string]string) map[string]bool {

	out := make(map[string]bool, len(m))
	for k := range m {

		out[k] = true
	}
	return out
}

// lastJSONLine picks the probe's report out of its output.
//
// The container log may carry a runtime warning before the report, so the last
// line that looks like JSON is taken rather than the whole stream.
func lastJSONLine(out string) string {

	best := ""
	for line := range strings.SplitSeq(out, "\n") {

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {

			best = line
		}
	}
	return best
}
