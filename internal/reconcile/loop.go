// Package reconcile is the desired-state loop (design §8.3).
//
// Two ordering rules are not optional and shape everything here:
//
//   - Mount, network and firewall rules exist BEFORE the container starts.
//     Never start a container and then apply policy; that is a window in which a
//     hook has open egress. And a container started before its data mount serves
//     an empty pb_data, silently.
//   - Firewall rules are re-asserted on every tick, idempotently. A Docker
//     daemon restart, a `docker network prune` or an unrelated firewall reload
//     can drop them, so missing rules are drift to repair and to log loudly.
package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/backup"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/egressctl"
	"github.com/citadel-ai-apps/citadel/internal/health"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/logcollect"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Reconciler converges the host to the control-plane database.
type Reconciler struct {
	cfg    config.Config
	db     *store.DB
	fs     *hostfs.FS
	drv    *dockerdrv.Driver
	backup *backup.Service
	net    *netpolicy.Manager
	proxy  *proxyctl.Controller
	egress *egressctl.Controller
	logs   *logcollect.Collector
	hc     *health.Checker
	audit  *auditlog.Logger
	log    *slog.Logger
	drift  *DriftBoard
	first  bool
	userns int

	// republished records, per tenant, that its edge route has been rendered
	// by this process at least once. A route already present at start-up was
	// rendered by whatever release published it, and a later release may
	// render routes differently (the refusal of tenant client addresses, for
	// one); publishing each one once per process brings old routes forward
	// without a PATCH per tenant on every tick.
	republished sync.Map

	// attest and signer are optional so the reconciler can run in tests and in
	// the acceptance harness without a signing key on disk. A nil attest means
	// no signed reports, never a silently different verdict.
	attest Attestor
	signer auditlog.Signer

	lastAttest time.Time
	lastAnchor time.Time
	attesting  atomic.Bool
	noticeMu   sync.Mutex
	notices    map[string]bool

	// Backup and upgrade schedules (§11, §12). Each guarded by its own flag
	// because each runs off-tick and neither must overlap itself.
	lastRoutine     time.Time
	lastSweep       time.Time
	lastEOL         time.Time
	backingUp       atomic.Bool
	lastSweepResult atomic.Pointer[backup.SweepResult]

	// Upgrade jobs in flight, for the process-local half of INV-6 and for the
	// fleet-wide concurrency cap.
	claimMu  sync.Mutex
	claims   map[string]string
	upgrades int
}

// Attestor is what the reconciler needs from internal/attest. An interface
// because attest depends on netpolicy, egressctl and proxyctl, and importing it
// concretely here would make the dependency circular.
type Attestor interface {
	Generate(ctx context.Context, tenantID string) (attest.Report, error)
}

// Options bundles the Reconciler's collaborators.
type Options struct {
	Config     config.Config
	DB         *store.DB
	FS         *hostfs.FS
	Driver     *dockerdrv.Driver
	Backup     *backup.Service
	NetPolicy  *netpolicy.Manager
	Proxy      *proxyctl.Controller
	Egress     *egressctl.Controller
	Logs       *logcollect.Collector
	Health     *health.Checker
	Audit      *auditlog.Logger
	Log        *slog.Logger
	UsernsBase int
	Attest     Attestor
	Signer     auditlog.Signer
}

// New returns a Reconciler.
func New(o Options) *Reconciler {

	return &Reconciler{
		cfg: o.Config, db: o.DB, fs: o.FS, drv: o.Driver, backup: o.Backup, net: o.NetPolicy,
		proxy: o.Proxy, egress: o.Egress, logs: o.Logs, hc: o.Health, audit: o.Audit, log: o.Log,
		drift: newDriftBoard(), first: true, userns: o.UsernsBase,
		attest: o.Attest, signer: o.Signer, notices: map[string]bool{},
		claims: map[string]string{},
	}
}

// Drift exposes the current drift board for the API's fleet view.
func (r *Reconciler) Drift() *DriftBoard { return r.drift }

// Bootstrap runs the platform pass and the recovery pass once, synchronously.
//
// Called before the API starts serving, so the first request cannot race the
// first tick: provisioning needs the edge proxy and the platform firewall rules
// to already exist, and §8.3's ordering rule says policy comes before anything
// that could use it.
func (r *Reconciler) Bootstrap(ctx context.Context) error {

	if err := r.platformPass(ctx, r.first); err != nil {

		return err
	}
	r.first = false
	return r.Recover(ctx)
}

// Run ticks until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) {

	t := time.NewTicker(r.cfg.ReconcileInterval.D())
	defer t.Stop()
	for {

		r.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick runs one reconcile pass.
func (r *Reconciler) Tick(ctx context.Context) {

	first := r.first
	r.first = false

	if err := r.platformPass(ctx, first); err != nil {

		r.log.Error("platform reconcile failed", "err", err)
		return
	}

	tenants, err := store.ListTenants(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot list tenants", "err", err)
		return
	}
	known := make(map[string]bool, len(tenants))
	for _, t := range tenants {

		known[t.ID] = true
	}
	grants, err := r.knownGrantIDs(ctx, tenants)
	if err != nil {

		r.log.Error("cannot read the grant set", "err", err)
		return
	}

	// An extra rule is a security event, not drift to repair. Checked
	// once per tick against the whole tenant set rather than per tenant, because
	// the question is "whose rule is this, and what authorised it?" and the
	// answer needs every tenant and every grant.
	// A rehearsal's rule is backed by its job, not by a grant, so the check
	// needs the set of jobs in flight as well as the grant set.
	liveJobs, err := store.ActiveUpgradeIDs(ctx, r.db.Reader())
	if err != nil {

		r.log.Error("cannot read the active upgrade jobs", "err", err)
		return
	}
	jobSet := make(map[string]bool, len(liveJobs))
	for id := range liveJobs {

		jobSet[id] = true
	}

	r.checkUnbackedRules(ctx, known, grants, jobSet)
	r.checkOrphanDirs(known)
	r.accountabilityPass(ctx, tenants)
	r.backupPass(ctx, tenants)
	r.eolPass(ctx, tenants)
	r.reapUpgrades(ctx)
	r.reapRehearsals(ctx)

	for _, t := range tenants {

		if err := r.tenant(ctx, t); err != nil {

			if errors.Is(err, hostfs.ErrLocked) {

				// An API call holds the lock. It will finish; the next tick
				// picks the tenant up.
				r.log.Debug("tenant is busy, skipping this tick", "tenant", t.ID)
				continue
			}
			r.log.Error("tenant reconcile failed", "tenant", t.ID, "err", err)
		}
	}
}

// platformPass asserts everything that is not per-tenant, before any tenant is
// touched.
func (r *Reconciler) platformPass(ctx context.Context, first bool) error {

	changes, err := r.net.EnsurePlatformRules(first)
	if err != nil {

		return err
	}
	for _, c := range changes {

		if !c.Repaired {

			// Written for the first time, typically at start-up: still a
			// netpolicy write, and audited as one (§14.4).
			r.auditPlatform(ctx, auditlog.ActionRuleWritten, "rule/"+c.Rule.Comment,
				map[string]any{"chain": c.Rule.Chain, "v6": c.Rule.V6})
			continue
		}
		r.drift.Record(Drift{
			Kind:     DriftMissingRule,
			Detail:   c.Rule.String(),
			Repaired: true,
			Security: true,
		})
		r.auditPlatform(ctx, auditlog.ActionRuleRepaired, "rule/"+c.Rule.Comment,
			map[string]any{"chain": c.Rule.Chain})
	}

	if err := r.net.AssertOrder(); err != nil {

		var ov netpolicy.OrderViolation
		if errors.As(err, &ov) {

			// Present-but-wrongly-ordered is its own failure mode: the host
			// probes observed egress silently breaking and connections
			// half-opening, with every rule nominally in place
			// (design.md §9.5).
			r.log.Error("DOCKER-USER rule ORDER is wrong; presence is not enough",
				"reason", ov.Reason, "chain", ov.Chain)
			r.drift.Record(Drift{Kind: DriftRuleOrder, Detail: ov.Reason, Security: true})
			r.auditPlatform(ctx, auditlog.ActionNetpolicyDrift, "chain/"+ov.Chain,
				map[string]any{"reason": ov.Reason})

		} else {

			return err
		}

	} else {

		r.drift.Clear(DriftRuleOrder, "")
	}

	if err := r.proxy.EnsureEdge(ctx); err != nil {

		return err
	}
	// After the edge, because the allowlist is a fleet-wide question: it needs
	// every tenant's active grants, and rendering it once means the proxy is
	// reloaded once rather than once per tenant.
	return r.egressPass(ctx)
}

func (r *Reconciler) checkUnbackedRules(ctx context.Context, known map[string]bool, grants map[string]map[string]bool, liveJobs map[string]bool) {

	unbacked, err := r.net.UnbackedRules(known, grants, liveJobs)
	if err != nil {

		r.log.Error("cannot read the live ruleset", "err", err)
		return
	}
	r.drift.Clear(DriftUnbackedRule, "")
	for _, o := range unbacked {

		detail := unbackedRuleDetail(o)
		// Never repaired, never removed. Auto-removing would destroy the
		// evidence and hide a recurring intrusion behind a self-healing loop
		// (§14.5).
		r.log.Error("SECURITY: a tagged firewall rule has no matching tenant or grant; NOT removing it",
			"detail", detail)
		r.drift.Record(Drift{Kind: DriftUnbackedRule, Detail: detail, Security: true})
		r.auditPlatform(ctx, auditlog.ActionUnbackedRule, "rule/"+o.Comment,
			map[string]any{"chain": o.Chain, "target": o.Target})
		// The drift alert says something is wrong; the attestation is the signed
		// record of WHAT, and it is what the tenant's own report shows. Generated
		// now rather than at the next scheduled pass, because an incident
		// already detected should not wait hours to become evidence.
		if tenant := o.Fields["tenant"]; tenant != "" && known[tenant] {

			r.AttestNow(ctx, tenant)
		}
	}
}

func (r *Reconciler) checkOrphanDirs(known map[string]bool) {

	dirs, err := r.fs.OrphanTenantDirs(known)
	if err != nil {

		r.log.Error("cannot scan tenant directories", "err", err)
		return
	}
	r.drift.Clear(DriftOrphanDir, "")
	for _, d := range dirs {

		// Reported, never deleted: the directory holds a database, and removing
		// one on the strength of a missing row turns a control-plane bug into
		// permanent data loss.
		r.log.Warn("tenant directory on disk has no tenant row; leaving it in place",
			"dir", d)
		r.drift.Record(Drift{Kind: DriftOrphanDir, TenantID: d,
			Detail: "directory exists on disk with no tenant row"})
	}
}

// Recover reconciles the host against the database at start-up.
//
// Not a special mode: every mutation commits its state change and its audit
// event in one transaction, so there is no half-written state to repair. What
// recovery does is find host objects the database does not claim — a container
// or network left behind by a crash between create and commit.
func (r *Reconciler) Recover(ctx context.Context) error {

	tenants, err := store.ListTenants(ctx, r.db.Reader())
	if err != nil {

		return err
	}
	known := make(map[string]bool, len(tenants))
	for _, t := range tenants {

		known[t.ID] = true
	}

	// A one-shot left by a crash still has a tenant's pb_data open, and the
	// next start would put the instance on it too (INV-3). None can be
	// legitimate at start-up: every one is removed before the lock it ran
	// under is released.
	oneShots, err := r.drv.RemoveOneShots(ctx)
	for _, tenantID := range oneShots {

		r.log.Warn("removed a one-shot container left by a crash", "tenant", tenantID)
		r.auditPlatform(ctx, auditlog.ActionRecovered, "container/oneshot/"+tenantID,
			map[string]any{"action": "removed_orphan_oneshot"})
	}
	if err != nil {

		return err
	}

	containers, err := r.drv.ManagedContainers(ctx)
	if err != nil {

		return err
	}
	for tenantID := range containers {

		if known[tenantID] {

			continue
		}
		name := config.ContainerName(tenantID)
		r.log.Warn("removing an orphaned container with no tenant row", "container", name)
		if err := r.drv.RemoveOrphan(ctx, name); err != nil {

			r.log.Error("cannot remove orphaned container", "container", name, "err", err)
			continue
		}
		r.auditPlatform(ctx, auditlog.ActionRecovered, "container/"+name,
			map[string]any{"action": "removed_orphan_container"})
	}

	networks, err := r.drv.ManagedNetworks(ctx)
	if err != nil {

		return err
	}
	for tenantID, netName := range networks {

		if known[tenantID] {

			continue
		}
		r.log.Warn("removing an orphaned network with no tenant row", "network", netName)
		_ = r.proxy.DetachNetwork(ctx, tenantID)
		if err := r.net.RemoveTenantNetwork(ctx, tenantID); err != nil {

			r.log.Error("cannot remove orphaned network", "network", netName, "err", err)
			continue
		}
		r.auditPlatform(ctx, auditlog.ActionRecovered, "network/"+netName,
			map[string]any{"action": "removed_orphan_network"})
	}

	// An edge route for a tenant that no longer exists would keep serving a
	// hostname the platform does not own a tenant for.
	if routes, err := r.proxy.RouteIDs(ctx); err == nil {

		for slug := range routes {

			if known[slug] {

				continue
			}
			r.log.Warn("removing an orphaned edge route", "slug", slug)
			if err := r.proxy.RemoveRoute(ctx, slug); err == nil {

				r.auditPlatform(ctx, auditlog.ActionRouteRemoved, "route/"+slug,
					map[string]any{"action": "removed_orphan_route"})
			}
		}
	}
	return nil
}

// auditPlatform writes an audit event for reconciler-originated work.
//
// The actor is the platform principal: automated actions get a real actor
// rather than a NULL (§14.1). Failures are logged and swallowed — the alternative
// is a reconcile tick that aborts because it could not write a log line, which
// would turn an audit problem into an availability problem.
func (r *Reconciler) auditPlatform(ctx context.Context, action, subject string, detail map[string]any) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    identity.PlatformPrincipal,
			ActorKind:  identity.KindPlatform,
			Action:     action,
			SubjectRef: subject,
			Detail:     detail,
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot write audit event", "action", action, "subject", subject, "err", err)
	}
}

// auditTenant is auditPlatform scoped to a tenant.
func (r *Reconciler) auditTenant(ctx context.Context, tenantID, action, subject string, detail map[string]any) {

	err := r.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    identity.PlatformPrincipal,
			ActorKind:  identity.KindPlatform,
			TenantID:   tenantID,
			Action:     action,
			SubjectRef: subject,
			Detail:     detail,
		})
		return err
	})
	if err != nil {

		r.log.Error("cannot write audit event", "tenant", tenantID, "action", action, "err", err)
	}
}

// specFor renders the driver spec for a tenant.
func (r *Reconciler) specFor(ctx context.Context, t store.Tenant) (driver.InstanceSpec, error) {

	key, err := r.fs.EncryptionKey(t.ID)
	if err != nil {

		return driver.InstanceSpec{}, err
	}
	env := map[string]string{"PB_ENCRYPTION_KEY": key}
	// Set for every tenant, granted or not. These are ergonomics, never
	// enforcement — the DOCKER-USER DROP is the boundary — and making
	// them a constant of the tenant's life means granting or revoking access
	// never needs a container recreate. Without a grant the tenant is not on the
	// egress network at all, so a hook that honours them gets an immediate
	// "no route to host" rather than a silent timeout.
	for k, v := range r.egress.ProxyEnv() {

		env[k] = v
	}
	// The egress attachment is part of the spec, so a first grant or a last
	// revocation shows up as a container to recreate. It cannot be applied to a
	// running container: under runsc that is a silent no-op
	// (design.md §9.4).
	egressNet, egressIP := "", ""
	if eg, _, err := r.egressBinding(ctx, t); err == nil && eg != nil {

		egressNet, egressIP = r.cfg.EgressNetwork, eg.TenantIP.String()
	}
	return driver.InstanceSpec{
		TenantID:    t.ID,
		Name:        config.ContainerName(t.Slug),
		EgressNet:   egressNet,
		EgressIP:    egressIP,
		ImageDigest: t.ImageDigest,
		AppDir:      r.fs.AppCurrent(t.ID),
		DataDir:     r.fs.DataDir(t.ID),
		Network:     t.NetworkName,
		IP:          t.ContainerIP,
		CPUs:        t.CPUs,
		MemMiB:      t.MemMiB,
		PidsLimit:   r.cfg.PidsLimit,
		LogMaxBytes: r.cfg.LogMaxBytes,
		Runtime:     r.cfg.TenantRuntime,
		Env:         env,

		SeccompProfilePath: r.cfg.SeccompProfile,
		AppArmorProfile:    r.cfg.AppArmorProfile,
	}, nil
}

// lockBudget is how long an operation a caller is waiting on retries for the
// tenant's instance.lock before giving up.
//
// Longer than a reconcile interval on purpose: the tick takes the lock for a
// fraction of a second every five seconds, and an upgrade or a restore that
// refused because it happened to collide with one would be failing for a reason
// that has nothing to do with what was asked. The reconciler itself keeps the
// non-blocking Lock and simply skips a busy tenant.
const lockBudget = 15 * time.Second
