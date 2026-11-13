package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

var platformActor = identity.Platform()

// slugPattern is deliberately narrow: a slug becomes a DNS label, a Docker
// network name, a bridge interface name and an iptables comment field.
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ProvisionRequest is what the API hands the reconciler to create a tenant.
type ProvisionRequest struct {
	Slug      string
	PBVersion string
	OwnerID   string
	AppDir    string // optional; empty means the empty artifact
	CPUs      float64
	MemMiB    int
	DiskMiB   int
	BodyCap   string
}

// ValidateMemMiB rejects a memory limit a tenant cannot run in. It is shared
// by create and resize, so a tenant cannot be resized into the state create
// refuses.
func ValidateMemMiB(runtime string, mib int) error {

	if mib <= 0 {

		return fmt.Errorf("mem_mib must be positive, got %d", mib)
	}
	if runtime == "runsc" && mib < driver.RunscMinMemMiB {

		return fmt.Errorf("mem_mib %d is below the %d MiB a runsc sandbox needs", mib, driver.RunscMinMemMiB)
	}
	return nil
}

// ValidateSlug checks a slug against every constraint it has to satisfy.
func ValidateSlug(slug string) error {

	if !slugPattern.MatchString(slug) {

		return fmt.Errorf("slug %q must be lowercase alphanumeric with internal hyphens", slug)
	}
	if len(slug) > config.MaxSlugLen {

		// Linux caps interface names at IFNAMSIZ (15) and `br-t-` takes 5. Over
		// the limit, the bridge-name option fails at network create — and worse,
		// a truncated bridge would stop matching the `br-t-+` INPUT wildcard and
		// the tenant would silently lose its host protection.
		return fmt.Errorf("slug %q is %d characters; the bridge name %s must fit IFNAMSIZ (max %d)",
			slug, len(slug), config.BridgeName(slug), config.MaxSlugLen)
	}
	if rehearsalSlug.MatchString(slug) {

		// Rehearsal networks are named t-rh<job id hex> (netpolicy.RehearsalSlug)
		// and torn down by name. A tenant holding such a slug would share its
		// network name with a rehearsal, and a rehearsal teardown would remove
		// the tenant's network.
		return fmt.Errorf("slug %q is reserved: rh followed by hex digits names upgrade rehearsals", slug)
	}
	return nil
}

// rehearsalSlug is the shape of netpolicy.RehearsalSlug.
var rehearsalSlug = regexp.MustCompile(`^rh[0-9a-f]*$`)

// Provision creates a tenant and brings it up.
//
// Every step is idempotent and re-entrant, in an order where a crash at any
// point converges on the next run: allocate (one transaction, with the audit
// event) → directories → quota image → mount → chown → keys → artifact →
// symlink → network → rules → one-shot owner seat → container → edge → health.
//
// The database transaction is first and includes the tenant row, the ownership
// row and the audit event. Either all three exist or none do — so there is no
// state in which a tenant exists without an owner or without an
// attributable creation event.
func (r *Reconciler) Provision(ctx context.Context, actor identity.Actor, req ProvisionRequest) (store.Tenant, error) {

	if err := ValidateSlug(req.Slug); err != nil {

		return store.Tenant{}, err
	}
	rv, err := store.GetRuntimeVersion(ctx, r.db.Reader(), req.PBVersion)
	if err != nil {

		return store.Tenant{}, err
	}
	owner, err := r.identityService().Get(ctx, req.OwnerID)
	if err != nil {

		return store.Tenant{}, fmt.Errorf("provision: owner %s: %w", req.OwnerID, err)
	}
	// An accountable owner is one who can act (INV-17): a suspended principal
	// cannot accept a transfer, answer for the tenant or even sign in.
	if owner.Status != identity.StatusActive {

		return store.Tenant{}, fmt.Errorf("provision: owner %s: %w: %s", req.OwnerID, identity.ErrInactive, owner.Status)
	}

	t := store.Tenant{
		ID:             req.Slug, // one id space: the slug IS the id
		Slug:           req.Slug,
		Hostname:       r.cfg.Hostname(req.Slug),
		DesiredState:   store.DesiredRunning,
		RuntimeVersion: rv.Version,
		ImageDigest:    rv.ImageDigest,
		NetworkName:    config.NetworkName(req.Slug),
		CPUs:           orFloat(req.CPUs, r.cfg.DefaultCPUs),
		MemMiB:         orInt(req.MemMiB, r.cfg.DefaultMemMiB),
		DiskMiB:        orInt(req.DiskMiB, r.cfg.DefaultDiskMiB),
		BodyCap:        orStr(req.BodyCap, r.cfg.DefaultBodyCap),
		EncKeyRef:      hostfs.EncKeyRef(req.Slug),
	}
	if err := ValidateMemMiB(r.cfg.TenantRuntime, t.MemMiB); err != nil {

		return store.Tenant{}, fmt.Errorf("provision: %w", err)
	}

	// The allocation and the row are written in one transaction so two
	// concurrent creates cannot be handed the same /29.
	err = r.db.Tx(ctx, func(tx bun.Tx) error {

		pool, err := r.net.Pool()
		if err != nil {

			return err
		}
		reserved, err := r.net.ReservedPrefixes()
		if err != nil {

			return err
		}
		takenStrs, err := store.AllocatedSubnets(ctx, tx)
		if err != nil {

			return err
		}
		taken, err := netpolicy.ParsePrefixes(takenStrs)
		if err != nil {

			return err
		}
		alloc, err := netpolicy.AllocateSubnet(pool, taken, reserved)
		if err != nil {

			return err
		}
		t.Subnet = alloc.Subnet.String()
		t.GatewayIP = alloc.GatewayIP.String()
		t.EdgeIP = alloc.EdgeIP.String()
		t.ContainerIP = alloc.TenantIP.String()

		if err := store.InsertTenant(ctx, tx, t); err != nil {

			return err
		}
		// Ownership in the same transaction: a tenant that briefly exists
		// without an owner is a tenant nobody is accountable for.
		if err := r.identityService().GrantRole(ctx, tx, actor, t.ID, req.OwnerID, identity.RoleOwner); err != nil {

			return err
		}
		_, err = r.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    actor.ID,
			ActorKind:  actor.Kind,
			TenantID:   t.ID,
			Action:     auditlog.ActionTenantProvisioned,
			SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{
				"slug":          t.Slug,
				"pb_version":    t.RuntimeVersion,
				"subnet":        t.Subnet,
				"owner":         req.OwnerID,
				"runtime":       r.cfg.TenantRuntime,
				"disk_mib":      t.DiskMiB,
				"hardening_rev": rv.HardeningRev,
			},
		})
		return err
	})
	if err != nil {

		return store.Tenant{}, err
	}

	// From here on, failures leave a tenant row the reconciler will keep trying
	// to converge — which is the point. The caller is told, and the tick retries.
	if err := r.materialise(ctx, t, req.AppDir, false); err != nil {

		return t, err
	}
	return t, nil
}

// materialise creates the host-side state for a tenant that already has a row.
//
// Separate from Provision so the reconciler can re-run it: after a crash, or
// after a reboot took the loopback mounts away, everything here has to converge
// from wherever it stopped.
//
// `existing` is false only for Provision. An existing tenant's instance is
// recreated, and its owner seat is restored if missing rather than upserted.
func (r *Reconciler) materialise(ctx context.Context, t store.Tenant, appDir string, existing bool) error {

	lock, err := r.fs.Lock(t.ID)
	if err != nil {

		return err
	}
	defer lock.Release()

	if existing {

		// Restart acts on a row read before the lock; re-read it, and leave a
		// tenant an upgrade job owns alone (INV-6).
		if t, err = r.lockedTenant(ctx, t.ID); err != nil {

			return err
		}
	}

	if err := r.fs.EnsureTenantDirs(t.ID); err != nil {

		return err
	}
	if err := r.fs.CreateDataImage(t.ID, t.DiskMiB); err != nil {

		return err
	}
	if err := r.fs.EnsureMounted(t.ID); err != nil {

		return err
	}
	// After the mount, never before: chowning first would chown the underlying
	// directory rather than the ext4 root inode, and the container's first write
	// would fail with EACCES for no visible reason (design.md §4).
	if err := r.fs.ChownData(t.ID, r.userns); err != nil {

		return err
	}
	if err := r.fs.EnsureKeys(t.ID); err != nil {

		return err
	}

	sha := t.CurrentArtifact
	if sha == "" {

		if appDir == "" {

			sha, err = r.fs.EmptyArtifact()

		} else {

			sha, err = r.fs.StageArtifact(appDir)
		}
		if err != nil {

			return err
		}
		if err := r.db.Tx(ctx, func(tx bun.Tx) error {

			return store.SetCurrentArtifact(ctx, tx, t.ID, sha)
		}); err != nil {

			return err
		}
		t.CurrentArtifact = sha
	}
	if err := r.fs.SwapAppCurrent(t.ID, sha); err != nil {

		return err
	}

	alloc, err := netpolicy.Addresses(mustPrefix(t.Subnet))
	if err != nil {

		return err
	}
	if err := r.net.EnsureTenantNetwork(ctx, t.Slug, alloc); err != nil {

		return err
	}
	if _, err := r.net.EnsurePlatformRules(false); err != nil {

		return err
	}
	// Before the container starts, never after: a container that is up before
	// its policy is a window in which a hook has open egress (§8.3).
	//
	// The binding is derived, never assumed. A tenant being provisioned has no
	// grant and gets only the intra-network accept, but Materialise also runs on
	// restart, for a tenant that may already hold grants. Passing no binding
	// there shrinks the desired set to the intra-network accept, and the prune
	// then removes the tenant's egress-default-deny while leaving its proxy
	// accept in place.
	eg, _, err := r.egressBinding(ctx, t)
	if err != nil {

		return err
	}
	known, err := r.grantIDsFor(ctx, t.ID)
	if err != nil {

		return err
	}
	in, err := netpolicy.ParseIngress(t.EdgeIP, t.ContainerIP)
	if err != nil {

		return err
	}
	ruleChanges, err := r.net.EnsureTenantRules(t.ID, t.Slug, in, eg, known, true)
	if err != nil {

		return err
	}
	r.recordRuleChanges(ctx, t.ID, ruleChanges)

	// The owner seat is written by a throwaway CLI container, never an exec
	// into a live one, and never with a second process on pb_data (INV-3). So
	// the running container goes first, as in a deploy (swapAndStart). On a
	// fresh provision there is none and both calls are no-ops.
	//
	// The restart path once skipped this, and ran the seat upsert against the
	// live instance's pb_data: under runsc the running server never saw the
	// write, tokens minted from disk were refused with a 401, and the tenant
	// stayed unhealthy until it was recreated.
	spec, err := r.specFor(ctx, t)
	if err != nil {

		return err
	}
	handle := driver.Handle{TenantID: t.ID, Name: spec.Name}
	// Restart recreates the container on the desired digest; refuse if that
	// is not the one it last ran (INV-11). On a fresh provision there is
	// neither a container nor a recorded digest, and this passes.
	if _, err := r.guardedStatus(ctx, t, spec); err != nil {

		return err
	}
	if err := r.drv.Stop(ctx, handle); err != nil {

		return err
	}
	if err := r.drv.Destroy(ctx, handle); err != nil {

		return err
	}
	if existing {

		// Only re-create a seat the owner deleted. An upsert would overwrite a
		// password they may have set on it.
		r.restoreSeat(ctx, t, spec)

	} else if err := r.ensureSeat(ctx, t, t.RuntimeVersion, spec); err != nil {

		return err
	}

	if err := r.fs.WriteMeta(hostfs.Meta{
		TenantID:    t.ID,
		Slug:        t.Slug,
		Hostname:    t.Hostname,
		PBVersion:   t.RuntimeVersion,
		ImageDigest: t.ImageDigest,
		Network:     t.NetworkName,
		Bridge:      config.BridgeName(t.Slug),
		Subnet:      t.Subnet,
		ContainerIP: t.ContainerIP,
		Artifact:    sha,
	}); err != nil {

		return err
	}

	h, err := r.drv.Ensure(ctx, spec)
	if err != nil {

		return err
	}
	if err := r.recordStarted(ctx, t, h.ContainerID); err != nil {

		return err
	}
	// Idempotent, and asserted here as well as in the platform pass: an edge
	// that was recreated between ticks has lost every tenant network
	// attachment, and without one the route's upstream name does not resolve.
	if err := r.proxy.EnsureEdge(ctx); err != nil {

		return err
	}
	if err := r.proxy.EnsureAttachment(ctx, t.Slug, t.EdgeIP); err != nil {

		return err
	}
	if err := r.publishRoute(ctx, t); err != nil {

		return err
	}

	// Wait for the data plane, not just /api/health: the first boot runs the
	// tenant's own pb_migrations, and a version-mismatched binary would answer
	// /api/health while auth is broken.
	return r.waitReady(ctx, t)
}

// Materialise re-runs host-side provisioning for an existing tenant and recreates
// its instance. Used by the API and portal restart paths.
func (r *Reconciler) Materialise(ctx context.Context, t store.Tenant) error {

	return r.materialise(ctx, t, "", true)
}

// identityService is built lazily so Options stays small; identity.Service is
// stateless over the read pool.
func (r *Reconciler) identityService() *identity.Service {

	return identity.New(r.db.Reader(), r.audit)
}

func containerNameFor(t store.Tenant) string { return config.ContainerName(t.Slug) }

func mustPrefix(s string) netip.Prefix {

	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {

		// A malformed subnet in the database means the firewall rules and the
		// reality have already diverged; there is no safe default to pick.
		panic("reconcile: tenant subnet " + s + " is not a prefix: " + err.Error())
	}
	return p
}

func orFloat(v, def float64) float64 {

	if v <= 0 {

		return def
	}
	return v
}

func orInt(v, def int) int {

	if v <= 0 {

		return def
	}
	return v
}

func orStr(v, def string) string {

	if v == "" {

		return def
	}
	return v
}
