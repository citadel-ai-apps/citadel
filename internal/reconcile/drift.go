package reconcile

import (
	"fmt"
	"sync"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
)

// Drift kinds. The asymmetry between the last two is the whole point (§14.5):
// a missing rule is a reliability problem, an extra one is either a platform bug
// or someone operating outside the control plane.
const (
	// DriftDigest is running image digest != desired digest. Never acted on
	//: acting would trigger an unbacked-up one-way migration.
	DriftDigest = "digest"
	// DriftMissingRule is a netpolicy rule that was absent and got repaired.
	DriftMissingRule = "missing_rule"
	// DriftUnbackedRule is a tagged rule with no matching tenant, or one whose
	// grant id is not in that tenant's active set. Never repaired, never
	// deleted — removing it destroys the evidence.
	DriftUnbackedRule = "unbacked_rule"
	// DriftUnbackedEgress is traffic on the egress network from an address no
	// tenant holds. Same class of signal as an unbacked rule.
	DriftUnbackedEgress = "unbacked_egress"
	// DriftEgressACL is a proxy whose generated allowlist could not be rendered,
	// written or reloaded. Approved access is then not in effect — a functional
	// bug, repaired on the next tick (§14.5, grant_without_enforcement).
	DriftEgressACL = "egress_acl"
	// DriftEgressACLTampered is a proxy allowlist found edited outside the
	// control plane. It is regenerated from grants — a proxy cannot be left
	// admitting hosts nobody approved — but the finding is kept, because an
	// entry with no grant behind it is enforcement_without_grant (§14.5).
	DriftEgressACLTampered = "egress_acl_tampered"
	// DriftRateLimit is an edge that accepted a route without its per-tenant
	// rate limits, because the running image has no rate_limit handler. A
	// missing control must be visible, not silent.
	DriftRateLimit = "rate_limit"
	// DriftRuleOrder is a DOCKER-USER chain whose rules are all present but in
	// an order that does not work (design.md §9.5).
	DriftRuleOrder = "rule_order"
	// DriftOrphanDir is a tenant directory on disk with no tenant row. Reported,
	// never deleted.
	DriftOrphanDir = "orphan_dir"
	// DriftMissingRoute is an edge route or network attachment that was absent.
	DriftMissingRoute = "missing_route"
	// DriftBackupFailed is a routine backup or a retention sweep that did not
	// complete. §15 alerts on it because nothing else about the tenant changes
	// when its backups stop: the failure is silent by construction.
	DriftBackupFailed = "backup_failed"
	// DriftUpgradeRollback is an upgrade that failed verification and restored
	// its snapshot. The tenant is back up and serving, so this is not an
	// outage — it is the signal that an upgrade the tenant asked for did not
	// work, and §15 alerts on it.
	DriftUpgradeRollback = "upgrade_rollback"
	// DriftRehearsalResidue is a rehearsal container, network, rule or mount
	// that outlived its job. Reported rather than silently retried, because a
	// rehearsal that cannot tear itself down is how subnets and loop devices
	// leak until provisioning stops working.
	DriftRehearsalResidue = "rehearsal_residue"
	// DriftUpgradeStuck is a job the reaper failed because the control plane
	// restarted mid-flight, where the tenant's digest and the running digest
	// then disagreed. Resuming a one-way migration from an unknown point is a
	// human's decision (INV-4).
	DriftUpgradeStuck = "upgrade_stuck"
	// DriftOwnerless is a tenant with other than exactly one active owner
	// (INV-17). Never repaired automatically: who should own it is a human
	// decision.
	DriftOwnerless = "ownerless"
	// DriftUnbackedACL is an allowlist block in the RUNNING proxy for a tenant
	// the control plane does not know, or one with no active egress grant.
	DriftUnbackedACL = "unbacked_acl"
	// DriftPosture is a tenant container found with settings no tenant
	// container may have (INV-12, INV-15). Repaired by recreating it, and
	// reported as security drift because nothing the platform does produces it.
	DriftPosture = "posture"
)

// Drift is one divergence between intent and the host.
type Drift struct {
	Kind       string    `json:"kind"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Detail     string    `json:"detail"`
	Repaired   bool      `json:"repaired"`
	Security   bool      `json:"security"`
	DetectedAt time.Time `json:"detected_at"`
}

// DriftBoard is the current set of drift, served at GET /admin/fleet.
//
// Drift is a reported state rather than an error return. A manual image_digest
// edit must produce a drift ALERT, not a restart — so it has to be visible
// somewhere, not merely not-acted-on.
type DriftBoard struct {
	mu      sync.Mutex
	entries map[string]Drift
}

func newDriftBoard() *DriftBoard {

	return &DriftBoard{entries: map[string]Drift{}}
}

func driftKey(kind, tenantID, detail string) string {

	return kind + "|" + tenantID + "|" + detail
}

// Record adds or refreshes a drift entry.
func (b *DriftBoard) Record(d Drift) {

	b.mu.Lock()
	defer b.mu.Unlock()
	if d.DetectedAt.IsZero() {

		d.DetectedAt = time.Now().UTC()
	}
	key := driftKey(d.Kind, d.TenantID, d.Detail)
	if prev, ok := b.entries[key]; ok {

		// Keep the original detection time: "this has been wrong since 03:14"
		// is the useful fact, not "it was still wrong five seconds ago".
		d.DetectedAt = prev.DetectedAt
	}
	b.entries[key] = d
}

// Clear removes every entry of a kind for a tenant, called when the tick finds
// that kind resolved.
func (b *DriftBoard) Clear(kind, tenantID string) {

	b.mu.Lock()
	defer b.mu.Unlock()
	for k, d := range b.entries {

		if d.Kind == kind && d.TenantID == tenantID {

			delete(b.entries, k)
		}
	}
}

// ClearTenant removes every entry for a tenant, called on destroy.
func (b *DriftBoard) ClearTenant(tenantID string) {

	b.mu.Lock()
	defer b.mu.Unlock()
	for k, d := range b.entries {

		if d.TenantID == tenantID {

			delete(b.entries, k)
		}
	}
}

// List returns the current drift, security items first.
func (b *DriftBoard) List() []Drift {

	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Drift, 0, len(b.entries))
	for _, d := range b.entries {

		out = append(out, d)
	}
	// enforcement_without_grant first (§15): these page, and they are not
	// auto-remediated.
	for i := 1; i < len(out); i++ {

		for j := i; j > 0 && lessDrift(out[j], out[j-1]); j-- {

			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func lessDrift(a, b Drift) bool {

	if a.Security != b.Security {

		return a.Security
	}
	return a.DetectedAt.Before(b.DetectedAt)
}

// unbackedRuleDetail renders an unbacked rule for the drift board and the audit
// subject ref, without the full listing (which is not a stable reference).
func unbackedRuleDetail(o netpolicy.Observed) string {

	return fmt.Sprintf("%s rule for unknown tenant %q: %s", o.Chain, o.Fields["tenant"], o.Comment)
}
