// Package grantpolicy classifies a request for a capability that crosses the
// sandbox boundary into one of the four tiers in design §14.3.
//
// Classification is a pure function of (kind, subject, tenant history, policy
// version), which is what makes it unit-testable and what lets every decision
// record the ruleset that made it. Nothing here writes a row or touches a host:
// it says which tier a request falls in, and the caller writes the access_grant
// row — the manifest is a request, the grant is the decision.
//
// Implemented today: the slice the deploy path needs — egress_host, plus the
// tier every other kind lands in so the portal can name them. Per-kind rules
// and an approval queue come later; a later ruleset bumps PolicyVersion rather
// than editing gp-1 in place, so an old decision stays explicable.
package grantpolicy

import (
	"fmt"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// PolicyVersion is recorded on every decision this ruleset makes.
const PolicyVersion = "gp-1"

// Tiers (design §14.3).
const (
	TierDenied     = 0 // never grantable; rejects the release
	TierAuto       = 1 // auto-granted and recorded, decided by the platform principal
	TierHuman      = 2 // named human approver, with a justification and an expiry
	TierBreakGlass = 3 // self-approved, time-boxed, loud
)

// Request is one capability a tenant (or an operator) is asking for.
type Request struct {
	Kind    string
	Subject string
}

// TenantContext is the platform state a classification depends on.
type TenantContext struct {
	// PlatformDomains are never allowlistable.
	PlatformDomains []string

	// PreviouslyRefused reports that this tenant has had this exact subject
	// denied or revoked before. §14.7: re-requesting is allowed, auto-granting
	// is not, regardless of tier — otherwise "revoke, then roll back" silently
	// undoes the revocation, because the restored release re-declares the host
	// in its manifest and it re-enters the pipeline as a fresh request.
	PreviouslyRefused bool
}

// Decision is the outcome, with the reason the tenant is shown verbatim.
type Decision struct {
	Tier          int
	Reason        string
	PolicyVersion string
	TTL           time.Duration
}

// Direction reports whether a kind lets the tenant reach out or lets the
// outside reach the tenant's data (§14.2).
func Direction(kind string) string {

	switch kind {

	case store.GrantOperatorDataAccess, store.GrantBackupExport,
		store.GrantLogAccess, store.GrantSupportImpersonate:
		return store.DirectionInbound
	default:
		return store.DirectionOutbound
	}
}

// DefaultTTL is the §14.2 expiry table. Every grant expires: not as hygiene,
// as the mechanism.
func DefaultTTL(kind string) time.Duration {

	const day = 24 * time.Hour
	switch kind {

	case store.GrantEgressHost, store.GrantOAuthProvider:
		return 365 * day
	case store.GrantSMTPRelay, store.GrantObjectStorage, store.GrantCustomDomain:
		return 180 * day
	case store.GrantLogAccess, store.GrantBackupExport:
		return 7 * day
	case store.GrantOperatorDataAccess, store.GrantSupportImpersonate:
		return 60 * time.Minute
	default:
		return 30 * day
	}
}

// Classify places a request in its tier.
func Classify(req Request, tc TenantContext) Decision {

	d := Decision{PolicyVersion: PolicyVersion, TTL: DefaultTTL(req.Kind)}

	switch req.Kind {

	case store.GrantEgressHost:
		return classifyEgress(req.Subject, tc, d)

	case store.GrantSMTPRelay, store.GrantObjectStorage, store.GrantCustomDomain,
		store.GrantOAuthProvider, store.GrantBackupExport, store.GrantLogAccess:
		d.Tier = TierHuman
		d.Reason = fmt.Sprintf("%s always needs a named approver (Tier 2)", req.Kind)
		return d

	case store.GrantOperatorDataAccess, store.GrantSupportImpersonate:
		// Break-glass. The platform does not pretend to prevent this (D15); it
		// makes it loud, time-boxed and visible to the tenant at grant time.
		d.Tier = TierBreakGlass
		d.Reason = fmt.Sprintf("%s is break-glass: time-boxed, reason mandatory, shown to the tenant (Tier 3)", req.Kind)
		return d

	default:
		d.Tier = TierDenied
		d.Reason = fmt.Sprintf("%q is not a capability this platform grants", req.Kind)
		return d
	}
}

func classifyEgress(host string, tc TenantContext, d Decision) Decision {

	if err := pkgvalidate.ValidateEgressHost(host, pkgvalidate.HostPolicy{PlatformDomains: tc.PlatformDomains}); err != nil {

		d.Tier = TierDenied
		d.Reason = err.Error()
		return d
	}
	if tc.PreviouslyRefused {

		d.Tier = TierHuman
		d.Reason = fmt.Sprintf("%s was denied or revoked for this tenant before; re-granting it needs a human", host)
		return d
	}
	if pkgvalidate.IsWildcard(host) {

		d.Tier = TierHuman
		d.Reason = fmt.Sprintf("%s is a wildcard: the set of destinations is unbounded, so it needs a named approver (Tier 2)", host)
		return d
	}
	d.Tier = TierAuto
	d.Reason = fmt.Sprintf("%s is a concrete host outside the denied ranges, so it is granted automatically and recorded (Tier 1)", host)
	return d
}

// DecisionFor maps a tier onto the access_grant decision it is written with.
// Tier 0 has none: it rejects the release rather than recording a denial the
// tenant did not ask a human for.
func DecisionFor(tier int) string {

	switch tier {

	case TierAuto:
		return store.DecisionAutoApproved
	default:
		return store.DecisionPending
	}
}
