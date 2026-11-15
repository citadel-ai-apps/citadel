package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// ErrForbidden is returned when a principal's role on a tenant does not carry
// the capability being asked for.
var ErrForbidden = errors.New("identity: role does not permit this")

// ErrInactive is returned when a principal exists but is suspended or deleted.
var ErrInactive = errors.New("identity: principal is not active")

// Capabilities, one per column of the §14.1 role table.
const (
	CapDeploy         = "deploy"
	CapRequestGrant   = "request_grant"
	CapDownloadBackup = "download_backup"
	CapTransfer       = "transfer_ownership"
	// CapInstanceAdmin opens the instance's own PocketBase admin UI (/_/) as
	// a superuser, through the portal handoff. Owner and admin: a superuser
	// can read, change and delete every record, which is no less than what
	// downloading a backup already gives an admin.
	CapInstanceAdmin = "instance_admin"
)

// roleRank orders the roles so the highest one a principal holds is the one
// that decides. A principal can hold several rows on one tenant; ownership is a
// history table, so "was granted deployer in March and owner in May" is normal.
var roleRank = map[string]int{
	RoleViewer: 1, RoleDeployer: 2, RoleAdmin: 3, RoleOwner: 4,
}

// Break-glass roles. Never stored: GrantRole refuses them, and Role and Require
// read only tenant_owner rows, so they cannot pass a check that goes to the
// database. The portal synthesises one for an operator holding an active
// break-glass grant on a tenant they have no role on (§14.3), and only its own
// role-from-session checks ever see it.
const (
	// RoleBreakglassData is operator_data_access on pb_data: the tenant's pages,
	// read-only, plus the PocketBase admin handoff, a read-write superuser
	// session whose token never outlives the session's 60-minute box.
	RoleBreakglassData = "break_glass"
	// RoleBreakglassView is support_impersonation, or operator_data_access on
	// any scope other than pb_data: the tenant's pages, read-only.
	RoleBreakglassView = "break_glass_view"
)

func IsBreakglassRole(role string) bool {

	return role == RoleBreakglassData || role == RoleBreakglassView
}

// capabilities is design §14.1's table, transcribed. A deployer may request
// grants of any tier, as a deploy's manifest already does; a Tier-2 request
// only becomes pending and still needs a named approver (§14.3). Re-affirming
// an inherited grant needs owner or admin (api.reaffirmGrant).
var capabilities = map[string]map[string]bool{
	RoleOwner:    {CapDeploy: true, CapRequestGrant: true, CapDownloadBackup: true, CapTransfer: true, CapInstanceAdmin: true},
	RoleAdmin:    {CapDeploy: true, CapRequestGrant: true, CapDownloadBackup: true, CapInstanceAdmin: true},
	RoleDeployer: {CapDeploy: true, CapRequestGrant: true},
	RoleViewer:   {},
	// Not in roleRank: a break-glass role is never compared against a stored
	// one, because a real role always wins.
	RoleBreakglassData: {CapInstanceAdmin: true},
	RoleBreakglassView: {},
}

// RoleAllows reports whether a role carries a capability.
func RoleAllows(role, capability string) bool {

	return capabilities[role][capability]
}

// Role returns the highest active role a principal holds on a tenant, or
// ErrForbidden when it holds none.
//
// The platform principal is not special-cased: when it has taken custody of an
// orphaned tenant it holds a real owner row like anyone else (§14.1).
func (s *Service) Role(ctx context.Context, tenantID, principalID string) (string, error) {

	var roles []string
	err := s.db.NewSelect().Model((*OwnerRow)(nil)).
		Column("role").
		Where("tenant_id = ?", tenantID).
		Where("principal_id = ?", principalID).
		Where("revoked_at IS NULL").
		Scan(ctx, &roles)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {

		return "", err
	}
	best := ""
	for _, r := range roles {

		if roleRank[r] > roleRank[best] {

			best = r
		}
	}
	if best == "" {

		// Neither id goes into the message: it reaches API callers, and the
		// tenant id is exactly what a caller with no role must not learn.
		return "", fmt.Errorf("%w: no role on this tenant", ErrForbidden)
	}
	return best, nil
}

// TenantRole pairs a tenant with the role a principal holds on it.
type TenantRole struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// TenantsFor lists every tenant a principal holds any active role on, highest
// role first. This is the portal's "your projects" query.
func (s *Service) TenantsFor(ctx context.Context, principalID string) ([]TenantRole, error) {

	var rows []OwnerRow
	err := s.db.NewSelect().Model(&rows).
		Where("principal_id = ?", principalID).
		Where("revoked_at IS NULL").
		Order("tenant_id").
		Scan(ctx)
	if err != nil {

		return nil, err
	}
	best := map[string]string{}
	for _, r := range rows {

		if roleRank[r.Role] > roleRank[best[r.TenantID]] {

			best[r.TenantID] = r.Role
		}
	}
	out := make([]TenantRole, 0, len(best))
	for id, role := range best {

		out = append(out, TenantRole{TenantID: id, Role: role})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

// Require checks a capability and returns the role that carried it.
func (s *Service) Require(ctx context.Context, tenantID, principalID, capability string) (string, error) {

	role, err := s.Role(ctx, tenantID, principalID)
	if err != nil {

		return "", err
	}
	if !RoleAllows(role, capability) {

		return "", fmt.Errorf("%w: %s is %s on %s, which cannot %s",
			ErrForbidden, principalID, role, tenantID, capability)
	}
	return role, nil
}
