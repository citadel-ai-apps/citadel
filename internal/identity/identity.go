// Package identity owns principals and ownership history (design §14.1).
//
// Ownership is a history table plus the current_owner view, never a column on
// tenant: "who owned this in March" must be a query, not an archaeology
// expedition through the audit log. Exactly one active owner per tenant is
// enforced by a partial unique index in migration 001 — SQL is the only place
// the one-owner rule cannot be forgotten.
package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Principal kinds.
const (
	KindPerson         = "person"
	KindServiceAccount = "service_account"
	KindPlatform       = "platform"
)

// Roles, in the order of §14.1's permission table.
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleDeployer = "deployer"
	RoleViewer   = "viewer"
)

// PlatformPrincipal is the platform's own principal id, seeded by migration 001.
const PlatformPrincipal = auditlog.PlatformPrincipal

// Principal statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted"
)

// Principal is anything that can act.
//
// The bun table name is pinned: this schema is singular (migration 001) and bun
// would otherwise look for "principals".
type Principal struct {
	bun.BaseModel `bun:"table:principal,alias:principal" json:"-"`

	ID          string `bun:"id,pk" json:"id"`
	Kind        string `bun:"kind" json:"kind"`
	ExternalID  string `bun:"external_id,nullzero" json:"external_id,omitempty"`
	Email       string `bun:"email,nullzero" json:"email,omitempty"`
	DisplayName string `bun:"display_name" json:"display_name"`
	Status      string `bun:"status" json:"status"`
	// Operator (migration 009): a person who may open, close and review
	// break-glass and sees the portal's operator pages. Persons only.
	Operator  bool      `bun:"operator" json:"operator,omitempty"`
	CreatedAt time.Time `bun:"created_at" json:"created_at"`
}

// OwnerRow is one row of a tenant's ownership history.
type OwnerRow struct {
	bun.BaseModel `bun:"table:tenant_owner,alias:tenant_owner" json:"-"`

	ID          string     `bun:"id,pk" json:"id"`
	TenantID    string     `bun:"tenant_id" json:"tenant_id"`
	PrincipalID string     `bun:"principal_id" json:"principal_id"`
	Role        string     `bun:"role" json:"role"`
	GrantedBy   string     `bun:"granted_by" json:"granted_by"`
	GrantedAt   time.Time  `bun:"granted_at" json:"granted_at"`
	RevokedBy   string     `bun:"revoked_by,nullzero" json:"revoked_by,omitempty"`
	RevokedAt   *time.Time `bun:"revoked_at,nullzero" json:"revoked_at,omitempty"`
}

// currentOwner reads the current_owner view (migration 001), which is the one
// place "who owns this tenant right now" is defined.
type currentOwner struct {
	bun.BaseModel `bun:"table:current_owner,alias:current_owner"`

	TenantID    string `bun:"tenant_id"`
	PrincipalID string `bun:"principal_id"`
}

// Errors callers are expected to branch on.
var (
	ErrNotFound    = errors.New("identity: principal not found")
	ErrOwnsTenants = errors.New("identity: principal still owns tenants")
	ErrBadID       = errors.New("identity: malformed principal id")
)

// Service reads and writes principals and ownership.
type Service struct {
	db    *bun.DB
	audit *auditlog.Logger
}

// New returns a Service reading through db (the read pool is fine; writes take
// an explicit bun.Tx).
func New(db *bun.DB, audit *auditlog.Logger) *Service {

	return &Service{db: db, audit: audit}
}

// idPattern constrains the local part of a principal id. It ends up in audit
// rows, iptables comments and log lines, so it stays boring on purpose.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ParseID splits "person:alice" into its kind and local name, defaulting the
// kind to person when the prefix is absent. The bare platform id is the one
// exception: it is stored unprefixed, so reading it as "person:platform" would
// name a principal that does not exist.
func ParseID(id string) (kind, name string, err error) {

	if id == PlatformPrincipal {

		return KindPlatform, id, nil
	}
	kind, name = KindPerson, id
	if k, n, ok := strings.Cut(id, ":"); ok {

		kind, name = k, n
	}
	switch kind {

	case KindPerson, KindServiceAccount, KindPlatform:
	case "svc":
		kind = KindServiceAccount
	default:
		return "", "", fmt.Errorf("%w: %q has unknown kind %q", ErrBadID, id, kind)
	}
	if kind == KindPlatform && name != PlatformPrincipal {

		return "", "", fmt.Errorf("%w: %q: the platform kind has one principal, %q", ErrBadID, id, PlatformPrincipal)
	}
	if !idPattern.MatchString(name) {

		return "", "", fmt.Errorf("%w: %q must be [a-z0-9][a-z0-9._-]* and at most 63 chars", ErrBadID, name)
	}
	return kind, name, nil
}

// CanonicalID renders a principal id in its stored form.
func CanonicalID(kind, name string) string {

	if kind == KindPlatform {

		return PlatformPrincipal
	}
	return kind + ":" + name
}

// Canonical parses a user-supplied principal id ("alice", "svc:ci",
// "platform") into its stored form.
func Canonical(id string) (string, error) {

	kind, name, err := ParseID(id)
	if err != nil {

		return "", err
	}
	return CanonicalID(kind, name), nil
}

// Get returns one principal.
func (s *Service) Get(ctx context.Context, id string) (Principal, error) {

	var p Principal
	err := s.db.NewSelect().Model(&p).Where("id = ?", id).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return Principal{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {

		return Principal{}, err
	}
	return p, nil
}

// List returns every principal, oldest first.
func (s *Service) List(ctx context.Context) ([]Principal, error) {

	var out []Principal
	err := s.db.NewSelect().Model(&out).Order("created_at ASC", "id ASC").Scan(ctx)
	return out, err
}

// CreateOptions describes a new principal.
type CreateOptions struct {
	ID          string // "person:alice"; kind defaults to person
	DisplayName string
	Email       string
	ExternalID  string
}

// Create inserts a principal and its audit event in tx.
func (s *Service) Create(ctx context.Context, tx bun.Tx, actor Actor, opt CreateOptions) (Principal, error) {

	kind, name, err := ParseID(opt.ID)
	if err != nil {

		return Principal{}, err
	}
	if kind == KindPlatform {

		return Principal{}, errors.New("identity: the platform principal is seeded by migration 001 and cannot be created")
	}
	id := CanonicalID(kind, name)
	display := opt.DisplayName
	if display == "" {

		display = name
	}
	now := time.Now().UTC()

	p := Principal{
		ID: id, Kind: kind, ExternalID: opt.ExternalID, Email: opt.Email,
		DisplayName: display, Status: StatusActive, CreatedAt: now,
	}
	if _, err := tx.NewInsert().Model(&p).Exec(ctx); err != nil {

		return Principal{}, fmt.Errorf("identity: create %s: %w", id, err)
	}
	if _, err := s.audit.Append(ctx, tx, auditlog.Event{
		ActorID:    actor.ID,
		ActorKind:  actor.Kind,
		Action:     auditlog.ActionPrincipalCreated,
		SubjectRef: "principal/" + id,
		Detail:     map[string]any{"kind": kind},
	}); err != nil {

		return Principal{}, err
	}
	return p, nil
}

// GrantRole records a role for a principal on a tenant.
//
// It does not enforce one-owner-per-tenant by itself; the partial unique index
// does. The caller gets a constraint error if a second active owner is
// attempted, which is the point: the rule holds even for code paths nobody
// thought about.
func (s *Service) GrantRole(ctx context.Context, tx bun.Tx, actor Actor, tenantID, principalID, role string) error {

	switch role {

	case RoleOwner, RoleAdmin, RoleDeployer, RoleViewer:
	default:
		return fmt.Errorf("identity: unknown role %q", role)
	}
	row := OwnerRow{
		ID: newRowID(), TenantID: tenantID, PrincipalID: principalID,
		Role: role, GrantedBy: actor.ID, GrantedAt: time.Now().UTC(),
	}
	if _, err := tx.NewInsert().Model(&row).Exec(ctx); err != nil {

		return fmt.Errorf("identity: grant %s on %s to %s: %w", role, tenantID, principalID, err)
	}
	_, err := s.audit.Append(ctx, tx, auditlog.Event{
		ActorID:    actor.ID,
		ActorKind:  actor.Kind,
		TenantID:   tenantID,
		Action:     auditlog.ActionOwnerGranted,
		SubjectRef: "principal/" + principalID,
		Detail:     map[string]any{"role": role},
	})
	return err
}

// CurrentOwner returns the tenant's single active owner.
func (s *Service) CurrentOwner(ctx context.Context, tenantID string) (string, error) {

	var id string
	err := s.db.NewSelect().Model((*currentOwner)(nil)).
		Column("principal_id").Where("tenant_id = ?", tenantID).Scan(ctx, &id)
	if errors.Is(err, sql.ErrNoRows) {

		// Every tenant always has an owner, so this is never legitimately reachable.
		return "", fmt.Errorf("identity: tenant %s has no active owner, which must never happen", tenantID)
	}
	return id, err
}

// History returns every role row for a tenant, oldest grant first.
func (s *Service) History(ctx context.Context, tenantID string) ([]OwnerRow, error) {

	var out []OwnerRow
	err := s.db.NewSelect().Model(&out).
		Where("tenant_id = ?", tenantID).
		Order("granted_at ASC", "id ASC").
		Scan(ctx)
	return out, err
}

// OwnedTenants lists the tenants a principal currently owns.
func (s *Service) OwnedTenants(ctx context.Context, principalID string) ([]string, error) {

	return ownedTenants(ctx, s.db, principalID)
}

func ownedTenants(ctx context.Context, db bun.IDB, principalID string) ([]string, error) {

	var out []string
	err := db.NewSelect().Model((*currentOwner)(nil)).
		Column("tenant_id").Where("principal_id = ?", principalID).
		Order("tenant_id").Scan(ctx, &out)
	return out, err
}

// ErrOwnerInvariant is a tenant found with other than exactly one active owner
// (INV-17). Never legitimately reachable; the transaction is rolled back.
var ErrOwnerInvariant = errors.New("identity: a tenant must have exactly one active owner (INV-17)")

// replaceOwner moves a tenant's owner seat to principalID inside tx.
//
// The only way an owner is ever revoked. SQL enforces "at most one" with the
// partial unique index; "at least one" cannot be a SQLite constraint, because
// the old row has to be revoked before the new one may be inserted and SQLite
// has no deferred checks. So it is enforced here, at the single choke point:
// the successor must be active, exactly one owner must be replaced, and
// exactly one must remain — checked inside the same transaction, so a
// violation rolls everything back rather than committing an orphan.
func (s *Service) replaceOwner(ctx context.Context, tx bun.Tx, actor Actor, tenantID, principalID string) (string, error) {

	var current []string
	if err := tx.NewSelect().Model((*currentOwner)(nil)).
		Column("principal_id").Where("tenant_id = ?", tenantID).Scan(ctx, &current); err != nil {

		return "", err
	}
	if len(current) != 1 {

		return "", fmt.Errorf("%w: %s has %d before the change", ErrOwnerInvariant, tenantID, len(current))
	}
	var status string
	err := tx.NewSelect().Model((*Principal)(nil)).Column("status").
		Where("id = ?", principalID).Scan(ctx, &status)
	if errors.Is(err, sql.ErrNoRows) {

		return "", fmt.Errorf("%w: %s", ErrNotFound, principalID)
	}
	if err != nil {

		return "", err
	}
	if status != StatusActive {

		return "", fmt.Errorf("%w: principal %s is %s and cannot own a tenant", ErrInactive, principalID, status)
	}

	if _, err := tx.NewUpdate().Model((*OwnerRow)(nil)).
		Set("revoked_by = ?", actor.ID).
		Set("revoked_at = ?", time.Now().UTC()).
		Where("tenant_id = ? AND role = 'owner' AND revoked_at IS NULL", tenantID).
		Exec(ctx); err != nil {

		return "", err
	}
	if _, err := s.audit.Append(ctx, tx, auditlog.Event{
		ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenantID,
		Action:     auditlog.ActionOwnerRevoked,
		SubjectRef: "principal/" + current[0],
		Detail:     map[string]any{"role": RoleOwner, "successor": principalID},
	}); err != nil {

		return "", err
	}
	if err := s.GrantRole(ctx, tx, actor, tenantID, principalID, RoleOwner); err != nil {

		return "", err
	}
	n, err := tx.NewSelect().Model((*currentOwner)(nil)).Where("tenant_id = ?", tenantID).Count(ctx)
	if err != nil {

		return "", err
	}
	if n != 1 {

		return "", fmt.Errorf("%w: %s has %d after the change", ErrOwnerInvariant, tenantID, n)
	}
	return current[0], nil
}

// Suspend marks a principal inactive.
//
// It refuses while the principal owns any tenant unless reassignToPlatform is
// set, in which case custody passes to the platform principal and each tenant
// is flagged owner_orphaned — a visible backlog item rather than a NULL nobody
// notices (§14.1). Every tenant keeps an owner either way.
func (s *Service) Suspend(ctx context.Context, tx bun.Tx, actor Actor, principalID string, reassignToPlatform bool) error {

	if principalID == PlatformPrincipal {

		return errors.New("identity: the platform principal cannot be suspended")
	}
	// Read inside tx, not from the read pool: an ownership transfer that
	// commits between a pool read and this write would hand a tenant to a
	// principal that is about to be suspended.
	owned, err := ownedTenants(ctx, tx, principalID)
	if err != nil {

		return err
	}
	if len(owned) > 0 && !reassignToPlatform {

		return fmt.Errorf("%w: %s owns %v; transfer them or pass --reassign-to-platform",
			ErrOwnsTenants, principalID, owned)
	}
	for _, tenantID := range owned {

		if _, err := s.replaceOwner(ctx, tx, actor, tenantID, PlatformPrincipal); err != nil {

			return err
		}
		if _, err := tx.NewUpdate().Table("tenant").
			Set("owner_orphaned = 1").Where("id = ?", tenantID).
			Exec(ctx); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID:    actor.ID,
			ActorKind:  actor.Kind,
			TenantID:   tenantID,
			Action:     auditlog.ActionOwnerOrphaned,
			SubjectRef: "principal/" + principalID,
			Detail:     map[string]any{"custody": PlatformPrincipal},
		}); err != nil {

			return err
		}
	}
	// Open offers to or from a suspended principal are cancelled: an offer TO
	// them would otherwise make them an owner the moment they are reinstated,
	// and an offer FROM them speaks for someone no longer accountable.
	var offers []store.OwnerTransfer
	if err := tx.NewSelect().Model(&offers).
		Where("from_principal = ? OR to_principal = ?", principalID, principalID).
		Where("accepted_at IS NULL AND declined_at IS NULL AND cancelled_at IS NULL").
		Scan(ctx); err != nil {

		return err
	}
	for _, o := range offers {

		if err := store.CloseTransfer(ctx, tx, o.ID, store.TransferCancelled); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: o.TenantID,
			Action:     auditlog.ActionTransferCancelled,
			SubjectRef: "transfer/" + o.ID,
			Detail:     map[string]any{"reason": "principal suspended", "principal": principalID},
		}); err != nil {

			return err
		}
	}
	if _, err := tx.NewUpdate().Model((*Principal)(nil)).
		Set("status = ?", StatusSuspended).Where("id = ?", principalID).
		Exec(ctx); err != nil {

		return err
	}
	_, err = s.audit.Append(ctx, tx, auditlog.Event{
		ActorID:    actor.ID,
		ActorKind:  actor.Kind,
		Action:     auditlog.ActionPrincipalSuspended,
		SubjectRef: "principal/" + principalID,
		Detail:     map[string]any{"orphaned_tenants": len(owned)},
	})
	return err
}

var ErrNotPerson = errors.New("identity: only a person can be an operator")

// SetOperator sets or clears a person's operator flag.
//
// The flag is what lets someone open break-glass, which is the one path to a
// tenant's data that needs no role on it, so every change is audited and the
// chain is its history. Clearing it ends any break-glass access the person
// holds on their next request: the portal re-reads it every time.
func (s *Service) SetOperator(ctx context.Context, tx bun.Tx, actor Actor, principalID string, on bool) error {

	var p Principal
	err := tx.NewSelect().Model(&p).Where("id = ?", principalID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return fmt.Errorf("%w: %s", ErrNotFound, principalID)
	}
	if err != nil {

		return err
	}
	if p.Kind != KindPerson {

		return fmt.Errorf("%w: %s is a %s", ErrNotPerson, p.ID, p.Kind)
	}
	if p.Status != StatusActive && on {

		return fmt.Errorf("%w: principal %s is %s", ErrInactive, p.ID, p.Status)
	}
	if _, err := tx.NewUpdate().Model((*Principal)(nil)).
		Set("operator = ?", on).Where("id = ?", p.ID).
		Exec(ctx); err != nil {

		return err
	}
	_, err = s.audit.Append(ctx, tx, auditlog.Event{
		ActorID: actor.ID, ActorKind: actor.Kind,
		Action:     auditlog.ActionPrincipalOperator,
		SubjectRef: "principal/" + p.ID,
		Detail:     map[string]any{"operator": on, "was": p.Operator},
	})
	return err
}

func newRowID() string {

	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {

		panic("identity: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
