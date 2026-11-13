package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// DefaultOfferTTL is how long an unaccepted transfer offer stands (§14.1: an
// unaccepted offer expires).
const DefaultOfferTTL = 7 * 24 * time.Hour

// Transfer errors callers branch on.
var (
	ErrTransferExpired  = errors.New("identity: the transfer offer has expired")
	ErrNotTransferee    = errors.New("identity: only the offered principal can answer a transfer")
	ErrSelfTransfer     = errors.New("identity: the tenant is already owned by that principal")
	ErrReasonRequired   = errors.New("identity: an operator-forced transfer requires a reason")
	ErrTransferConflict = errors.New("identity: this tenant already has an open transfer offer")
)

// OfferTransfer records an offer of ownership. It changes nothing about who
// owns the tenant.
//
// Transfer is two-party (§14.1): the current owner offers, the target accepts,
// both sides are on the record. A tenant is never pushed onto someone who did
// not agree to be accountable for it — which is also why an operator-forced
// transfer needs a reason, and that reason appears in the tenant's own feed.
func (s *Service) OfferTransfer(ctx context.Context, tx bun.Tx, actor Actor, tenantID, toPrincipal, reason string) (store.OwnerTransfer, error) {

	owner, err := s.CurrentOwner(ctx, tenantID)
	if err != nil {

		return store.OwnerTransfer{}, err
	}
	if toPrincipal == owner {

		return store.OwnerTransfer{}, fmt.Errorf("%w: %s", ErrSelfTransfer, owner)
	}
	target, err := s.Get(ctx, toPrincipal)
	if err != nil {

		return store.OwnerTransfer{}, err
	}
	if target.Status != StatusActive {

		return store.OwnerTransfer{}, fmt.Errorf("identity: %s is %s and cannot take ownership", toPrincipal, target.Status)
	}
	// An operator may reassign a tenant they do not own — the departed-owner
	// case — but not quietly.
	if actor.ID != owner && reason == "" {

		return store.OwnerTransfer{}, ErrReasonRequired
	}
	if existing, err := store.OpenTransfer(ctx, s.db, tenantID); err == nil {

		return store.OwnerTransfer{}, fmt.Errorf("%w: %s is offered to %s", ErrTransferConflict, existing.ID, existing.ToPrincipal)
	}

	now := time.Now().UTC()
	tr := store.OwnerTransfer{
		ID:            store.NewID("tr"),
		TenantID:      tenantID,
		FromPrincipal: owner,
		ToPrincipal:   toPrincipal,
		OfferedBy:     actor.ID,
		OfferedAt:     now,
		ExpiresAt:     now.Add(DefaultOfferTTL),
		Reason:        reason,
	}
	if err := store.InsertTransfer(ctx, tx, tr); err != nil {

		return store.OwnerTransfer{}, err
	}
	if _, err := s.audit.Append(ctx, tx, auditlog.Event{
		ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenantID,
		Action:     auditlog.ActionTransferOffered,
		SubjectRef: "transfer/" + tr.ID,
		Detail: map[string]any{
			"from": owner, "to": toPrincipal, "forced": actor.ID != owner,
			"expires_at": tr.ExpiresAt.Format(time.RFC3339),
		},
	}); err != nil {

		return store.OwnerTransfer{}, err
	}
	return tr, nil
}

// AcceptTransfer moves ownership to the offered principal.
//
// Only that principal can call it, which is the half of the two-party rule that
// makes the offer meaningful. The revoke and the grant are in one transaction
// with the audit event, so there is no instant where the tenant has two owners
// or none.
func (s *Service) AcceptTransfer(ctx context.Context, tx bun.Tx, actor Actor, tenantID string) (store.OwnerTransfer, error) {

	// Inside tx: the offer must still be open when the seat moves.
	tr, err := store.OpenTransfer(ctx, tx, tenantID)
	if err != nil {

		return store.OwnerTransfer{}, err
	}
	if actor.ID != tr.ToPrincipal {

		return store.OwnerTransfer{}, fmt.Errorf("%w: %s is offered to %s", ErrNotTransferee, tr.ID, tr.ToPrincipal)
	}
	if !tr.Open(time.Now().UTC()) {

		return store.OwnerTransfer{}, fmt.Errorf("%w: %s lapsed on %s", ErrTransferExpired, tr.ID, tr.ExpiresAt.Format(time.RFC3339))
	}

	if _, err := s.replaceOwner(ctx, tx, actor, tenantID, tr.ToPrincipal); err != nil {

		return store.OwnerTransfer{}, err
	}
	// A tenant with a real owner again is no longer a backlog item (§14.1).
	if _, err := tx.NewUpdate().Table("tenant").
		Set("owner_orphaned = 0").Where("id = ?", tenantID).Exec(ctx); err != nil {

		return store.OwnerTransfer{}, err
	}
	if err := store.CloseTransfer(ctx, tx, tr.ID, store.TransferAccepted); err != nil {

		return store.OwnerTransfer{}, err
	}
	if _, err := s.audit.Append(ctx, tx, auditlog.Event{
		ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenantID,
		Action:     auditlog.ActionOwnerTransferred,
		SubjectRef: "transfer/" + tr.ID,
		Detail:     map[string]any{"from": tr.FromPrincipal, "to": tr.ToPrincipal, "offered_by": tr.OfferedBy},
	}); err != nil {

		return store.OwnerTransfer{}, err
	}
	now := time.Now().UTC()
	tr.AcceptedAt = &now
	return tr, nil
}

// CloseTransfer declines or cancels an open offer.
//
// The offered principal declines; the offering side (or an operator) cancels.
// Both outcomes are recorded: an offer that was refused is part of the
// ownership story.
func (s *Service) CloseTransfer(ctx context.Context, tx bun.Tx, actor Actor, tenantID, outcome string) error {

	tr, err := store.OpenTransfer(ctx, s.db, tenantID)
	if err != nil {

		return err
	}
	action := auditlog.ActionTransferCancelled
	if outcome == store.TransferDeclined {

		if actor.ID != tr.ToPrincipal {

			return fmt.Errorf("%w: %s is offered to %s", ErrNotTransferee, tr.ID, tr.ToPrincipal)
		}
		action = auditlog.ActionTransferDeclined
	}
	if err := store.CloseTransfer(ctx, tx, tr.ID, outcome); err != nil {

		return err
	}
	_, err = s.audit.Append(ctx, tx, auditlog.Event{
		ActorID: actor.ID, ActorKind: actor.Kind, TenantID: tenantID,
		Action:     action,
		SubjectRef: "transfer/" + tr.ID,
		Detail:     map[string]any{"from": tr.FromPrincipal, "to": tr.ToPrincipal},
	})
	return err
}

// PendingTransfer returns the tenant's open offer, if any.
func (s *Service) PendingTransfer(ctx context.Context, tenantID string) (store.OwnerTransfer, bool, error) {

	tr, err := store.OpenTransfer(ctx, s.db, tenantID)
	if errors.Is(err, store.ErrTransferNotFound) {

		return store.OwnerTransfer{}, false, nil
	}
	if err != nil {

		return store.OwnerTransfer{}, false, err
	}
	return tr, true, nil
}

// Transfers returns a tenant's transfer history.
func (s *Service) Transfers(ctx context.Context, tenantID string) ([]store.OwnerTransfer, error) {

	return store.ListTransfers(ctx, s.db, tenantID)
}
