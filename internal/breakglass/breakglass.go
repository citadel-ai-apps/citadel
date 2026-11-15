// Package breakglass is Tier-3 access (design §14.3): an operator needs a
// tenant's data now, mid-incident, and waiting for a second approver is not
// viable.
//
// The API (over the unix socket) and the portal (for a named operator) both go
// through here, so the terms cannot drift between the two doors:
//
//   - only a named person with the operator flag opens, holds, reviews or
//     closes a session — never the shared platform login (INV-16);
//   - a reason is mandatory and is shown to the tenant verbatim;
//   - the box is hard, 60 minutes, and not extendable — ask again;
//   - the tenant AND the other operators are told at grant time, in the same
//     transaction as the grant;
//   - a session still unreviewed 24h after it was opened blocks its opener from
//     opening another, and only someone else's review clears it. Inside those
//     24h nothing blocks: an operator may open further sessions while earlier
//     ones are unreviewed (store.OverdueBreakglassFor).
//
// What an open session grants is decided where it is used: the portal resolves
// a tenant the operator has no role on through store.ActiveBreakglassFor, and
// OpensAdmin says which sessions reach the PocketBase admin UI. Root
// on the host can read pb_data regardless; that path stays detect-and-attribute
// (D15), and this one is the door that needs no root.
package breakglass

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/grantpolicy"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Errors callers map onto status codes. The forbidden ones wrap
// identity.ErrForbidden, so existing mappings already answer 403.
var (
	// ErrInvalid is a malformed request: no reason, an unknown kind, a bad
	// review outcome.
	ErrInvalid       = errors.New("breakglass: invalid request")
	ErrNotBreakglass = errors.New("breakglass: not a break-glass grant")
	// ErrBlocked is the §14.3 block: this principal has sessions past their
	// 24h review window with no review.
	ErrBlocked  = errors.New("breakglass: unreviewed sessions block this principal")
	ErrReviewed = errors.New("breakglass: session already reviewed")
	ErrEnded    = errors.New("breakglass: session already ended")
	// ErrTenantRevoke refuses a tenant's revoke of a break-glass row. A
	// session a tenant member could end mid-incident would not be break-glass;
	// an operator ends it (Close), and the tenant's say is the notice at grant
	// time and the verdict at review.
	ErrTenantRevoke = fmt.Errorf("%w: break-glass access is ended by an operator, not revoked by the tenant; you were told when it opened and will see its review", identity.ErrForbidden)
	ErrNotOperator  = fmt.Errorf("%w: break-glass is for a named person with the operator flag (`citadel principal operator`)", identity.ErrForbidden)
)

const DefaultScope = "pb_data"

// OpensAdmin reports whether a session also opens the instance's PocketBase
// admin UI: operator_data_access on all of pb_data. That is a superuser
// session, which can change and delete records, not only read them, and the
// tenant is told so in those words. Every other session is the tenant's portal
// pages, read-only.
func OpensAdmin(g store.Grant) bool {

	return g.Kind == store.GrantOperatorDataAccess && g.Subject == DefaultScope
}

// Request is POST /admin/tenants/{id}/breakglass, and the portal's open form.
type Request struct {
	Reason string `json:"reason"`
	// Scope is recorded as the grant subject and shown to the tenant. Only
	// pb_data changes what a session can do (OpensAdmin). Any other value, such
	// as the id of a snapshot an operator is about to read as root on the host,
	// gives the read-only pages and puts that read on the record.
	Scope string `json:"scope,omitempty"`
	Kind  string `json:"kind,omitempty"`
}

type Service struct {
	db    *store.DB
	audit *auditlog.Logger
	now   func() time.Time
}

func New(db *store.DB, audit *auditlog.Logger) *Service {

	return &Service{db: db, audit: audit, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Open(ctx context.Context, actor identity.Actor, t store.Tenant, r Request) (store.Grant, error) {

	if !actor.CanBreakglass() {

		return store.Grant{}, ErrNotOperator
	}
	r.Reason = strings.TrimSpace(r.Reason)
	if r.Reason == "" {

		return store.Grant{}, fmt.Errorf("%w: break-glass needs a reason; it is shown to the tenant verbatim", ErrInvalid)
	}
	kind := r.Kind
	if kind == "" {

		kind = store.GrantOperatorDataAccess
	}
	if kind != store.GrantOperatorDataAccess && kind != store.GrantSupportImpersonate {

		return store.Grant{}, fmt.Errorf("%w: %s is not a break-glass kind; use %s or %s",
			ErrInvalid, kind, store.GrantOperatorDataAccess, store.GrantSupportImpersonate)
	}
	scope := strings.TrimSpace(r.Scope)
	if scope == "" {

		scope = DefaultScope
	}

	// The block: this principal's sessions opened more than ReviewWindow ago and
	// still unreviewed. A younger unreviewed session does not count. Cleared by
	// someone OTHER than the requester reviewing it, so it is not something the
	// operator can dismiss for themselves.
	now := s.now()
	outstanding, err := store.OverdueBreakglassFor(ctx, s.db.Reader(), actor.ID, now)
	if err != nil {

		return store.Grant{}, err
	}
	if len(outstanding) > 0 {

		ids := make([]string, 0, len(outstanding))
		for _, g := range outstanding {

			ids = append(ids, g.ID)
		}
		return store.Grant{}, fmt.Errorf("%w: %s has break-glass sessions past their 24h review (%s); another operator must review them first",
			ErrBlocked, actor.ID, strings.Join(ids, ", "))
	}

	g := store.Grant{
		ID:            store.NewID("g"),
		TenantID:      t.ID,
		Kind:          kind,
		Direction:     store.DirectionInbound,
		Subject:       scope,
		Tier:          grantpolicy.TierBreakGlass,
		Decision:      store.DecisionApproved,
		RequestedBy:   actor.ID,
		RequestedAt:   now,
		DecidedBy:     actor.ID, // self-approved, and the record says so
		DecidedAt:     &now,
		PolicyVersion: grantpolicy.PolicyVersion,
		Justification: r.Reason,
		// Hard box. Not derived from grantpolicy's default TTL, because that is
		// a policy knob and this one is not negotiable.
		ExpiresAt: now.Add(store.BreakglassTTL),
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertGrant(ctx, tx, g); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionBreakglassOpened,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"kind": g.Kind, "scope": g.Subject, "reason": g.Justification,
				"expires_at": g.ExpiresAt.Format(time.RFC3339),
			},
		}); err != nil {

			return err
		}
		// Both notices in this transaction, with the grant itself. An operator
		// opening a customer's database learns the customer is being told as it
		// happens — which is only true if the telling cannot fail separately
		// from the opening.
		what := "read-only access to your project's portal pages"
		if OpensAdmin(g) {

			what = "access to your pb_data, including a superuser session in your PocketBase admin " +
				"that can change and delete records,"
		}
		if err := store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassOpened, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s opened break-glass %s (scope %s) until %s. Reason given: %s",
				actor.ID, what, g.Subject, g.ExpiresAt.Format(time.RFC3339), g.Justification),
		}); err != nil {

			return err
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: t.ID, Audience: store.AudienceOperator,
			Kind: store.NotifyBreakglassOpened, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("%s opened break-glass on %s (%s); access is already open, until %s. "+
				"Review afterwards, within 24h, whether it was justified: %s",
				actor.ID, t.Slug, g.Subject, g.ExpiresAt.Format(time.RFC3339), g.Justification),
		})
	})
	if err != nil {

		return store.Grant{}, err
	}
	return g, nil
}

// Review records the verdict on a session: justified or unjustified, after the
// fact. It grants and withdraws nothing, and is due within ReviewWindow of the
// opening, after which the opener is blocked until it exists.
//
// Refused from the requester. A self-reviewed break-glass is not a review, and
// letting one clear the block would make the block decorative. Refused from
// anyone but a named operator: the verdict is the second operator's, and a
// tenant member reviewing the access to their own data would be neither.
func (s *Service) Review(ctx context.Context, actor identity.Actor, grantID, outcome, notes string) (store.Grant, error) {

	if !actor.CanBreakglass() {

		return store.Grant{}, ErrNotOperator
	}
	if outcome != store.ReviewJustified && outcome != store.ReviewUnjustified {

		return store.Grant{}, fmt.Errorf("%w: outcome must be %s or %s", ErrInvalid, store.ReviewJustified, store.ReviewUnjustified)
	}
	notes = strings.TrimSpace(notes)
	if notes == "" {

		return store.Grant{}, fmt.Errorf("%w: a review needs notes", ErrInvalid)
	}
	g, err := s.tier3(ctx, grantID)
	if err != nil {

		return store.Grant{}, err
	}
	if g.RequestedBy == actor.ID {

		return store.Grant{}, fmt.Errorf(
			"%w: a break-glass session is reviewed by someone other than the operator who opened it", identity.ErrForbidden)
	}
	if _, err := store.GetReview(ctx, s.db.Reader(), g.ID); err == nil {

		return store.Grant{}, fmt.Errorf("%w: %s", ErrReviewed, g.ID)

	} else if !errors.Is(err, store.ErrReviewNotFound) {

		return store.Grant{}, err
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertReview(ctx, tx, store.BreakglassReview{
			GrantID: g.ID, ReviewedBy: actor.ID, Outcome: outcome, Notes: notes,
		}); err != nil {

			return err
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action:     auditlog.ActionBreakglassReviewed,
			SubjectRef: "grant/" + g.ID,
			Detail: map[string]any{
				"outcome": outcome, "opened_by": g.RequestedBy, "notes": notes,
			},
		}); err != nil {

			return err
		}
		// The tenant sees the verdict on the access to their own data, not just
		// the access.
		return store.Notify(ctx, tx, store.Notification{
			TenantID: g.TenantID, Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassReviewed, SubjectRef: "grant/" + g.ID,
			Body: fmt.Sprintf("The break-glass access %s took to your %s was reviewed by %s and found %s: %s",
				g.RequestedBy, g.Subject, actor.ID, outcome, notes),
		})
	})
	if err != nil {

		return store.Grant{}, err
	}
	return g, nil
}

// Close ends a session before its box runs out.
//
// The requester (done early) or another operator (it should not be open). Not
// the tenant: a session that a tenant member could end mid-incident would not
// be break-glass. The tenant is told, and judges it in the review.
func (s *Service) Close(ctx context.Context, actor identity.Actor, grantID, reason string) (store.Grant, error) {

	if !actor.CanBreakglass() {

		return store.Grant{}, ErrNotOperator
	}
	g, err := s.tier3(ctx, grantID)
	if err != nil {

		return store.Grant{}, err
	}
	now := s.now()
	if !g.Active(now) {

		return store.Grant{}, fmt.Errorf("%w: %s is %s", ErrEnded, g.ID, g.State(now))
	}
	reason = strings.TrimSpace(reason)

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.RevokeGrant(ctx, tx, g.ID, actor.ID); err != nil {

			if errors.Is(err, store.ErrGrantNotFound) {

				return fmt.Errorf("%w: %s", ErrEnded, g.ID)
			}
			return err
		}
		detail := map[string]any{"opened_by": g.RequestedBy, "kind": g.Kind, "scope": g.Subject}
		if reason != "" {

			detail["reason"] = reason
		}
		if _, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action:     auditlog.ActionBreakglassClosed,
			SubjectRef: "grant/" + g.ID,
			Detail:     detail,
		}); err != nil {

			return err
		}
		body := fmt.Sprintf("%s ended the break-glass access %s took to your %s.", actor.ID, g.RequestedBy, g.Subject)
		if reason != "" {

			body += " Reason given: " + reason
		}
		return store.Notify(ctx, tx, store.Notification{
			TenantID: g.TenantID, Audience: store.AudienceTenant,
			Kind: store.NotifyBreakglassClosed, SubjectRef: "grant/" + g.ID,
			Body: body,
		})
	})
	if err != nil {

		return store.Grant{}, err
	}
	g.RevokedBy, g.RevokedAt = actor.ID, &now
	return g, nil
}

// tier3 loads a grant and refuses anything that is not break-glass.
func (s *Service) tier3(ctx context.Context, grantID string) (store.Grant, error) {

	g, err := store.GetGrant(ctx, s.db.Reader(), grantID)
	if err != nil {

		return store.Grant{}, err
	}
	if g.Tier != grantpolicy.TierBreakGlass {

		return store.Grant{}, fmt.Errorf("%w: %s", ErrNotBreakglass, g.ID)
	}
	return g, nil
}
