package identity

import (
	"context"
	"errors"
	"fmt"
)

// Actor is the resolved principal behind a request. Every mutation carries one:
// an automated action gets Platform(), a human action must name a human, and
// there is no third option (§14.1).
type Actor struct {
	ID   string
	Kind string
}

// Platform is the actor for reconciler and recovery work.
func Platform() Actor { return Actor{ID: PlatformPrincipal, Kind: KindPlatform} }

// ErrNoActor is returned when a mutation arrives with no resolvable principal.
// It is deliberately not satisfiable by falling back to the platform principal:
// that would attribute a human's action to the platform and make the audit log
// lie about who did it.
var ErrNoActor = errors.New("identity: request has no resolvable principal")

// ResolveActor looks up id and returns it as an Actor, refusing non-active
// principals.
func (s *Service) ResolveActor(ctx context.Context, id string) (Actor, error) {

	if id == "" {

		return Actor{}, ErrNoActor
	}
	canonical, err := Canonical(id)
	if err != nil {

		return Actor{}, err
	}
	p, err := s.Get(ctx, canonical)
	if err != nil {

		// Deliberately not auto-created. Silently inventing a principal for an
		// unrecognised --as would turn a typo into a new identity in the audit
		// log, which is worse than failing: the log would name an actor nobody
		// ever vouched for.
		return Actor{}, fmt.Errorf("%w (create it with `citadel principal create %s`)", err, id)
	}
	if p.Status != StatusActive {

		return Actor{}, fmt.Errorf("%w: principal %s is %s", ErrInactive, p.ID, p.Status)
	}
	return Actor{ID: p.ID, Kind: p.Kind}, nil
}
