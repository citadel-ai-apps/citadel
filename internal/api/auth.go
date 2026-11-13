package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

type ctxKey int

const (
	actorKey ctxKey = iota
	actorErrKey
	operatorKey
)

// WithActor puts the acting principal in the context. Authentication happens in
// middleware, once, so no handler has to know which listener it is serving.
func WithActor(ctx context.Context, a identity.Actor) context.Context {

	return context.WithValue(ctx, actorKey, a)
}

// ActorFrom returns the authenticated principal, if any.
func ActorFrom(ctx context.Context) (identity.Actor, bool) {

	a, ok := ctx.Value(actorKey).(identity.Actor)
	return a, ok
}

// withActorErr carries a header that named a principal the control plane does
// not know. It is not a request-level failure: on the socket the read endpoints
// do not need an actor at all, and rejecting them here would make `citadel fleet` depend on
// the caller's shell username existing as a principal. Handlers that do need an
// actor get this error from s.actor, so the message still names the problem.
func withActorErr(ctx context.Context, err error) context.Context {

	return context.WithValue(ctx, actorErrKey, err)
}

func actorErrFrom(ctx context.Context) error {

	err, _ := ctx.Value(actorErrKey).(error)
	return err
}

// SocketHandler is the handler for the unix-socket listener.
//
// There, X-V2P-Principal is attribution rather than authentication: the socket's
// 0600 file mode is the authorisation boundary, and anyone who can open it is
// already root on the host. A bearer token is accepted too, so a service
// account can act through the socket with the same identity it would use over
// the network.
func (s *Server) SocketHandler() http.Handler {

	return s.withLogging(s.authenticate(s.router, true))
}

// APIHandler is the same router for a TCP listener: bearer tokens only.
//
// X-V2P-Principal is deliberately NOT honoured here and is stripped before the
// router sees it. On a socket the header is a convenience; on a TCP port it
// would be free impersonation of any principal, including the platform.
func (s *Server) APIHandler() http.Handler {

	return s.authenticate(s.router, false)
}

func (s *Server) authenticate(next http.Handler, trustHeader bool) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		ctx := req.Context()
		if trustHeader {

			// The same signal that makes X-V2P-Principal trustworthy makes this
			// the management listener: both come from the socket's file mode.
			ctx = withOperator(ctx)

		} else {

			req.Header.Del(PrincipalHeader)
		}
		req = req.WithContext(ctx)

		if raw, ok := bearer(req); ok {

			actor, err := s.Authenticate(ctx, raw)
			if err != nil {

				writeErr(w, statusFor(err), err)
				return
			}
			next.ServeHTTP(w, req.WithContext(WithActor(ctx, actor)))
			return
		}
		if !trustHeader {

			// Nothing on this listener is public (§8.4: "unauthenticated:
			// nothing beyond login", and login is the portal's, not the API's).
			// The socket can afford anonymous reads because its file mode already
			// authorised the caller; a TCP port has no such check behind it.
			w.Header().Set("WWW-Authenticate", `Bearer realm="citadel"`)
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("%w: a bearer token is required", authn.ErrBadToken))
			return
		}
		if id := req.Header.Get(PrincipalHeader); id != "" {

			actor, err := s.ident.ResolveActor(ctx, id)
			if err != nil {

				ctx = withActorErr(ctx, err)

			} else {

				ctx = WithActor(ctx, actor)
			}
		}
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func bearer(req *http.Request) (string, bool) {

	h := req.Header.Get("Authorization")
	if h == "" {

		return "", false
	}
	scheme, value, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || value == "" {

		return "", false
	}
	return strings.TrimSpace(value), true
}

// errTokenRefused is the one answer for every token that does not authenticate.
var errTokenRefused = fmt.Errorf("%w: token refused", authn.ErrBadToken)

// Authenticate resolves an API token to its principal.
//
// Every check that can fail closed does: unknown id, revoked, expired, wrong
// secret and a suspended principal all produce the same refusal, so a caller
// cannot use the error text to enumerate tokens.
func (s *Server) Authenticate(ctx context.Context, token string) (identity.Actor, error) {

	id, secret, err := authn.SplitToken(token)
	if err != nil {

		return identity.Actor{}, err
	}
	// The secret is hashed before the row is looked at. Why a token was
	// refused goes to the log, where the operator can read it.
	presented := authn.HashToken(secret)
	row, err := store.TokenByID(ctx, s.db.Reader(), id)
	reason := ""
	switch {

	case err != nil:
		reason = "unknown token"
	case row.RevokedAt != nil:
		reason = "revoked"
	case !time.Now().Before(row.ExpiresAt):
		reason = "expired"
	case !authn.EqualTokenHash(row.Hash, presented):
		reason = "wrong secret"
	}
	if reason != "" {

		s.log.Info("refused an API token", "token", id, "reason", reason)
		return identity.Actor{}, errTokenRefused
	}
	actor, err := s.ident.ResolveActor(ctx, row.PrincipalID)
	if err != nil {

		s.log.Info("refused an API token", "token", id, "reason", err)
		return identity.Actor{}, errTokenRefused
	}
	// Not an audit event: the audit log records what the principal did, and a
	// row per authenticated request would bury that under traffic (§14.4 vs
	// §15). The timestamp is for the token list in the portal.
	if err := store.TouchToken(ctx, s.db, row.ID); err != nil {

		s.log.Warn("cannot record token use", "token", row.ID, "err", err)
	}
	return actor, nil
}

// anyRole is the capability argument that asks for a role on the tenant and
// nothing more. The §14.1 table has no column for reading: every role, viewer
// included, sees the tenant-facing surface of §8.4 and §14.6 — the same rule the
// portal applies to its pages.
const anyRole = ""

// requireCap checks the acting principal's role on a tenant (§14.1). With
// anyRole it checks only that a role exists.
//
// The platform principal is exempt: automated work — the reconciler's own
// deploys, orphan custody — acts as the platform and must not need a role row
// on every tenant it touches. It is still a real, named actor in the audit log.
func (s *Server) requireCap(ctx context.Context, actor identity.Actor, tenantID, capability string) error {

	if actor.Kind == identity.KindPlatform {

		return nil
	}
	if capability == anyRole {

		_, err := s.ident.Role(ctx, tenantID, actor.ID)
		return err
	}
	_, err := s.ident.Require(ctx, tenantID, actor.ID, capability)
	return err
}

// readTenant opens every read handler under /tenants/{id}.
//
// On the socket the listener is the authorisation (see isOperator), so reads
// need neither an actor nor a role: `citadel tenant status` must not depend on
// the operator's shell username being a principal with a role on every tenant.
// Over TCP the bearer's principal needs a role on the tenant.
func (s *Server) readTenant(req *http.Request) (store.Tenant, error) {

	if isOperator(req) {

		return s.tenantFrom(req.Context(), req)
	}
	_, t, err := s.authedTenant(req, anyRole)
	return t, err
}

// requireCapOverTCP checks a capability for an action the operator may take on
// any tenant: start, stop and restart (a deployer's call, §14.1), cancelling a
// transfer. On the socket the listener is the authorisation and the operator
// needs no role on the tenant; over TCP the token's principal needs the
// capability.
func (s *Server) requireCapOverTCP(req *http.Request, actor identity.Actor, t store.Tenant, capability string) error {

	if isOperator(req) {

		return nil
	}
	if err := s.requireCap(req.Context(), actor, t.ID, capability); err != nil {

		return s.hideForeignTenant(req, actor, t, err)
	}
	return nil
}

// operatorOnly guards the /admin subrouter: §8.4 makes that half operator-only,
// and the operator boundary is the listener. A bearer token over TCP is a
// tenant-facing credential however powerful its principal, so it gets a 403
// rather than the fleet.
func operatorOnly(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		if !isOperator(req) {

			writeErr(w, http.StatusForbidden, fmt.Errorf(
				"%w: /admin is served on the control-plane socket only", identity.ErrForbidden))
			return
		}
		next.ServeHTTP(w, req)
	})
}

// authedTenant resolves the actor, the tenant and the capability in one step,
// which is the opening of nearly every mutating tenant handler. anyRole still
// requires a role.
func (s *Server) authedTenant(req *http.Request, capability string) (identity.Actor, store.Tenant, error) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		return identity.Actor{}, store.Tenant{}, err
	}
	t, err := s.tenantFrom(ctx, req)
	if err != nil {

		return identity.Actor{}, store.Tenant{}, err
	}
	if err := s.requireCap(ctx, actor, t.ID, capability); err != nil {

		return identity.Actor{}, store.Tenant{}, s.hideForeignTenant(req, actor, t, err)
	}
	return actor, t, nil
}

// hideForeignTenant turns "you have no role on this tenant" into "no such
// tenant".
//
// A 403 for a tenant that exists next to a 404 for one that does not is an
// oracle: a token holder could enumerate every slug and id on the platform and
// learn which ones are real. A principal with SOME role on the tenant already
// knows it exists, so a missing capability stays a 403 that says which.
func (s *Server) hideForeignTenant(req *http.Request, actor identity.Actor, t store.Tenant, err error) error {

	if !errors.Is(err, identity.ErrForbidden) {

		return err
	}
	if _, rerr := s.ident.Role(req.Context(), t.ID, actor.ID); errors.Is(rerr, identity.ErrForbidden) {

		return fmt.Errorf("%w: %s", store.ErrTenantNotFound, pathID(req))
	}
	return err
}

// withOperator marks the request as operator-originated.
func withOperator(ctx context.Context) context.Context {

	return context.WithValue(ctx, operatorKey, true)
}

// isOperator reports whether a request arrived on the unix socket.
//
// The operator boundary in this platform is the LISTENER, not the actor: the
// socket's 0600 mode is the authorisation check, and anyone who can open it is
// already root on the host. Every /admin route relies on exactly that. The
// actor stays a real person, because §14.1 wants a human on the audit row
// rather than the platform principal standing in for one.
//
// This gates the few flags that disable a safety check rather than exercise a
// capability — `rehearse: false`, `force` on an upgrade, `force` on a restore.
// A tenant may upgrade and may restore; only an operator may do either with the
// guard switched off, because the guard is what stands between a mistake and an
// irreversible migration (INV-4).
func isOperator(req *http.Request) bool {

	on, _ := req.Context().Value(operatorKey).(bool)
	return on
}
