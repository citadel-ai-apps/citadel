package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/breakglass"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// openBreakglass is a named operator opening Tier-3 access from the portal
// (§14.3). The terms are internal/breakglass's, the same ones the socket API
// applies; this adds the one thing a browser needs that a root shell does not:
// the operator's password, again.
//
// A session cookie is a bearer credential. Without the re-check, anyone who
// lifted one could open every tenant's data in the operator's name; with it,
// they also need the secret the cookie was minted from. It is throttled with
// the login form's counters, so this is not a second place to guess passwords.
func (s *Server) openBreakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	const to = "/attestations"
	if !sess.actor.CanBreakglass() {

		back(w, req, to, "", breakglass.ErrNotOperator)
		return
	}
	t, err := s.operatorTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	if err := s.confirmPassword(ctx, req, sess.actor); err != nil {

		back(w, req, to, "", err)
		return
	}
	g, err := s.bg.Open(ctx, sess.actor, t, breakglass.Request{
		Reason: req.PostFormValue("reason"),
		Kind:   req.PostFormValue("kind"),
		Scope:  req.PostFormValue("scope"),
	})
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	back(w, req, "/t/"+t.ID, fmt.Sprintf("break-glass %s: your access to %s is open now, until %s; %s has been told, "+
		"and another operator reviews it afterwards", g.ID, t.Slug, stamp(g.ExpiresAt), t.Slug), nil)
}

// confirmPassword re-checks the signed-in principal's password, on the login
// form's throttle.
func (s *Server) confirmPassword(ctx context.Context, req *http.Request, actor identity.Actor) error {

	keys := []throttleKey{{"principal", actor.ID}, {"address", hostOnly(req.RemoteAddr)}}
	if !s.throttle.allowed(keys...) {

		return errors.New("too many failed attempts; try again later")
	}
	if _, err := s.verify(ctx, actor.ID, req.PostFormValue("password")); err != nil {

		s.throttle.fail(keys...)
		s.recordAuth(ctx, actor.ID, false, req.RemoteAddr, "portal:breakglass-confirm")
		return fmt.Errorf("%w: re-enter your own portal password to open break-glass", authn.ErrBadCredentials)
	}
	s.throttle.succeed(keys[0])
	return nil
}

// reviewBreakglass records the verdict on a session (breakglass.Review).
func (s *Server) reviewBreakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	const to = "/attestations"
	g, err := s.bg.Review(ctx, sess.actor, mux.Vars(req)["gid"],
		req.PostFormValue("outcome"), req.PostFormValue("notes"))
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	back(w, req, to, "reviewed "+g.ID+": "+req.PostFormValue("outcome"), nil)
}

// closeBreakglass ends a session early: the opener from the tenant page's
// banner or the project list, or another operator from /attestations.
func (s *Server) closeBreakglass(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	const to = "/attestations"
	g, err := s.bg.Close(ctx, sess.actor, mux.Vars(req)["gid"], req.PostFormValue("reason"))
	if err != nil {

		back(w, req, to, "", err)
		return
	}
	back(w, req, to, "break-glass "+g.ID+" closed; another operator still reviews it afterwards", nil)
}

// auditBreakglassView records an impersonation the first time an operator
// views the tenant's pages under a support_impersonation session (§14.4 audits
// impersonation; §14.6 shows it to the tenant). A data session's page views
// are covered by its open event; its reads of data are audited where they
// happen (the admin handoff, the log tail).
func (s *Server) auditBreakglassView(ctx context.Context, actor identity.Actor, a tenantAccess) error {

	if a.Breakglass == nil || a.Breakglass.Kind != store.GrantSupportImpersonate {

		return nil
	}
	return s.auditBreakglassOnce(ctx, actor, *a.Breakglass, auditlog.ActionImpersonationStarted,
		map[string]any{"what": "tenant_pages", "scope": a.Breakglass.Subject})
}

// auditBreakglassOnce appends action once per session, tied to the grant.
// Process-local: a restart can record a session's first view or read twice,
// never not at all.
func (s *Server) auditBreakglassOnce(ctx context.Context, actor identity.Actor, g store.Grant, action string, detail map[string]any) error {

	key := g.ID + "|" + action
	if _, seen := s.bgAudited.LoadOrStore(key, struct{}{}); seen {

		return nil
	}
	d := map[string]any{"grant": g.ID, "surface": "portal"}
	for k, v := range detail {

		d[k] = v
	}
	err := s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: g.TenantID,
			Action: action, SubjectRef: "grant/" + g.ID, Detail: d,
		})
		return err
	})
	if err != nil {

		// Not recorded, so not shown: the next request tries again.
		s.bgAudited.Delete(key)
	}
	return err
}
