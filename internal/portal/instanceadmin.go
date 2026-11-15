package portal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
)

// The break-glass admin token's bounds. maxBreakglassAdmin is how long an
// admin tab opened under a session can outlive an early close of it; the
// operator re-opens the handoff for longer, and each re-open is another
// data.pb_data.read on the tenant's Access tab.
const (
	minBreakglassAdmin = time.Minute
	maxBreakglassAdmin = 15 * time.Minute
)

// openInstanceAdmin hands an owner or admin, or a named operator under a
// break-glass data session on pb_data, into the instance's PocketBase admin UI
// (/_/) on the strength of their portal session alone.
//
// No PocketBase password exists to know: the portal signs a short-lived
// superuser token for the owner seat from pb_data on the host
// (internal/pbauth), and the browser carries it to the edge's bridge page on
// the instance's own hostname in the URL FRAGMENT, which no server ever
// receives. The bridge stores it where the admin UI looks. For an owner or
// admin the UI refreshes it into an ordinary session; a break-glass token
// cannot be refreshed. Nothing here calls the instance's API (design.md INV-5).
func (s *Server) openInstanceAdmin(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	// The platform principal can hold a real owner row (orphan custody), but
	// its shared login names nobody, so it never opens tenant data: that is a
	// named operator's break-glass (§14.3, §14.6).
	if sess.actor.Kind == identity.KindPlatform {

		http.Error(w, "the shared platform login does not open tenant data; a named operator uses break-glass",
			http.StatusForbidden)
		return
	}
	a, err := s.resolveTenant(ctx, sess.actor, mux.Vars(req)["id"])
	if err == nil && !identity.RoleAllows(a.Role, identity.CapInstanceAdmin) {

		err = fmt.Errorf("%w: %s is %s on %s", identity.ErrForbidden, sess.actor.ID, a.Role, a.Tenant.Slug)
	}
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	t := a.Tenant
	if t.Quarantined {

		back(w, req, "/t/"+t.ID, "", errors.New("the instance is quarantined; the edge is not serving it"))
		return
	}

	key, err := s.fs.EncryptionKey(t.ID)
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}
	src := pbauth.Source{DataDir: s.fs.DataDir(t.ID), PBVersion: t.RuntimeVersion, EncryptionKey: key}
	seat := pbauth.BySeatEmail(pbauth.SeatEmail(t.ID))
	var tok pbauth.Token
	ttl := pbauth.DefaultTTL
	if a.Breakglass != nil {

		// Break-glass: a token that cannot be refreshed, so the admin UI session
		// ends when it does, and never later than the session itself. Capped
		// below the session so an early close is outlived by at most that cap.
		left := time.Until(a.Breakglass.ExpiresAt)
		if left < minBreakglassAdmin {

			back(w, req, "/t/"+t.ID, "", errors.New("this break-glass session ends in under a minute; open a new one"))
			return
		}
		ttl = min(left, maxBreakglassAdmin)
		tok, err = pbauth.MintStatic(ctx, src, seat, ttl)

	} else {

		tok, err = pbauth.Mint(ctx, src, seat, ttl)
	}
	if errors.Is(err, pbauth.ErrNotTimeBoxable) {

		back(w, req, "/t/"+t.ID, "", errors.New("PocketBase "+t.RuntimeVersion+
			" cannot issue an admin session that stops with the break-glass session, so break-glass gives its pages only"))
		return
	}
	if errors.Is(err, pbauth.ErrNoSuperuser) {

		back(w, req, "/t/"+t.ID, "", errors.New("the owner account "+pbauth.SeatEmail(t.ID)+
			" was removed from inside the instance; it is re-created on the next deploy"))
		return
	}
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}
	entryKey, entryValue, err := pbauth.AdminUIEntry(tok)
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}
	frag, err := json.Marshal(map[string]string{"k": entryKey, "v": entryValue})
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}

	// Subject ref, never the token: the audit log outlives everything and a
	// token in it would be a credential in a table nothing may delete from.
	ev := auditlog.Event{
		ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
		Action: auditlog.ActionInstanceAdminOpened, SubjectRef: "tenant/" + t.ID,
		Detail: map[string]any{"superuser": tok.Email},
	}
	if a.Breakglass != nil {

		// A platform access to the tenant's data, on their Access tab (§14.6),
		// tied to the session that allowed it. data.pb_data.read is the
		// access-log family; the detail says what the session can actually do,
		// which is everything a superuser can, writes and deletes included.
		ev.Action, ev.SubjectRef = auditlog.ActionDataRead, "grant/"+a.Breakglass.ID
		ev.Detail = map[string]any{
			"what": "pb_data", "via": "instance_admin", "access": "superuser, read-write",
			"superuser": tok.Email,
			"grant":     a.Breakglass.ID, "expires_in": ttl.Round(time.Second).String(),
		}
	}
	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, ev)
		return err
	}); err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, req, "http://"+t.Hostname+proxyctl.AdminBridgePath+"#"+
		base64.RawURLEncoding.EncodeToString(frag), http.StatusSeeOther)
}
