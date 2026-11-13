package portal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pbauth"
	"github.com/citadel-ai-apps/citadel/internal/proxyctl"
)

// openInstanceAdmin hands the owner into their instance's PocketBase admin UI
// (/_/) on the strength of their portal session alone.
//
// No PocketBase password exists for the owner to know: the portal signs a
// short-lived superuser token for the owner seat from pb_data on the host
// (internal/pbauth), and the browser carries it to the edge's bridge page on
// the instance's own hostname in the URL FRAGMENT, which no server ever
// receives. The bridge stores it where the admin UI looks, and the UI refreshes
// it into an ordinary session. Nothing here calls the instance's API
// (design.md INV-5).
func (s *Server) openInstanceAdmin(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	sess := current(ctx)
	// The platform principal can hold a real owner row (orphan custody), but
	// a platform read of tenant data goes through break-glass (§14.6), never
	// through the owner's door.
	if sess.actor.Kind == identity.KindPlatform {

		http.Error(w, "the platform opens tenant data through break-glass, not the owner's admin handoff",
			http.StatusForbidden)
		return
	}
	t, err := s.tenantWithCap(ctx, sess.actor, mux.Vars(req)["id"], identity.CapInstanceAdmin)
	if err != nil {

		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if t.Quarantined {

		back(w, req, "/t/"+t.ID, "", errors.New("the instance is quarantined; the edge is not serving it"))
		return
	}

	key, err := s.fs.EncryptionKey(t.ID)
	if err != nil {

		back(w, req, "/t/"+t.ID, "", err)
		return
	}
	tok, err := pbauth.Mint(ctx, pbauth.Source{
		DataDir: s.fs.DataDir(t.ID), PBVersion: t.RuntimeVersion, EncryptionKey: key,
	}, pbauth.BySeatEmail(pbauth.SeatEmail(t.ID)), pbauth.DefaultTTL)
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
	if err := s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: sess.actor.ID, ActorKind: sess.actor.Kind, TenantID: t.ID,
			Action: auditlog.ActionInstanceAdminOpened, SubjectRef: "tenant/" + t.ID,
			Detail: map[string]any{"superuser": tok.Email},
		})
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
