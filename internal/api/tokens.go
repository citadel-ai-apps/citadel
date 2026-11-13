package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// CreateTokenRequest is POST /admin/tokens.
type CreateTokenRequest struct {
	Principal     string `json:"principal"`
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

// createToken mints an API token for a principal.
//
// The token is bound to a principal — for CI, a service_account — so a
// pipeline's deploy has a real actor in the audit log instead of an anonymous
// write nobody can attribute afterwards.
func (s *Server) createToken(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body CreateTokenRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := identity.Canonical(body.Principal)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	p, err := s.ident.Get(ctx, id)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// requireCap exempts the platform, so a platform bearer would be every
	// role on every tenant over TCP. The platform acts in-process and never
	// needs one.
	if p.Kind == identity.KindPlatform {

		writeErr(w, http.StatusUnprocessableEntity,
			fmt.Errorf("api: the platform principal cannot hold a token"))
		return
	}
	if p.Status != identity.StatusActive {

		writeErr(w, http.StatusUnprocessableEntity,
			fmt.Errorf("api: %s is %s and cannot hold a token", p.ID, p.Status))
		return
	}
	if body.Name == "" {

		writeErr(w, http.StatusBadRequest, fmt.Errorf("api: a token needs a name; it is how an operator knows what to revoke"))
		return
	}

	ttl := s.cfg.TokenTTL.D()
	if body.ExpiresInDays > 0 {

		ttl = time.Duration(body.ExpiresInDays) * 24 * time.Hour
	}
	row := store.APIToken{
		ID:          store.NewID("tk"),
		PrincipalID: p.ID,
		Name:        body.Name,
		CreatedBy:   actor.ID,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(ttl),
	}
	plaintext, hash := authn.NewToken(row.ID)
	row.Hash = hash

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertToken(ctx, tx, row); err != nil {

			return err
		}
		// No secret in the detail: audit rows outlive tenant data and hold
		// references, never values (§14.4). The token id is the reference.
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action:     auditlog.ActionTokenCreated,
			SubjectRef: "api_token/" + row.ID,
			Detail: map[string]any{
				"principal": row.PrincipalID, "name": row.Name,
				"expires_at": row.ExpiresAt.Format(time.RFC3339),
			},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	// The only time the secret exists outside the caller's memory.
	writeJSON(w, http.StatusCreated, map[string]any{"token": row, "secret": plaintext})
}

func (s *Server) listTokens(w http.ResponseWriter, req *http.Request) {

	rows, err := store.ListTokens(req.Context(), s.db.Reader(), req.URL.Query().Get("principal"))
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

func (s *Server) revokeToken(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	id := pathID(req)
	row, err := store.TokenByID(ctx, s.db.Reader(), id)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.RevokeToken(ctx, tx, id, actor.ID); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action:     auditlog.ActionTokenRevoked,
			SubjectRef: "api_token/" + id,
			Detail:     map[string]any{"principal": row.PrincipalID, "name": row.Name},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": id, "revoked": true})
}

// SetPasswordRequest is POST /admin/principals/{id}/password.
type SetPasswordRequest struct {
	Password string `json:"password"`
}

// setPassword sets a principal's portal password.
//
// An operator can set anyone's password — this is the bootstrap path, and the
// host root can read the database regardless (D15). What makes that acceptable
// is that it is audited with a named actor, exactly like every other action
// that crosses a trust boundary.
func (s *Server) setPassword(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	actor, err := s.actor(ctx, req)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	var body SetPasswordRequest
	if err := decodeBody(req, &body); err != nil {

		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := identity.Canonical(mux.Vars(req)["id"])
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	p, err := s.ident.Get(ctx, id)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	hash, err := authn.HashPassword(body.Password)
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.SetCredential(ctx, tx, store.PrincipalCredential{
			PrincipalID: p.ID, Algo: authn.Algo, Hash: hash,
		}); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind,
			Action:     auditlog.ActionCredentialSet,
			SubjectRef: "principal/" + p.ID,
			Detail:     map[string]any{"self_service": actor.ID == p.ID},
		})
		return err
	})
	if err != nil {

		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal": p.ID, "password_set": true})
}
