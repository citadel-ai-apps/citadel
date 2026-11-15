// Package portal is the browser surface: the product a tenant actually touches.
//
// It runs on its own TCP listener, never on the control-plane unix socket — a
// browser cannot dial a socket. That is acceptable because tenant bridges
// cannot reach host ports at all (the `INPUT -i br-t-+ -j DROP`
// host-protection rule), and it is the reason the portal is NOT published
// through the edge Caddy: Caddy joins every tenant network, so a route there
// would put the operator UI inside every tenant's reach.
//
// Authentication is a signed session cookie (internal/authn) over the control
// plane's own identity store — never a tenant's PocketBase, because the
// tenant is superuser of their own instance and can delete any account the
// platform creates in it.
//
// Pages are server-rendered html/template with htmx for the live bits. Every
// form works without JavaScript; htmx only removes full-page reloads.
package portal

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/breakglass"
	"github.com/citadel-ai-apps/citadel/internal/config"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/logcollect"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// assets are vendored, not linked from a CDN: a CDN is a supply-chain surface
// and an offline failure, and the portal has to work on a host with no egress
// of its own. htmx 2.0.4, sha256
// e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447.
//
//go:embed templates/*.html static/*
var assets embed.FS

// Server renders the portal.
type Server struct {
	cfg      config.Config
	db       *store.DB
	fs       *hostfs.FS
	ident    *identity.Service
	rel      *release.Store
	rec      *reconcile.Reconciler
	drv      *dockerdrv.Driver
	logs     *logcollect.Collector
	audit    *auditlog.Logger
	sessions *authn.Sessions
	api      http.Handler
	attest   Attestor
	signer   auditlog.Signer
	log      *slog.Logger
	tpl      *template.Template
	router   *mux.Router
	bg       *breakglass.Service

	// bgAudited is the (grant, action) pairs already audited under a
	// break-glass session: the first page view of an impersonation, the first
	// log read. Pages are reloaded and the log tail polls every few seconds; one
	// row per session says who looked without burying the tenant's access log.
	bgAudited sync.Map

	throttle  *loginThrottle
	hashSlots hashSlots
	// dummyHash is verified against when the claimed principal has no
	// credential, so an unknown name costs the same argon2id as a known one.
	dummyHash string
}

// Options bundles the portal's collaborators.
type Options struct {
	Config     config.Config
	DB         *store.DB
	FS         *hostfs.FS
	Identity   *identity.Service
	Releases   *release.Store
	Reconciler *reconcile.Reconciler
	Driver     *dockerdrv.Driver
	Logs       *logcollect.Collector
	Audit      *auditlog.Logger
	Sessions   *authn.Sessions
	// API is the control-plane JSON API with bearer-token authentication,
	// mounted under /api/. It is how a CI deploy reaches the platform: the unix
	// socket needs host access, and a pipeline does not have that.
	API http.Handler
	Log *slog.Logger
	// Attest and Signer are optional. Nil means the pages that show a signed
	// report say so, rather than rendering an empty card that reads as "nothing
	// to see".
	Attest Attestor
	Signer auditlog.Signer
}

// Attestor is what the portal needs from internal/attest.
type Attestor interface {
	Generate(ctx context.Context, tenantID string) (attest.Report, error)
}

// New parses the templates and registers the routes.
func New(o Options) (*Server, error) {

	tpl, err := template.New("portal").Funcs(funcs()).ParseFS(assets, "templates/*.html")
	if err != nil {

		return nil, fmt.Errorf("portal: templates: %w", err)
	}
	s := &Server{
		cfg: o.Config, db: o.DB, fs: o.FS, ident: o.Identity, rel: o.Releases,
		rec: o.Reconciler, drv: o.Driver, logs: o.Logs, audit: o.Audit, sessions: o.Sessions,
		api: o.API, attest: o.Attest, signer: o.Signer,
		log: o.Log, tpl: tpl, router: mux.NewRouter(),
		throttle: newLoginThrottle(), hashSlots: make(hashSlots, concurrentHashes),
		bg: breakglass.New(o.DB, o.Audit),
	}
	dummy, err := authn.HashPassword(rand.Text())
	if err != nil {

		return nil, fmt.Errorf("portal: %w", err)
	}
	s.dummyHash = dummy
	s.routes()
	return s, nil
}

func (s *Server) routes() {

	r := s.router
	r.Use(s.securityHeaders)
	r.PathPrefix("/static/").Handler(http.FileServer(http.FS(assets)))
	if s.api != nil {

		r.PathPrefix("/api/").Handler(s.api)
	}

	r.HandleFunc("/login", s.loginPage).Methods(http.MethodGet)
	r.HandleFunc("/login", s.login).Methods(http.MethodPost)
	r.HandleFunc("/logout", s.logout).Methods(http.MethodPost)

	in := r.NewRoute().Subrouter()
	in.Use(s.requireSession)
	in.HandleFunc("/", s.tenantsPage).Methods(http.MethodGet)
	in.HandleFunc("/grants", s.grantQueuePage).Methods(http.MethodGet)
	in.HandleFunc("/attestations", s.attestationsPage).Methods(http.MethodGet)
	// Operator actions on a tenant live under /attestations, not /t/: every /t/
	// route is role-checked, and the operator has no role on most tenants. The
	// re-check is for any operator; break-glass is for a named person with the
	// operator flag (INV-16), never the shared platform login. Tier-2 grant
	// decisions are still citadel on the host.
	in.HandleFunc("/attestations/{id}/check", s.attestNow).Methods(http.MethodPost)
	in.HandleFunc("/attestations/{id}/breakglass", s.openBreakglass).Methods(http.MethodPost)
	in.HandleFunc("/breakglass/{gid}/review", s.reviewBreakglass).Methods(http.MethodPost)
	in.HandleFunc("/breakglass/{gid}/close", s.closeBreakglass).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}", s.tenantPage).Methods(http.MethodGet)
	in.HandleFunc("/t/{id}/logs", s.tenantLogs).Methods(http.MethodGet)
	in.HandleFunc("/t/{id}/upload", s.upload).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/releases/{rid}/download", s.downloadRelease).Methods(http.MethodGet)
	in.HandleFunc("/t/{id}/deploy", s.deploy).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/rollback", s.rollback).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/restart", s.restart).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/backup", s.backup).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/backups/{bid}/restore", s.restoreBackup).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/upgrade", s.startUpgrade).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/upgrade/{jobid}", s.upgradePage).Methods(http.MethodGet)
	in.HandleFunc("/fleet", s.fleetPage).Methods(http.MethodGet)
	in.HandleFunc("/t/{id}/grants/{gid}/revoke", s.revokeGrant).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/grants/{gid}/reenable", s.reenableGrant).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/grants/{gid}/reaffirm", s.reaffirmGrant).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/owner/{action}", s.ownerAction).Methods(http.MethodPost)
	in.HandleFunc("/t/{id}/admin", s.openInstanceAdmin).Methods(http.MethodPost)

	r.NotFoundHandler = s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		http.Error(w, "not found", http.StatusNotFound)
	}))
}

// contentSecurityPolicy forbids inline script and every origin but the
// portal's own.
//
// The portal renders text a tenant controls: container output, hook errors,
// release notes. html/template escapes what it interpolates, but an htmx swap
// of a raw response is HTML insertion, and one missing hx-swap was enough to
// put a tenant's console.log into an operator's session. The policy is what
// makes the next such slip inert rather than an account takeover.
//
// form-action names the apps domain because the admin handoff is a form post
// that redirects to <slug>.<apps domain>, and browsers apply form-action to the
// redirect target as well as to the form's own action.
func contentSecurityPolicy(appsDomain string) string {

	formAction := "'self'"
	if appsDomain != "" {

		formAction += " http://*." + appsDomain + " https://*." + appsDomain
	}
	return "default-src 'self'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data:; object-src 'none'; base-uri 'none'; " +
		"frame-ancestors 'none'; form-action " + formAction
}

// securityHeaders sets the response headers every portal page carries.
//
// Handlers that need something stricter (the admin handoff) override them
// with Header().Set after this has run.
func (s *Server) securityHeaders(next http.Handler) http.Handler {

	csp := contentSecurityPolicy(s.cfg.AppsDomain)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, req)
	})
}

// Serve listens on cfg.PortalAddr until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {

	ln, err := net.Listen("tcp", s.cfg.PortalAddr)
	if err != nil {

		return fmt.Errorf("portal: listen %s: %w", s.cfg.PortalAddr, err)
	}
	srv := &http.Server{Handler: s.withLogging(s.router), ReadHeaderTimeout: 10 * time.Second}
	go func() {

		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	s.log.Info("portal listening", "addr", s.cfg.PortalAddr)
	if s.cfg.PortalAllowPublic && !s.cfg.PortalSecureCookies {

		s.log.Warn("the portal is bound to a public address without portal_secure_cookies: " +
			"session cookies and passwords travel in the clear unless a TLS proxy fronts it; " +
			"put one in front and set portal_secure_cookies")
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {

		return err
	}
	return nil
}

func (s *Server) withLogging(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		start := time.Now()
		next.ServeHTTP(w, req)
		s.log.Debug("portal request", "method", req.Method, "path", req.URL.Path, "dur", time.Since(start))
	})
}

// currentEpoch reports whether a cookie's session epoch is the principal's
// current one. Sign-out and a password change bump the stored epoch, which is
// what ends every copy of a cookie issued before them.
//
// A principal with no credential row is at epoch 0: a portal session is only
// ever issued by a password login, so such a cookie was minted by whoever holds
// the session key, which no epoch could stop anyway.
func (s *Server) currentEpoch(ctx context.Context, principalID string, epoch int64) bool {

	cred, err := store.GetCredential(ctx, s.db.Reader(), principalID)
	switch {

	case err == nil:
		return cred.SessionEpoch == epoch
	case errors.Is(err, store.ErrCredentialNotFound):
		return epoch == 0
	default:
		s.log.Warn("cannot read the session epoch; refusing the session", "principal", principalID, "err", err)
		return false
	}
}

// formBodyLimit caps every portal POST that is not a package upload.
const formBodyLimit = 1 << 20

type ctxKey int

const actorKey ctxKey = iota

type session struct {
	actor identity.Actor
	csrf  string
}

// requireSession authenticates from the cookie and nothing else.
//
// X-V2P-Principal is deliberately not consulted here: on a TCP listener that
// header is an impersonation primitive, and the portal never trusts it. The
// only other credential this listener accepts is a bearer token, on /api/,
// which is mounted outside this subrouter.
func (s *Server) requireSession(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		c, err := req.Cookie(s.cookieName())
		if err != nil {

			s.redirectToLogin(w, req)
			return
		}
		id, epoch, err := s.sessions.VerifyEpoch(c.Value)
		if err == nil && !s.currentEpoch(req.Context(), id, epoch) {

			err = authn.ErrBadSession
		}
		if err != nil {

			s.clearCookie(w)
			s.redirectToLogin(w, req)
			return
		}
		actor, err := s.ident.ResolveActor(req.Context(), id)
		if err != nil {

			// The principal was suspended or deleted while the cookie was still
			// valid. Stateless sessions cannot be revoked server-side, so the
			// check happens here, on every request (see authn.Sessions).
			s.clearCookie(w)
			s.redirectToLogin(w, req)
			return
		}
		if req.Method == http.MethodPost {

			// Capped before anything parses the body: reading the CSRF field
			// parses the whole form, multipart included, and that happens
			// before any handler has checked a role. Only an upload may be
			// package-sized.
			limit := int64(formBodyLimit)
			if strings.HasSuffix(req.URL.Path, "/upload") {

				limit = s.cfg.MaxPackageBytes + formBodyLimit
			}
			req.Body = http.MaxBytesReader(w, req.Body, limit)
			// The body only: a token in the query string ends up in logs,
			// history and Referer headers.
			if !s.sessions.ValidCSRF(c.Value, req.PostFormValue("csrf")) {

				http.Error(w, "csrf token missing or stale; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(req.Context(), actorKey, session{actor: actor, csrf: s.sessions.CSRFToken(c.Value)})
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func (s *Server) redirectToLogin(w http.ResponseWriter, req *http.Request) {

	next := req.URL.RequestURI()
	http.Redirect(w, req, "/login?next="+template.URLQueryEscaper(next), http.StatusSeeOther)
}

func current(ctx context.Context) session {

	sess, _ := ctx.Value(actorKey).(session)
	return sess
}

// cookieName is the session cookie's name. With secure cookies it carries the
// __Host- prefix, which a browser only accepts on a Secure, host-only cookie
// with Path=/ — so no sibling subdomain, and nothing on plain HTTP, can plant
// or overwrite it.
func (s *Server) cookieName() string {

	if s.cfg.PortalSecureCookies {

		return "__Host-" + authn.SessionCookie
	}
	return authn.SessionCookie
}

func (s *Server) clearCookie(w http.ResponseWriter) {

	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cfg.PortalSecureCookies,
	})
}

func (s *Server) setCookie(w http.ResponseWriter, value string) {

	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: value, Path: "/",
		MaxAge: int(s.sessions.TTL().Seconds()),
		// HttpOnly so a scripting bug cannot read it; SameSite=Lax so a
		// cross-site form post cannot deploy on someone's behalf, which the
		// CSRF token then backs up; Secure when the portal is served over TLS.
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cfg.PortalSecureCookies,
	})
}

// funcs are the template helpers. Deliberately few, and deliberately tolerant
// of nil and of both int64 and uint64: a template that panics on a nil
// timestamp is a page a tenant cannot load, and the difference between a
// backup's int64 size and a filesystem's uint64 one is not a distinction any
// template should have to make.
func funcs() template.FuncMap {

	return template.FuncMap{
		"short": func(s string) string {

			if len(s) > 12 {

				return s[:12]
			}
			return s
		},
		"ago":   ago,
		"stamp": stamp,
		"bytes": humanBytes,
		"label": func(s string) string { return strings.ReplaceAll(s, "_", " ") },
	}
}

func asTime(v any) time.Time {

	switch t := v.(type) {

	case time.Time:
		return t
	case *time.Time:
		if t == nil {

			return time.Time{}
		}
		return *t
	default:
		return time.Time{}
	}
}

func ago(v any) string {

	t := asTime(v)
	if t.IsZero() {

		return "—"
	}
	d := time.Since(t).Round(time.Second)
	switch {

	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func stamp(v any) string {

	t := asTime(v)
	if t.IsZero() {

		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func humanBytes(v any) string {

	var n float64
	switch b := v.(type) {

	case uint64:
		n = float64(b)
	case int64:
		n = float64(b)
	case int:
		n = float64(b)
	default:
		return "—"
	}
	switch {

	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", n/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", n/(1<<10))
	default:
		return fmt.Sprintf("%.0f B", n)
	}
}
