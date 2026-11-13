// Package api serves the control-plane HTTP API over a unix socket.
//
// A socket, not a TCP listener. Design §8.4 requires the control-plane API to
// be unreachable from any address a tenant bridge can route to, and the host
// probes showed a host service bound on 0.0.0.0 was reachable from a tenant
// container until the host-protection INPUT rule closed it. A socket file with
// 0600 permissions has no listener for a tenant to find at all.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"

	"github.com/citadel-ai-apps/citadel/internal/attest"
	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/authn"
	"github.com/citadel-ai-apps/citadel/internal/backup"
	"github.com/citadel-ai-apps/citadel/internal/config"
	dockerdrv "github.com/citadel-ai-apps/citadel/internal/driver/docker"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/reconcile"
	"github.com/citadel-ai-apps/citadel/internal/release"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// PrincipalHeader carries the acting principal. citadel sets it from --as,
// $CITADEL_PRINCIPAL, or person:$SUDO_USER.
const PrincipalHeader = "X-V2P-Principal"

// Server is the control-plane API.
type Server struct {
	cfg    config.Config
	db     *store.DB
	fs     *hostfs.FS
	ident  *identity.Service
	rel    *release.Store
	bkp    *backup.Service
	rec    *reconcile.Reconciler
	drv    *dockerdrv.Driver
	audit  *auditlog.Logger
	log    *slog.Logger
	router *mux.Router

	// attest and signer are optional. Nil means the control plane was started
	// without a signing key, and the surfaces that need one refuse with a clear
	// error rather than answering with an unsigned report that looks the same.
	attest Attestor
	signer auditlog.Signer
}

// Attestor is what the API needs from internal/attest.
type Attestor interface {
	Generate(ctx context.Context, tenantID string) (attest.Report, error)
}

// Options bundles the Server's collaborators.
type Options struct {
	Config     config.Config
	DB         *store.DB
	FS         *hostfs.FS
	Identity   *identity.Service
	Releases   *release.Store
	Backups    *backup.Service
	Reconciler *reconcile.Reconciler
	Driver     *dockerdrv.Driver
	Audit      *auditlog.Logger
	Log        *slog.Logger
	Attest     Attestor
	Signer     auditlog.Signer
}

// New returns a Server with its routes registered.
func New(o Options) *Server {

	s := &Server{
		cfg: o.Config, db: o.DB, fs: o.FS, ident: o.Identity, rel: o.Releases,
		bkp: o.Backups, rec: o.Reconciler,
		drv: o.Driver, audit: o.Audit, log: o.Log, router: mux.NewRouter(),
		attest: o.Attest, signer: o.Signer,
	}
	s.routes()
	return s
}

// Serve listens on the configured unix socket until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {

	path := s.cfg.SocketPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {

		return fmt.Errorf("api: mkdir %s: %w", filepath.Dir(path), err)
	}
	// A leftover socket from a killed daemon would make Listen fail. Removing
	// it is safe: if another daemon were live, it would hold the tenant locks
	// and every mutation would be refused anyway.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {

		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {

		return fmt.Errorf("api: listen %s: %w", path, err)
	}
	// 0600: the socket's file mode is the outer authorisation boundary; token
	// auth bound to service-account principals sits on top of it.
	if err := os.Chmod(path, 0o600); err != nil {

		return err
	}

	srv := &http.Server{Handler: s.SocketHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {

		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	s.log.Info("control-plane API listening", "socket", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {

		return err
	}
	return nil
}

// withLogging wraps the whole router rather than being registered with
// router.Use. Gorilla runs Use middleware only on matched routes, and a request
// that matches nothing is exactly the one worth having in the log on an API
// whose only authorisation boundary is a socket file mode. Per-route middleware
// (token auth) goes on the subrouters instead.
func (s *Server) withLogging(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, req)
		s.log.Debug("api request", "method", req.Method, "path", req.URL.Path,
			"status", rec.status, "dur", time.Since(start),
			"principal", req.Header.Get(PrincipalHeader))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {

	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer so log streaming is not buffered.
func (r *statusRecorder) Flush() {

	if f, ok := r.ResponseWriter.(http.Flusher); ok {

		f.Flush()
	}
}

// actor returns the principal the auth middleware resolved.
//
// No resolvable principal is a 400, never a silent fall back to the platform
// principal: attributing a human's action to the platform would make the audit
// log lie about who did it, which is the one thing §14 exists to prevent. The
// req argument is kept so every handler reads the same way whether it needs the
// request for anything else.
func (s *Server) actor(ctx context.Context, _ *http.Request) (identity.Actor, error) {

	a, ok := ActorFrom(ctx)
	if ok {

		return a, nil
	}
	if err := actorErrFrom(ctx); err != nil {

		return identity.Actor{}, err
	}
	return identity.Actor{}, identity.ErrNoActor
}

func writeJSON(w http.ResponseWriter, status int, v any) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {

		_ = json.NewEncoder(w).Encode(v)
	}
}

// apiError is the error envelope citadel renders.
type apiError struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, err error) {

	writeJSON(w, status, apiError{Error: err.Error()})
}

// statusFor maps domain errors onto HTTP codes, so citadel can distinguish "you
// asked for something that does not exist" from "the host is broken".
func statusFor(err error) int {

	switch {

	case errors.Is(err, identity.ErrNoActor):
		return http.StatusBadRequest
	case errors.Is(err, identity.ErrNotFound),
		errors.Is(err, store.ErrTenantNotFound),
		errors.Is(err, store.ErrVersionNotFound):
		return http.StatusNotFound
	case errors.Is(err, identity.ErrBadID):
		return http.StatusBadRequest
	case errors.Is(err, identity.ErrOwnsTenants),
		errors.Is(err, identity.ErrTransferConflict),
		errors.Is(err, identity.ErrSelfTransfer),
		errors.Is(err, reconcile.ErrUpgradeActive),
		errors.Is(err, reconcile.ErrDeployActive),
		errors.Is(err, reconcile.ErrDigestDrift),
		errors.Is(err, reconcile.ErrFrozen),
		errors.Is(err, reconcile.ErrPinNeedsStopped),
		errors.Is(err, store.ErrHardeningRegress),
		errors.Is(err, reconcile.ErrTooManyUpgrades):
		return http.StatusConflict
	case errors.Is(err, identity.ErrForbidden),
		errors.Is(err, identity.ErrInactive),
		errors.Is(err, identity.ErrNotTransferee):
		return http.StatusForbidden
	case errors.Is(err, authn.ErrBadCredentials),
		errors.Is(err, authn.ErrBadToken),
		errors.Is(err, authn.ErrBadSession):
		return http.StatusUnauthorized
	// Another tenant's release is answered exactly like a missing one:
	// confirming that a release id exists elsewhere is itself information.
	case errors.Is(err, store.ErrReleaseNotFound),
		errors.Is(err, release.ErrUploadMissing),
		errors.Is(err, reconcile.ErrWrongTenant),
		errors.Is(err, store.ErrBackupNotFound),
		errors.Is(err, store.ErrGrantNotFound),
		errors.Is(err, store.ErrTokenNotFound),
		errors.Is(err, store.ErrTransferNotFound),
		errors.Is(err, store.ErrCredentialNotFound),
		errors.Is(err, store.ErrUpgradeJobNotFound),
		errors.Is(err, store.ErrVersionNotFound):
		return http.StatusNotFound
	// A package the platform will not accept is the caller's to fix, and it is
	// a well-formed request about an unprocessable entity — not a 400 about
	// syntax and not a 500 about the host.
	case errors.Is(err, pkgvalidate.ErrManifest),
		errors.Is(err, pkgvalidate.ErrNotZip),
		errors.Is(err, pkgvalidate.ErrTooLarge),
		errors.Is(err, pkgvalidate.ErrTooManyFiles),
		errors.Is(err, pkgvalidate.ErrZipBomb),
		errors.Is(err, pkgvalidate.ErrForeignPath),
		errors.Is(err, pkgvalidate.ErrTraversal),
		errors.Is(err, pkgvalidate.ErrSymlink),
		errors.Is(err, pkgvalidate.ErrNodeType),
		errors.Is(err, pkgvalidate.ErrExecBit),
		errors.Is(err, pkgvalidate.ErrNonJS),
		errors.Is(err, pkgvalidate.ErrRange),
		errors.Is(err, pkgvalidate.ErrEgressPolicy),
		errors.Is(err, pkgvalidate.ErrRefusedSubject),
		errors.Is(err, pkgvalidate.ErrNoSupportedRuntime),
		errors.Is(err, reconcile.ErrIncompatible),
		errors.Is(err, reconcile.ErrEgressDenied),
		errors.Is(err, authn.ErrWeakPassword),
		errors.Is(err, identity.ErrTransferExpired),
		errors.Is(err, identity.ErrReasonRequired),
		errors.Is(err, backup.ErrVersionMismatch),
		errors.Is(err, backup.ErrArchiveDigest),
		errors.Is(err, reconcile.ErrUpgradeBlocked),
		errors.Is(err, reconcile.ErrSameVersion),
		errors.Is(err, reconcile.ErrDowngrade),
		errors.Is(err, reconcile.ErrVersionNotUpgradable),
		errors.Is(err, reconcile.ErrNotRunning),
		errors.Is(err, reconcile.ErrPinNeedsJustification),
		errors.Is(err, store.ErrEOLDateRequired),
		errors.Is(err, store.ErrBadVersionState):
		return http.StatusUnprocessableEntity
	case errors.Is(err, hostfs.ErrLocked):
		return http.StatusConflict
	case errors.Is(err, auditlog.ErrDetailRejected):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func decodeBody(req *http.Request, v any) error {

	defer req.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, req.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {

		return fmt.Errorf("api: bad request body: %w", err)
	}
	return nil
}
