// Package release turns an uploaded package zip into a validated, immutable,
// content-addressed release.
//
// The artifact store itself is internal/hostfs (StageArtifact, SwapAppCurrent):
// this package validates, stages, records the row and writes the audit event.
//
// One identity decision worth knowing before reading the code: release.sha256
// is the artifact *tree* digest from hostfs.ArtifactDigest, not the digest of
// the uploaded zip bytes. That is the value artifacts/<sha>/ and
// tenant.current_artifact are keyed by, so a sha shared by ten tenants is
// stored once (§7), and two uploads differing only in zip metadata dedupe to
// one artifact. The zip's own digest is recorded in the release.uploaded audit
// event, so the exact bytes a tenant uploaded remain attributable.
package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/uptrace/bun"

	"github.com/citadel-ai-apps/citadel/internal/auditlog"
	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/hostfs"
	"github.com/citadel-ai-apps/citadel/internal/identity"
	"github.com/citadel-ai-apps/citadel/internal/pkgvalidate"
	"github.com/citadel-ai-apps/citadel/internal/store"
)

// Store ingests packages into the artifact store.
type Store struct {
	cfg   config.Config
	db    *store.DB
	fs    *hostfs.FS
	audit *auditlog.Logger
}

// New returns a Store.
func New(cfg config.Config, db *store.DB, fs *hostfs.FS, audit *auditlog.Logger) *Store {

	return &Store{cfg: cfg, db: db, fs: fs, audit: audit}
}

// Ingest validates the zip at r, stages its artifact, and records a release row
// for the tenant. The release is not deployed: that is a separate, explicit
// operation (§8.5).
func (s *Store) Ingest(ctx context.Context, actor identity.Actor, t store.Tenant, r io.ReaderAt, size int64) (store.Release, error) {

	supported, err := s.supportedVersions(ctx)
	if err != nil {

		return store.Release{}, err
	}

	// Unpack inside the artifacts directory so the later rename into
	// artifacts/<sha>/ stays on one filesystem and stays atomic.
	tmp, err := os.MkdirTemp(s.cfg.ArtifactsDir(), "ingest-")
	if err != nil {

		return store.Release{}, fmt.Errorf("release: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	limits := pkgvalidate.DefaultLimits()
	limits.MaxUncompressed = s.cfg.MaxPackageBytes
	limits.MaxFiles = s.cfg.MaxPackageFiles

	opt := pkgvalidate.Options{
		Limits:     limits,
		HostPolicy: pkgvalidate.HostPolicy{PlatformDomains: []string{s.cfg.AppsDomain}},
		Supported:  supported,
	}
	res, err := pkgvalidate.Validate(r, size, tmp, opt)
	if err != nil {

		return store.Release{}, err
	}

	sha, err := s.fs.StageArtifact(tmp)
	if err != nil {

		return store.Release{}, err
	}
	zipSha, err := s.keepUpload(r, size, sha)
	if err != nil {

		return store.Release{}, err
	}

	egress, err := json.Marshal(res.Manifest.Egress)
	if err != nil {

		return store.Release{}, err
	}
	rel := store.Release{
		ID:          store.NewID("rel"),
		TenantID:    t.ID,
		Sha256:      sha,
		Manifest:    string(res.Raw),
		PBMin:       res.Manifest.PocketBase.Min,
		PBMax:       res.Manifest.PocketBase.Max,
		EgressHosts: string(egress),
		Status:      store.ReleaseValidated,
	}

	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		if err := store.InsertRelease(ctx, tx, rel); err != nil {

			return err
		}
		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionReleaseUploaded,
			SubjectRef: "release/" + rel.ID,
			Detail: map[string]any{
				"artifact":       sha,
				"upload_sha256":  zipSha,
				"files":          res.Files,
				"bytes":          res.Bytes,
				"app_version":    res.Manifest.Version,
				"pb_min":         res.Manifest.PocketBase.Min,
				"pb_max":         res.Manifest.PocketBase.Max,
				"egress_request": len(res.Manifest.Egress),
			},
		})
		return err
	})
	if err != nil {

		return store.Release{}, err
	}
	return rel, nil
}

// keepUpload stores the zip as uploaded, beside its artifact, and returns its
// digest. §7 keeps the original for audit: the unpacked tree is what runs, but
// the bytes the tenant sent are what a later question is about.
func (s *Store) keepUpload(r io.ReaderAt, size int64, sha string) (string, error) {

	src := io.NewSectionReader(r, 0, size)
	dst := filepath.Join(s.cfg.ArtifactsDir(), sha+".zip")

	h := sha256.New()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if os.IsExist(err) {

		// The artifact already existed, so this upload is a duplicate of one
		// already kept. Hash it anyway: the audit event records what *this*
		// upload was, not what the first one happened to be.
		if _, err := io.Copy(h, src); err != nil {

			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	if err != nil {

		return "", fmt.Errorf("release: keep upload: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(io.MultiWriter(f, h), src); err != nil {

		_ = os.Remove(dst)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ErrUploadMissing is returned when a release row exists but the zip it was
// ingested from is no longer on disk. Answered as not-found: there is nothing
// to download.
var ErrUploadMissing = errors.New("release: package zip is no longer stored")

// Download is an opened release package, ready to be served.
type Download struct {
	Release store.Release
	File    *os.File
	ModTime time.Time
	// Name is the filename to offer the client.
	Name string
}

// OpenDownload opens the zip a tenant's release was ingested from and records
// that it was handed out.
//
// The release must belong to t: a release id from another tenant is answered
// exactly like a missing one, so a member of one tenant cannot probe another's
// ids. The caller is responsible for the capability check and for closing
// File.
func (s *Store) OpenDownload(ctx context.Context, actor identity.Actor, t store.Tenant, releaseID string) (Download, error) {

	rel, err := store.GetRelease(ctx, s.db.Reader(), releaseID)
	if err != nil {

		return Download{}, err
	}
	if rel.TenantID != t.ID {

		return Download{}, fmt.Errorf("%w: %s", store.ErrReleaseNotFound, releaseID)
	}
	// Uploads that differ only in zip metadata share one artifact and so one
	// kept zip: the first. Its tree is byte-identical to this release's.
	f, err := os.Open(filepath.Join(s.cfg.ArtifactsDir(), rel.Sha256+".zip"))
	if os.IsNotExist(err) {

		return Download{}, fmt.Errorf("%w: %s", ErrUploadMissing, rel.ID)
	}
	if err != nil {

		return Download{}, fmt.Errorf("release: open package of %s: %w", rel.ID, err)
	}
	fi, err := f.Stat()
	if err != nil {

		_ = f.Close()
		return Download{}, err
	}

	// Audited: the package is the tenant's source code, and who took a copy of
	// it is exactly the kind of question §14.4 is there to answer.
	err = s.db.Tx(ctx, func(tx bun.Tx) error {

		_, err := s.audit.Append(ctx, tx, auditlog.Event{
			ActorID: actor.ID, ActorKind: actor.Kind, TenantID: t.ID,
			Action:     auditlog.ActionReleaseDownloaded,
			SubjectRef: "release/" + rel.ID,
			Detail:     map[string]any{"artifact": rel.Sha256, "bytes": fi.Size()},
		})
		return err
	})
	if err != nil {

		_ = f.Close()
		return Download{}, err
	}
	return Download{Release: rel, File: f, ModTime: fi.ModTime(), Name: rel.ID + ".zip"}, nil
}

// Serve writes the package as an attachment and closes it. Range and
// conditional requests are handled by http.ServeContent.
func (d Download) Serve(w http.ResponseWriter, req *http.Request) {

	defer d.File.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": d.Name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	http.ServeContent(w, req, d.Name, d.ModTime, d.File)
}

// supportedVersions is the set a manifest range must intersect: what the
// platform will actually schedule today, not every version ever registered.
func (s *Store) supportedVersions(ctx context.Context) ([]string, error) {

	rows, err := store.ListRuntimeVersions(ctx, s.db.Reader())
	if err != nil {

		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, rv := range rows {

		if rv.State == store.VersionCurrent || rv.State == store.VersionSupported {

			out = append(out, rv.Version)
		}
	}
	return out, nil
}

// Manifest decodes a stored release's manifest.
//
// The raw bytes are what was uploaded, so this can fail only if something has
// rewritten the row — which is worth an error rather than a silent zero value.
func Manifest(rel store.Release) (pkgvalidate.Manifest, error) {

	var m pkgvalidate.Manifest
	if err := json.Unmarshal([]byte(rel.Manifest), &m); err != nil {

		return pkgvalidate.Manifest{}, fmt.Errorf("release: manifest of %s does not parse: %w", rel.ID, err)
	}
	if m.Healthcheck.Path == "" {

		m.Healthcheck = pkgvalidate.DefaultHealthcheck()
	}
	return m, nil
}
