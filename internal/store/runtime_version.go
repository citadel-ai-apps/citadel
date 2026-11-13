package store

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// Runtime version lifecycle states (design §12).
const (
	VersionCurrent    = "current"
	VersionSupported  = "supported"
	VersionDeprecated = "deprecated"
	VersionEOL        = "eol"
)

// ErrVersionNotFound is returned for an unregistered PocketBase version.
var ErrVersionNotFound = errors.New("store: runtime version not registered")

// RuntimeVersion is one supported PocketBase version pinned to an image digest.
type RuntimeVersion struct {
	bun.BaseModel `bun:"table:runtime_version,alias:runtime_version" json:"-"`

	Version      string     `bun:"version,pk" json:"version"`
	HardeningRev int        `bun:"hardening_rev" json:"hardening_rev"`
	ImageDigest  string     `bun:"image_digest" json:"image_digest"`
	State        string     `bun:"state" json:"state"`
	EOLAt        *time.Time `bun:"eol_at,nullzero" json:"eol_at,omitempty"`
	ReleaseNotes string     `bun:"release_notes,nullzero" json:"release_notes,omitempty"`
	CreatedAt    time.Time  `bun:"created_at" json:"created_at"`
}

// Upgradable reports whether a tenant may move ONTO this version of their own
// accord. A deprecated version still runs and still takes patch updates, but
// nobody is moved onto a line the platform is trying to retire.
func (rv RuntimeVersion) Upgradable() bool {

	return rv.State == VersionCurrent || rv.State == VersionSupported
}

// UpsertRuntimeVersion registers or updates a version.
func UpsertRuntimeVersion(ctx context.Context, tx bun.Tx, rv RuntimeVersion) error {

	if !strings.Contains(rv.ImageDigest, "@sha256:") {

		// a retagged image would silently change what a tenant runs.
		return fmt.Errorf("store: image_digest %q is not a digest reference", rv.ImageDigest)
	}
	// The row only moves forward. A tenant on this version whose digest
	// differs from the row's is offered the row's image as an upgrade, which
	// is only sound if the row can never point at an older hardening rev.
	existing, err := GetRuntimeVersion(ctx, tx, rv.Version)
	switch {

	case errors.Is(err, ErrVersionNotFound):
	case err != nil:
		return err
	case rv.HardeningRev < existing.HardeningRev:
		return fmt.Errorf("%w: %s is registered at hardening rev %d; refusing rev %d",
			ErrHardeningRegress, rv.Version, existing.HardeningRev, rv.HardeningRev)
	}
	keepState := rv.State == ""
	if keepState {

		rv.State = VersionSupported
	}
	if rv.CreatedAt.IsZero() {

		rv.CreatedAt = time.Now().UTC()
	}
	// created_at is deliberately not updated: it records when the version was
	// first registered, not when its digest was last refreshed. Nor is the
	// lifecycle state, unless the caller set one: re-seeding digests at start-up
	// must not quietly move a deprecated or EOL version back to supported.
	q := tx.NewInsert().Model(&rv).
		On("CONFLICT (version) DO UPDATE").
		Set("hardening_rev = EXCLUDED.hardening_rev").
		Set("image_digest = EXCLUDED.image_digest")
	if !keepState {

		q = q.Set("state = EXCLUDED.state")
	}
	_, err = q.Exec(ctx)
	return err
}

// ErrHardeningRegress is a registration that would move a version's image to
// an older hardening rev.
var ErrHardeningRegress = errors.New("store: hardening revs only move forward")

// GetRuntimeVersion returns one registered version.
func GetRuntimeVersion(ctx context.Context, db bun.IDB, version string) (RuntimeVersion, error) {

	var rv RuntimeVersion
	err := db.NewSelect().Model(&rv).Where("version = ?", version).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {

		return RuntimeVersion{}, fmt.Errorf("%w: %s", ErrVersionNotFound, version)
	}
	if err != nil {

		return RuntimeVersion{}, err
	}
	return rv, nil
}

// ListRuntimeVersions returns every registered version.
func ListRuntimeVersions(ctx context.Context, db bun.IDB) ([]RuntimeVersion, error) {

	var out []RuntimeVersion
	err := db.NewSelect().Model(&out).Order("version").Scan(ctx)
	return out, err
}

// ErrEOLDateRequired is returned when a version is deprecated with no EOL date.
var ErrEOLDateRequired = errors.New("store: deprecating a version requires an EOL date")

// ErrBadVersionState is returned for a state outside the §12 lifecycle.
var ErrBadVersionState = errors.New("store: unknown runtime version state")

// ValidVersionState reports whether state is one of the four §12 states.
func ValidVersionState(state string) bool {

	switch state {

	case VersionCurrent, VersionSupported, VersionDeprecated, VersionEOL:
		return true
	}
	return false
}

// SetVersionState moves a version along the §12 lifecycle.
//
// Entering `deprecated` REQUIRES an EOL date. §12 publishes the date on entry
// to the state, and a deprecation with no date is a nag nobody can plan around
// — the tenant is told to move with no answer to "by when?", and the platform
// has no trigger for the forced upgrade that eventually follows.
func SetVersionState(ctx context.Context, tx bun.Tx, version, state string, eolAt *time.Time) error {

	if !ValidVersionState(state) {

		return fmt.Errorf("%w: %q", ErrBadVersionState, state)
	}
	rv, err := GetRuntimeVersion(ctx, tx, version)
	if err != nil {

		return err
	}
	if eolAt == nil {

		eolAt = rv.EOLAt
	}
	if (state == VersionDeprecated || state == VersionEOL) && eolAt == nil {

		return fmt.Errorf("%w: %s", ErrEOLDateRequired, version)
	}
	q := tx.NewUpdate().Model((*RuntimeVersion)(nil)).
		Set("state = ?", state).
		Where("version = ?", version)
	if eolAt != nil {

		q = q.Set("eol_at = ?", eolAt.UTC())
	}
	res, err := q.Exec(ctx)
	if err != nil {

		return fmt.Errorf("store: set runtime version %s state: %w", version, err)
	}
	return checkOneRow(res, ErrVersionNotFound, version)
}

// ListVersionTenants returns the tenants pinned to one runtime version, which
// is the fleet view's "who is blocking the next EOL date?".
func ListVersionTenants(ctx context.Context, db bun.IDB, version string) ([]Tenant, error) {

	var out []Tenant
	err := db.NewSelect().Model(&out).
		Where("runtime_version = ?", version).
		Where("desired_state != ?", DesiredDeleted).
		Order("slug").
		Scan(ctx)
	return out, err
}

// DigestEntry is one line of images/pb-hardened/digests.txt.
type DigestEntry struct {
	Version      string
	HardeningRev int
	Arch         string
	Ref          string
}

// ParseDigestsFile reads the `<version> h<rev> <arch> <ref>` format written by
// `make image` (§5). It is the hand-off from the image build to
// runtime_version.image_digest, and the only place tags become digests.
func ParseDigestsFile(path string) ([]DigestEntry, error) {

	f, err := os.Open(path)
	if err != nil {

		return nil, err
	}
	defer f.Close()

	var out []DigestEntry
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {

		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {

			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 4 {

			return nil, fmt.Errorf("%s:%d: expected `<version> h<rev> <arch> <ref>`, got %q", path, line, text)
		}
		rev, err := strconv.Atoi(strings.TrimPrefix(fields[1], "h"))
		if err != nil {

			return nil, fmt.Errorf("%s:%d: bad hardening rev %q", path, line, fields[1])
		}
		if !strings.Contains(fields[3], "@sha256:") {

			return nil, fmt.Errorf("%s:%d: %q is not a digest reference", path, line, fields[3])
		}
		out = append(out, DigestEntry{Version: fields[0], HardeningRev: rev, Arch: fields[2], Ref: fields[3]})
	}
	return out, sc.Err()
}

// SelectDigest picks the last entry matching version, rev and arch — the same
// `grep … | tail -1` semantics, so a rebuilt image wins over its predecessor
// in the file.
func SelectDigest(entries []DigestEntry, version string, rev int, arch string) (string, error) {

	ref := ""
	for _, e := range entries {

		if e.Version == version && e.HardeningRev == rev && e.Arch == arch {

			ref = e.Ref
		}
	}
	if ref == "" {

		return "", fmt.Errorf("no digest for %s h%d %s; run `make image PB_VERSION=%s`", version, rev, arch, version)
	}
	return ref, nil
}
