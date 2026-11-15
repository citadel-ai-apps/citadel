// Package config holds the control plane's runtime configuration.
//
// The defaults describe a single-host deployment with everything under
// /srv/citadel.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config is the whole knob set. Loaded from JSON, with every field defaulted.
type Config struct {
	// PBRoot is the §7 on-disk root.
	PBRoot string `json:"pb_root"`
	// SocketPath is the control-plane API's unix socket. Never a TCP address:
	// design §8.4 requires the API to be unreachable from any tenant bridge.
	SocketPath string `json:"socket_path"`
	// AppsDomain suffixes every tenant hostname (subdomain routing).
	AppsDomain string `json:"apps_domain"`

	// TenantRuntime is the OCI runtime for tenant containers. D2 decided runsc,
	// and Validate accepts nothing else (INV-1).
	TenantRuntime string `json:"tenant_runtime"`
	// UsernsRemap, when true, requires the daemon to have userns-remap enabled
	// and chowns data dirs to base+10001. D3 decided yes.
	UsernsRemap bool `json:"userns_remap"`
	// SeccompProfile and AppArmorProfile apply only under runc; runsc ignores
	// per-container seccomp and supplies its own filter (design.md §5).
	SeccompProfile  string `json:"seccomp_profile"`
	AppArmorProfile string `json:"apparmor_profile"`

	// DigestsFile is the images/pb-hardened/digests.txt hand-off to
	// runtime_version.image_digest (§5). Digests, never tags.
	DigestsFile  string `json:"digests_file"`
	HardeningRev int    `json:"hardening_rev"`
	Arch         string `json:"arch"`

	// SubnetPool is carved into /29s, one per tenant.
	SubnetPool string `json:"subnet_pool"`
	// ReservedSubnets are never allocated. test/netprobe owns 10.213.0.0/29.
	ReservedSubnets []string `json:"reserved_subnets"`

	// EdgeContainer, EdgeImage and EdgeAdminDir describe the Caddy edge.
	//
	// EdgeImage and EgressProxyImage are digest references. Left empty, each
	// is resolved at Load from its digests file — the newest entry for this
	// host's architecture, as `make edge-image` / `make egress-image` record
	// it — the same hand-off pb-hardened uses (§5). A tag is refused unless
	// AllowUnpinnedImages says so: these two containers parse every tenant's
	// traffic, and a tag is whatever was pushed under it last.
	EdgeContainer string `json:"edge_container"`
	EdgeImage     string `json:"edge_image"`
	// EdgeDigestsFile and EgressDigestsFile are where the defaults come from.
	EdgeDigestsFile   string `json:"edge_digests_file"`
	EgressDigestsFile string `json:"egress_digests_file"`
	// AllowUnpinnedImages accepts a tag for edge_image or egress_proxy_image.
	AllowUnpinnedImages bool `json:"allow_unpinned_images"`
	// Warnings are things Load decided that the operator should hear about,
	// logged at start-up. Not configuration.
	Warnings     []string `json:"-"`
	EdgeAdminDir string   `json:"edge_admin_dir"`
	EdgeHTTPPort int      `json:"edge_http_port"`

	// EgressNetwork is the ONE non-internal network in the platform (§9.4). A
	// tenant joins it only while it holds an active egress grant, and it
	// contains nothing but the forward proxy.
	EgressNetwork string `json:"egress_network"`
	// EgressBridge must NOT match config.BridgeWildcard. The host-protection
	// INPUT drop matches `br-t-+`, and a proxy bridge inside that wildcard
	// would lose the host path its own container needs.
	EgressBridge string `json:"egress_bridge"`
	// EgressSubnet is explicit for the same reason tenant subnets are: the
	// DOCKER-USER accept and the proxy's source-IP ACL are written against
	// these addresses (§8.1).
	EgressSubnet string `json:"egress_subnet"`
	// The forward proxy itself. A platform container: runc, not runsc.
	EgressProxyContainer string `json:"egress_proxy_container"`
	EgressProxyImage     string `json:"egress_proxy_image"`
	EgressProxyPort      int    `json:"egress_proxy_port"`
	// EgressSNIEnforce adds the §9.4 ClientHello check on top of the CONNECT
	// target. Peek-at-step1 only: no bumping, no certificate injection, no
	// MITM. Turned off automatically, loudly, if the proxy build has no
	// ssl_bump support.
	EgressSNIEnforce bool `json:"egress_sni_enforce"`

	// Host-side log collection (§15).
	LogMaxBytes int64 `json:"log_max_bytes"`
	LogKeep     int   `json:"log_keep"`

	// Per-tenant rate limits at the edge (§10), separately for the API and the
	// admin UI. Enforced by the rate_limit handler in the custom edge image.
	RateAPIEvents   int      `json:"rate_api_events"`
	RateAPIWindow   Duration `json:"rate_api_window"`
	RateAdminEvents int      `json:"rate_admin_events"`
	RateAdminWindow Duration `json:"rate_admin_window"`

	// Tenant resource defaults (§4 sizing, D9).
	DefaultCPUs    float64 `json:"default_cpus"`
	DefaultMemMiB  int     `json:"default_mem_mib"`
	DefaultDiskMiB int     `json:"default_disk_mib"`
	DefaultBodyCap string  `json:"default_body_cap"`
	PidsLimit      int     `json:"pids_limit"`

	// ReconcileInterval is the §8.3 tick.
	ReconcileInterval Duration `json:"reconcile_interval"`
	// HealthTimeout bounds the wait for a tenant to become healthy.
	HealthTimeout Duration `json:"health_timeout"`
	// AttestInterval is how often every tenant is attested from the host
	// (§14.5). Not on the 5-second tick: an attestation reads two proxies and
	// the Docker daemon per tenant, and an incident is caught within a tick by
	// the unbacked-rule check regardless, which generates a report immediately.
	AttestInterval Duration `json:"attest_interval"`
	// AnchorInterval is how often the audit chain head is signed and written
	// where the control plane cannot retract it (§14.4). Shortening it shortens
	// the window in which history is only as trustworthy as this host.
	AnchorInterval Duration `json:"anchor_interval"`

	// RoutineBackupInterval is how often every running tenant gets a `routine`
	// snapshot (§11: nightly, kept 7 days). Taken live via VACUUM INTO, so it
	// costs the tenant no downtime and can therefore be missed without anyone
	// noticing — which is why the fleet view reports backup age.
	RoutineBackupInterval Duration `json:"routine_backup_interval"`
	// RoutineBackupWindow restricts routine backups to a local-time window,
	// "HH:MM-HH:MM". Empty means any time. A VACUUM INTO of a busy 2 GiB
	// database competes with the tenant's own IO, so the default keeps it away
	// from business hours.
	RoutineBackupWindow string `json:"routine_backup_window"`
	// BackupSweepInterval is how often retention is enforced (§11). Frequent and
	// cheap: it is a query plus a handful of unlinks, and the sweep is the only
	// thing standing between a 7-day retention policy and a full disk.
	BackupSweepInterval Duration `json:"backup_sweep_interval"`
	// BackupTimeout bounds one tenant's routine snapshot. The pass is serial,
	// and the live copy runs inside the tenant's own sandbox: without a bound,
	// one tenant whose copy never finishes stops every other tenant's backup.
	BackupTimeout Duration `json:"backup_timeout"`

	// RehearsalTimeout bounds one rehearsal: copy, boot, probe, teardown (§12).
	RehearsalTimeout Duration `json:"rehearsal_timeout"`
	// RehearsalHold keeps a finished rehearsal up this long before teardown.
	// Zero, the default, in production. It exists for the acceptance suite: a
	// rehearsal that fails on its hooks lives about a second, too short to
	// inspect the isolation it is supposed to prove.
	RehearsalHold Duration `json:"rehearsal_hold"`
	// UpgradeTimeout bounds a whole upgrade job. A job past it is failed by the
	// reaper rather than resumed — resuming a one-way migration from an unknown
	// point is worse than stopping and asking (INV-4).
	UpgradeTimeout Duration `json:"upgrade_timeout"`
	// MaxConcurrentUpgrades caps upgrades in flight across the fleet. Each one
	// is an mkfs, a multi-gigabyte copy and a container boot; an EOL sweep must
	// not start twenty at once.
	MaxConcurrentUpgrades int `json:"max_concurrent_upgrades"`
	// ProbeImage is the digest of the rehearsal probe image. Left empty, it is
	// resolved at Load from ProbeDigestsFile, as `make probe-image` records it.
	// Unlike the edge and proxy there is no unpinned fallback (the probe is
	// built from this tree), so nothing resolvable leaves it empty, which
	// disables rehearsal — reported by the upgrade path rather than silently
	// skipped, because an upgrade that quietly stops rehearsing is the failure
	// §12 is built to prevent.
	ProbeImage       string `json:"probe_image"`
	ProbeDigestsFile string `json:"probe_digests_file"`

	// EOLNagInterval is how often a tenant on a deprecated version is told
	// (§12).
	EOLNagInterval Duration `json:"eol_nag_interval"`
	// EOLGrace is how long past a version's EOL date the platform waits before
	// forcing the upgrade itself.
	EOLGrace Duration `json:"eol_grace"`
	// EOLForceBatch caps forced upgrades started per tick, so an EOL date does
	// not restart the fleet at once.
	EOLForceBatch int `json:"eol_force_batch"`

	// PortalAddr is the portal's own TCP listener. The API stays on the unix
	// socket (§8.4); the portal cannot, because a browser cannot dial one.
	// Tenant bridges are kept off host ports by the host-protection INPUT drop,
	// which is what makes a host listener acceptable here at all — and why the
	// portal is NOT published through the edge Caddy, which sits on every
	// tenant bridge.
	PortalAddr string `json:"portal_addr"`
	// PortalAllowPublic must be set explicitly to bind the portal on a
	// non-loopback address. An operator UI should not become world-reachable
	// through a default.
	PortalAllowPublic bool `json:"portal_allow_public"`
	// PortalSecureCookies marks the session cookie Secure and names it with
	// the __Host- prefix, so a browser only ever sends it over TLS and only
	// to this exact origin. Set it whenever the portal is reached over HTTPS
	// (a TLS-terminating proxy in front of a public portal). Off by default
	// because the development portal is plain HTTP, where a Secure cookie is
	// never sent back.
	PortalSecureCookies bool `json:"portal_secure_cookies"`
	// PortalSessionTTL bounds a signed session cookie.
	PortalSessionTTL Duration `json:"portal_session_ttl"`
	// TokenTTL is the default lifetime of an API token. Like a grant, every
	// token expires (§14.2).
	TokenTTL Duration `json:"token_ttl"`

	// MaxPackageBytes and MaxPackageFiles are the §6 upload caps.
	MaxPackageBytes int64 `json:"max_package_bytes"`
	MaxPackageFiles int   `json:"max_package_files"`
}

// Duration is a time.Duration that marshals as a Go duration string.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {

	var s string
	if err := json.Unmarshal(b, &s); err != nil {

		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {

		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {

	return json.Marshal(time.Duration(d).String())
}

// Default returns the single-host configuration, with production sizing for
// disk.
func Default() Config {

	arch := "amd64"
	if runtime.GOARCH == "arm64" {

		arch = "arm64"
	}
	return Config{
		PBRoot:          "/srv/citadel",
		SocketPath:      "/run/citadel/control.sock",
		AppsDomain:      "apps.localhost",
		TenantRuntime:   "runsc",
		UsernsRemap:     true,
		SeccompProfile:  "images/pb-hardened/seccomp.json",
		AppArmorProfile: "pb-hardened",
		DigestsFile:     "images/pb-hardened/digests.txt",
		HardeningRev:    3,
		Arch:            arch,
		SubnetPool:      "10.213.0.0/16",
		ReservedSubnets: []string{"10.213.0.0/29"},
		EdgeContainer:   "citadel-caddy",
		// Empty: resolved from EdgeDigestsFile at Load.
		EdgeDigestsFile: "images/edge-caddy/digests.txt",
		EdgeHTTPPort:    80,

		EgressNetwork: "v2p-egress",
		// Not br-t-*: that prefix belongs to the host-protection wildcard and
		// the proxy is a platform container, not a tenant.
		EgressBridge:         "br-v2p-egr",
		EgressSubnet:         "10.214.0.0/24",
		EgressProxyContainer: "citadel-squid",
		// Built here, not pulled: verified on the host, the easily pulled
		// distro images ship Squid without --with-openssl and reject
		// `at_step`, which leaves only CONNECT-target filtering.
		// `make egress-image` builds one that has it and records its digest;
		// the image itself is resolved from that file at Load.
		EgressDigestsFile: "images/egress-proxy/digests.txt",
		EgressProxyPort:   3128,
		EgressSNIEnforce:  true,

		LogMaxBytes: 16 << 20,
		LogKeep:     5,

		RateAPIEvents:     600,
		RateAPIWindow:     Duration(time.Minute),
		RateAdminEvents:   60,
		RateAdminWindow:   Duration(time.Minute),
		DefaultCPUs:       1.0,
		DefaultMemMiB:     256,
		DefaultDiskMiB:    2048,
		DefaultBodyCap:    "32MB",
		PidsLimit:         128,
		ReconcileInterval: Duration(5 * time.Second),
		HealthTimeout:     Duration(60 * time.Second),
		AttestInterval:    Duration(6 * time.Hour),
		AnchorInterval:    Duration(time.Hour),

		RoutineBackupInterval: Duration(24 * time.Hour),
		RoutineBackupWindow:   "02:00-04:00",
		BackupSweepInterval:   Duration(time.Hour),
		BackupTimeout:         Duration(15 * time.Minute),
		RehearsalTimeout:      Duration(10 * time.Minute),
		UpgradeTimeout:        Duration(30 * time.Minute),
		MaxConcurrentUpgrades: 2,
		EOLNagInterval:        Duration(7 * 24 * time.Hour),
		EOLGrace:              Duration(14 * 24 * time.Hour),
		EOLForceBatch:         3,
		// Empty ProbeImage: resolved from ProbeDigestsFile at Load.
		ProbeDigestsFile: "images/rehearse-probe/digests.txt",

		PortalAddr:       "127.0.0.1:8080",
		PortalSessionTTL: Duration(12 * time.Hour),
		TokenTTL:         Duration(90 * 24 * time.Hour),
		MaxPackageBytes:  50 << 20,
		MaxPackageFiles:  2000,
	}
}

// Load reads path over the defaults. An empty path returns the defaults.
func Load(path string) (Config, error) {

	cfg := Default()
	if path != "" {

		b, err := os.ReadFile(path)
		if err != nil {

			return Config{}, err
		}
		if err := json.Unmarshal(b, &cfg); err != nil {

			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if cfg.EdgeAdminDir == "" {

		cfg.EdgeAdminDir = filepath.Join(cfg.PBRoot, "caddy", "admin")
	}
	if err := cfg.resolveImages(); err != nil {

		return Config{}, err
	}
	return cfg, cfg.Validate()
}

// Unpinned fallbacks, used only when nothing has been built on this host. They
// work — the edge without per-tenant rate limits, the proxy only if it was
// built under that tag — and Load says so in Warnings.
const (
	fallbackEdgeImage   = "caddy:2"
	fallbackEgressImage = "v2p-squid:6-r3"
)

// resolveImages fills in the edge, egress proxy and rehearsal probe images.
//
// An empty image is resolved from its digests file. A configured one must be a
// digest unless allow_unpinned_images is set. Nothing resolvable falls back to
// the unpinned tag with a warning rather than refusing to start: a fresh host
// that has not built the images yet still comes up, and says why it is not
// pinned.
func (c *Config) resolveImages() error {

	for _, img := range []struct {
		field    *string
		key      string
		file     string
		fallback string
		builds   string
	}{
		{&c.EdgeImage, "edge_image", c.EdgeDigestsFile, fallbackEdgeImage, "make edge-image"},
		{&c.EgressProxyImage, "egress_proxy_image", c.EgressDigestsFile, fallbackEgressImage, "make egress-image"},
	} {

		if *img.field != "" {

			if !IsDigestRef(*img.field) && !c.AllowUnpinnedImages {

				return fmt.Errorf("%s %q is not a digest reference; use the digest `%s` prints, "+
					"or set allow_unpinned_images", img.key, *img.field, img.builds)
			}
			continue
		}
		ref, err := LatestDigest(img.file, c.Arch)
		if err != nil || ref == "" {

			*img.field = img.fallback
			reason := "no " + c.Arch + " entry"
			if err != nil {

				reason = err.Error()
			}
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"%s is the unpinned tag %s: %s in %s (run `%s` to build and record one)",
				img.key, img.fallback, reason, img.file, img.builds))
			continue
		}
		*img.field = ref
	}

	// The probe: no fallback tag, so unresolved means rehearsal is off. Its
	// digest check stays in Validate — allow_unpinned_images does not cover it.
	if c.ProbeImage == "" {

		ref, err := LatestDigest(c.ProbeDigestsFile, c.Arch)
		if err != nil || ref == "" {

			reason := "no " + c.Arch + " entry"
			if err != nil {

				reason = err.Error()
			}
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"probe_image is unset, so upgrades cannot be rehearsed: %s in %s (run `make probe-image` to build and record one)",
				reason, c.ProbeDigestsFile))

		} else {

			c.ProbeImage = ref
		}
	}
	return nil
}

// IsDigestRef reports whether ref names an image by content digest.
func IsDigestRef(ref string) bool { return strings.Contains(ref, "@sha256:") }

// LatestDigest returns the last digest recorded for arch in a digests file,
// whose lines end "... <arch> <ref>" (images/*/digests.txt). Later lines are
// newer builds.
func LatestDigest(path, arch string) (string, error) {

	if path == "" {

		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {

		return "", err
	}
	ref := ""
	for _, line := range strings.Split(string(b), "\n") {

		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {

			continue
		}
		if f[len(f)-2] == arch && IsDigestRef(f[len(f)-1]) {

			ref = f[len(f)-1]
		}
	}
	return ref, nil
}

// Validate rejects a configuration that would break a §9 rule.
func (c Config) Validate() error {

	if !filepath.IsAbs(c.PBRoot) {

		return fmt.Errorf("pb_root %q must be absolute", c.PBRoot)
	}
	if !filepath.IsAbs(c.SocketPath) {

		return fmt.Errorf("socket_path %q must be absolute; a TCP listener is not acceptable", c.SocketPath)
	}
	// Tenant code is hostile (INV-1), and under Docker the boundary is the
	// kernel unless a user-space kernel sits in front of it. runc would
	// silently downgrade every tenant on the host, so it is not a setting.
	if c.TenantRuntime != "runsc" {

		return fmt.Errorf("tenant_runtime %q is not allowed: tenant containers run under gVisor (runsc), INV-1 and D2", c.TenantRuntime)
	}
	pool, err := netip.ParsePrefix(c.SubnetPool)
	if err != nil {

		return fmt.Errorf("subnet_pool: %w", err)
	}
	if !pool.Addr().Is4() || pool.Bits() > 29 {

		return fmt.Errorf("subnet_pool %q must be IPv4 and no smaller than /29", c.SubnetPool)
	}
	for _, r := range c.ReservedSubnets {

		if _, err := netip.ParsePrefix(r); err != nil {

			return fmt.Errorf("reserved_subnets %q: %w", r, err)
		}
	}
	if c.ReconcileInterval.D() <= 0 {

		return fmt.Errorf("reconcile_interval must be positive")
	}
	if c.AttestInterval.D() <= 0 || c.AnchorInterval.D() <= 0 {

		return fmt.Errorf("attest_interval and anchor_interval must be positive")
	}
	if err := c.validateUpgrade(); err != nil {

		return err
	}
	if err := c.validateEgress(pool); err != nil {

		return err
	}
	if err := c.validatePortal(); err != nil {

		return err
	}
	if c.MaxPackageBytes <= 0 || c.MaxPackageFiles <= 0 {

		return fmt.Errorf("max_package_bytes and max_package_files must be positive")
	}
	return nil
}

// validateUpgrade checks the backup and upgrade knobs (§11, §12).
func (c Config) validateUpgrade() error {

	if c.RoutineBackupInterval.D() <= 0 || c.BackupSweepInterval.D() <= 0 || c.BackupTimeout.D() <= 0 {

		return fmt.Errorf("routine_backup_interval, backup_sweep_interval and backup_timeout must be positive")
	}
	if _, _, err := ParseWindow(c.RoutineBackupWindow); err != nil {

		return fmt.Errorf("routine_backup_window: %w", err)
	}
	if c.RehearsalTimeout.D() <= 0 || c.UpgradeTimeout.D() <= 0 {

		return fmt.Errorf("rehearsal_timeout and upgrade_timeout must be positive")
	}
	if c.RehearsalTimeout.D() >= c.UpgradeTimeout.D() {

		// The rehearsal happens inside the job, so a rehearsal budget at or
		// above the job budget means the reaper fails the job before the
		// rehearsal it is waiting for can report.
		return fmt.Errorf("rehearsal_timeout must be shorter than upgrade_timeout")
	}
	if c.RehearsalHold.D() < 0 || c.RehearsalHold.D() >= c.RehearsalTimeout.D() {

		// The hold runs inside the rehearsal's own budget; one that fills it
		// turns every rehearsal into a timeout.
		return fmt.Errorf("rehearsal_hold must be zero or more and shorter than rehearsal_timeout")
	}
	if c.MaxConcurrentUpgrades <= 0 || c.EOLForceBatch <= 0 {

		return fmt.Errorf("max_concurrent_upgrades and eol_force_batch must be positive")
	}
	if c.EOLNagInterval.D() <= 0 || c.EOLGrace.D() < 0 {

		return fmt.Errorf("eol_nag_interval must be positive and eol_grace must not be negative")
	}
	if c.ProbeImage != "" && !IsDigestRef(c.ProbeImage) {

		return fmt.Errorf("probe_image %q is not a digest reference", c.ProbeImage)
	}
	return nil
}

// ParseWindow parses an "HH:MM-HH:MM" local-time window into minutes past
// midnight. An empty string means "any time" and returns a zero-width window
// callers treat as always open.
//
// A window that wraps midnight ("22:00-04:00") is legal and common, so the
// comparison is not a simple range test — see InWindow.
func ParseWindow(s string) (start, end int, err error) {

	if strings.TrimSpace(s) == "" {

		return 0, 0, nil
	}
	from, to, ok := strings.Cut(s, "-")
	if !ok {

		return 0, 0, fmt.Errorf("%q is not HH:MM-HH:MM", s)
	}
	if start, err = parseHM(from); err != nil {

		return 0, 0, err
	}
	if end, err = parseHM(to); err != nil {

		return 0, 0, err
	}
	return start, end, nil
}

func parseHM(s string) (int, error) {

	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {

		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// InWindow reports whether t falls inside the configured routine-backup window.
// An unset or zero-width window is always open.
func (c Config) InWindow(t time.Time) bool {

	start, end, err := ParseWindow(c.RoutineBackupWindow)
	if err != nil || start == end {

		return true
	}
	m := t.Hour()*60 + t.Minute()
	if start < end {

		return m >= start && m < end
	}
	// Wraps midnight.
	return m >= start || m < end
}

// validateEgress refuses a configuration in which the one non-internal network
// in the platform would be mistaken for a tenant bridge, or would overlap the
// address space the tenant allocator hands out.
//
// Both failures are silent at runtime and expensive to diagnose: an egress
// bridge inside the `br-t-+` wildcard is dropped by the host-protection INPUT rule, and
// an overlapping subnet makes a DOCKER-USER accept written for one tenant match
// another's address.
func (c Config) validateEgress(pool netip.Prefix) error {

	if strings.HasPrefix(c.EgressBridge, "br-t-") {

		return fmt.Errorf("egress_bridge %q starts with br-t-, which the host-protection INPUT drop matches "+
			"as a tenant bridge; the egress proxy would lose its own host path", c.EgressBridge)
	}
	if len(c.EgressBridge) > ifnamsiz {

		return fmt.Errorf("egress_bridge %q is %d chars; the kernel limit is %d",
			c.EgressBridge, len(c.EgressBridge), ifnamsiz)
	}
	egress, err := netip.ParsePrefix(c.EgressSubnet)
	if err != nil {

		return fmt.Errorf("egress_subnet: %w", err)
	}
	if !egress.Addr().Is4() {

		return fmt.Errorf("egress_subnet %q must be IPv4", c.EgressSubnet)
	}
	if egress.Overlaps(pool) {

		return fmt.Errorf("egress_subnet %q overlaps subnet_pool %q; a rule written for one tenant "+
			"would match another's address", c.EgressSubnet, c.SubnetPool)
	}
	for _, r := range c.ReservedSubnets {

		p, err := netip.ParsePrefix(r)
		if err != nil {

			continue // already reported by Validate
		}
		if egress.Overlaps(p) {

			return fmt.Errorf("egress_subnet %q overlaps reserved subnet %q", c.EgressSubnet, r)
		}
	}
	if c.EgressProxyPort <= 0 || c.EgressProxyPort > 65535 {

		return fmt.Errorf("egress_proxy_port %d is not a port", c.EgressProxyPort)
	}
	if c.LogMaxBytes <= 0 || c.LogKeep < 0 {

		return fmt.Errorf("log_max_bytes must be positive and log_keep must not be negative")
	}
	return nil
}

// ifnamsiz is the kernel's interface-name limit, minus the terminating NUL.
const ifnamsiz = 15

// validatePortal keeps the operator UI off a public address unless someone said
// so out loud. Binding 0.0.0.0 is a deliberate, reviewable choice — it must not
// be something a half-filled config file does by accident.
func (c Config) validatePortal() error {

	if c.PortalAddr == "" {

		return nil // portal disabled
	}
	host, _, err := net.SplitHostPort(c.PortalAddr)
	if err != nil {

		return fmt.Errorf("portal_addr %q must be host:port: %w", c.PortalAddr, err)
	}
	if c.PortalSessionTTL.D() <= 0 {

		return fmt.Errorf("portal_session_ttl must be positive")
	}
	if host == "" {

		return fmt.Errorf("portal_addr %q has no host; set 127.0.0.1 or an explicit address", c.PortalAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {

		return fmt.Errorf("portal_addr host %q is not an IP address", host)
	}
	if !addr.IsLoopback() && !c.PortalAllowPublic {

		return fmt.Errorf("portal_addr %q is not loopback; set portal_allow_public to bind it deliberately", c.PortalAddr)
	}
	return nil
}

// PortalEnabled reports whether the portal listener should be started.
func (c Config) PortalEnabled() bool { return c.PortalAddr != "" }

// SessionKeyPath is the HMAC key that signs portal session cookies. Rotating
// (or deleting) it invalidates every live session.
func (c Config) SessionKeyPath() string {

	return filepath.Join(c.PBRoot, "control", "portal-session.key")
}

// StateDB is the control-plane SQLite path.
func (c Config) StateDB() string { return filepath.Join(c.PBRoot, "control", "state.db") }

// KeysDir holds per-tenant encryption keys, 0600.
func (c Config) KeysDir() string { return filepath.Join(c.PBRoot, "control", "keys") }

// ArtifactsDir holds content-addressed, immutable, unpacked releases.
func (c Config) ArtifactsDir() string { return filepath.Join(c.PBRoot, "artifacts") }

// TenantsDir holds one directory per tenant.
func (c Config) TenantsDir() string { return filepath.Join(c.PBRoot, "tenants") }

// TenantDir is one tenant's directory.
func (c Config) TenantDir(id string) string { return filepath.Join(c.TenantsDir(), id) }

// BackupsDir holds snapshots.
func (c Config) BackupsDir() string { return filepath.Join(c.PBRoot, "backups") }

// ScratchDir holds throwaway per-job working directories — today, the data
// copies an upgrade rehearsal boots against (§12). Deliberately not under
// tenants/, which is live tenant state and is orphan-scanned every tick.
func (c Config) ScratchDir() string { return filepath.Join(c.PBRoot, "scratch") }

// LogsDir holds host-side collected container logs.
func (c Config) LogsDir() string { return filepath.Join(c.PBRoot, "logs") }

// TenantLogDir is one tenant's collected stdout/stderr (§15).
func (c Config) TenantLogDir(id string) string { return filepath.Join(c.LogsDir(), id) }

// EgressLogDir is bind-mounted into the proxy as /var/log/squid, so the control
// plane reads the access log as a file rather than parsing a container log
// stream. The underscore prefix keeps it out of the tenant-id namespace.
func (c Config) EgressLogDir() string { return filepath.Join(c.LogsDir(), "_egress") }

// EgressDir holds the generated proxy configuration, bind-mounted read-only.
func (c Config) EgressDir() string { return filepath.Join(c.PBRoot, "egress") }

// CaddyDir holds the edge's config and admin socket.
func (c Config) CaddyDir() string { return filepath.Join(c.PBRoot, "caddy") }

// SigningKeyPath holds the ed25519 key that signs chain anchors and access
// attestations (§7).
//
// Its limit is worth stating plainly: the key lives on this host, so an
// operator with root can sign whatever they like going forward. What they
// cannot do is retract an anchor already copied elsewhere, which is what bounds
// the tampering rather than preventing it.
func (c Config) SigningKeyPath() string {

	return filepath.Join(c.PBRoot, "control", "audit-signing.key")
}

// AuditDir holds the signed records that must outlive tenant data.
func (c Config) AuditDir() string { return filepath.Join(c.PBRoot, "audit") }

// AnchorsDir holds signed chain heads. Replicating this directory off the host
// is what turns the hash chain from a formality into tamper evidence; until
// that exists (§16, Later), an anchor here is only as trustworthy as the host.
func (c Config) AnchorsDir() string { return filepath.Join(c.AuditDir(), "anchors") }

// AttestationsDir holds signed access attestations, one subdirectory per
// tenant. A tenant's final report is kept after deletion as the closing record
// of what it could reach on the day it went away (§14.7).
func (c Config) AttestationsDir() string { return filepath.Join(c.AuditDir(), "attestations") }

// TenantAttestationDir is one tenant's report directory.
func (c Config) TenantAttestationDir(id string) string {

	return filepath.Join(c.AttestationsDir(), id)
}

// Hostname is the tenant's public name (subdomain, never a path prefix).
func (c Config) Hostname(slug string) string { return slug + "." + c.AppsDomain }

// ContainerName is the tenant's container. Caddy resolves this through Docker's
// embedded DNS on the tenant network, so it must match what proxyctl publishes.
func ContainerName(slug string) string { return "pb-" + slug }

// NetworkName is the tenant's internal network.
func NetworkName(slug string) string { return "t-" + slug }

// BridgeName must stay inside IFNAMSIZ (15) and must match the `br-t-+`
// wildcard the host-protection INPUT rule uses, or the tenant loses host protection.
func BridgeName(slug string) string { return "br-t-" + slug }

// BridgeWildcard is the iptables interface wildcard covering every tenant
// bridge. The trailing `+` is iptables syntax, not a shell glob.
const BridgeWildcard = "br-t-+"

// PocketBasePort is the port the hardened image's entrypoint serves on. The
// edge dials it, and the tenant's intra-network accept admits nothing else.
const PocketBasePort = "8090"

// MaxSlugLen is 15 (IFNAMSIZ) minus len("br-t-").
const MaxSlugLen = 10
