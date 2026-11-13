// Package egressctl runs the forward proxy that is the only way out of the
// sandbox (design §9.4).
//
// Three things about this package are load-bearing:
//
//   - Its allowlist is generated from ACTIVE access_grant rows and from nothing
//     else. The tenant's manifest is a request; `release.egress_hosts`
//     records what was asked for, never what is allowed.
//   - It is not the boundary. The DOCKER-USER rules in internal/netpolicy are.
//     A hostile hook ignores HTTP_PROXY and opens a raw socket; what stops it is
//     a netfilter DROP, and this proxy only decides which hostnames a
//     cooperating connection may reach.
//   - It never terminates TLS. `peek` reads the ClientHello, `splice` hands the
//     connection through, and no certificate is generated or injected. The
//     tenant validates the real origin certificate, which is why §5 puts a CA
//     bundle in the hardened image.
package egressctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
)

//go:embed squid.conf.tmpl
var templateFS embed.FS

// Paths inside the proxy container. The configuration is read-only to it: a
// proxy that can rewrite its own allowlist is not an allowlist.
const (
	// A DIRECTORY, not the file. Bind-mounting the file pins the container to
	// one inode, and render() replaces the inode on every write (write-temp,
	// rename) — so the container would read the original allowlist forever
	// while the host showed the current one. This cost an afternoon
	// exactly that (design.md §9.4).
	confMountDir = "/etc/squid/v2p"
	logMount     = "/var/log/squid"
	confName     = "squid.conf"
	// squidUID is the uid the proxy image drops to (31 in Alpine). Under userns-remap
	// the log directory has to be chowned to usernsBase+squidUID or the daemon
	// FATALs on its own access log before it serves anything — the same trap
	// proxyctl documents for Caddy's admin directory.
	squidUID = 31
)

// SquidDomains turns a tenant's granted hosts into the domain list Squid is
// given.
//
// A grant for "*.example.com" is written ".example.com", which is how Squid
// spells "this domain and everything under it"; written literally, the
// asterisk is part of a hostname nothing ever has, and an approved wildcard
// silently allowed nothing. Squid has no subdomains-only form for dstdomain,
// so the wildcard also admits the apex itself.
//
// A host the same list already covers is left out — "api.example.com" next to
// ".example.com", or "example.com" itself. Squid warns about such an entry and
// DROPS one of the two to keep its lookup tree predictable, so the running
// allowlist would no longer show what was granted. internal/attest reads a
// covered host as in effect through its wildcard.
func SquidDomains(hosts []string) []string {

	var wild []string
	for _, h := range hosts {

		if strings.HasPrefix(h, "*.") {

			wild = append(wild, h[2:])
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {

		entry := h
		if strings.HasPrefix(h, "*.") {

			entry = h[1:]
			if coveredBy(h[2:], wild, true) {

				continue // a narrower wildcard inside a wider one
			}

		} else if coveredBy(h, wild, false) {

			continue
		}
		if !seen[entry] {

			seen[entry] = true
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}

// coveredBy reports whether host falls under one of the wildcard bases. With
// strict, host equal to a base does not count, so a wildcard does not cover
// itself.
func coveredBy(host string, bases []string, strict bool) bool {

	for _, b := range bases {

		if strings.HasSuffix(host, "."+b) || (!strict && host == b) {

			return true
		}
	}
	return false
}

// Resource bounds for the proxy container.
var proxyPidsLimit int64 = 256

const proxyMemoryBytes = 1 << 30

// TenantACL is one tenant's entry in the generated allowlist.
type TenantACL struct {
	TenantID string
	IP       string
	Hosts    []string
}

// ACLName is the tenant id with everything Squid will not accept in an ACL name
// replaced. Squid ACL names allow a narrow character set, and a tenant slug is
// user-supplied.
func (t TenantACL) ACLName() string { return aclSafe.ReplaceAllString(t.TenantID, "_") }

var aclSafe = regexp.MustCompile(`[^A-Za-z0-9_]`)

// Controller owns the proxy container and its generated configuration.
type Controller struct {
	cfg        config.Config
	docker     client.APIClient
	log        *slog.Logger
	usernsBase int

	tmpl *template.Template
	// sni records whether the running proxy build understands ssl_bump. Probed
	// once against the real binary rather than assumed from the image tag,
	// because a build without --with-openssl accepts the rest of the
	// configuration and rejects only these lines.
	sni      bool
	sniKnown bool
	// hostAddrs lists the host's own addresses for the proxy's destination
	// deny. A field so tests can render deterministically.
	hostAddrs func() []netip.Addr

	// mu serialises Ensure: two egress passes rendering at once write the same
	// temporary file and can reload the proxy onto a half-written allowlist.
	mu sync.Mutex
	// lastWritten is the allowlist this controller last wrote (or found
	// already correct). A file on disk that differs from it was edited by
	// somebody else — see Tamper.
	lastWritten []byte
}

// EnsureResult is what one Ensure call did.
type EnsureResult struct {
	// Changed is set when a new allowlist was written.
	Changed bool
	// Tampered is set when the allowlist on disk was not the one this
	// controller last wrote.
	Tampered *Tamper
}

// Tamper describes an allowlist edited outside the control plane.
//
// The file is regenerated from grants regardless — a proxy cannot be left
// admitting hosts nobody approved, so unlike an unbacked firewall rule this is
// not left in place (§14.5). What must not happen is that the regeneration
// erases the evidence silently: an entry with no grant behind it is
// enforcement_without_grant, and the record of it is the only thing left once
// the file has been rewritten. The caller audits it.
type Tamper struct {
	// FoundDigest and WantDigest are the sha256 of the file as found and as
	// last written.
	FoundDigest string
	WantDigest  string
	// Added and Removed are the lines that differ, at most maxTamperLines each.
	Added   []string
	Removed []string
	// EvidencePath is where the file as found was kept, before it was
	// overwritten; empty if it could not be written.
	EvidencePath string
}

// maxTamperLines bounds what a tamper report carries into the audit record.
const maxTamperLines = 20

// New returns a Controller.
func New(cfg config.Config, docker client.APIClient, log *slog.Logger, usernsBase int) *Controller {

	tmpl := template.Must(template.ParseFS(templateFS, "squid.conf.tmpl"))
	return &Controller{cfg: cfg, docker: docker, log: log, usernsBase: usernsBase, tmpl: tmpl,
		hostAddrs: interfaceAddrs}
}

// interfaceAddrs is every address on the host's interfaces. The control plane
// runs in the host's network namespace, so this is the host as the proxy
// would reach it.
func interfaceAddrs() []netip.Addr {

	addrs, err := net.InterfaceAddrs()
	if err != nil {

		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {

		if p, err := netip.ParsePrefix(a.String()); err == nil {

			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// squidOnlyBlocked are destination ranges the proxy refuses on top of
// netpolicy's denied ranges. They are not netfilter denies because nothing
// routes them anyway; the proxy, though, would try.
// IPv4-mapped IPv6 is not listed: Squid holds IPv4 addresses in that form
// internally, so the IPv4 ranges already cover it, and listing it would
// overlap every one of them.
var squidOnlyBlocked = []string{"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128"}

// blockedDestinations is the proxy's destination deny: every range netfilter
// denies, the ranges above, and each of the host's own addresses.
//
// A range inside one already listed is left out. Squid warns about an
// overlapping entry and drops it to keep its lookup tree predictable, so
// listing 10.0.2.15/32 after 10.0.0.0/8 says nothing new and fills the parse
// output with warnings that bury a real one.
func (c *Controller) blockedDestinations() []string {

	var kept []netip.Prefix
	add := func(p netip.Prefix) {

		p = p.Masked()
		for _, k := range kept {

			if k.Addr().Is4() == p.Addr().Is4() && k.Bits() <= p.Bits() && k.Contains(p.Addr()) {

				return
			}
		}
		kept = append(kept, p)
	}
	// Widest first within each list, so a list's own subsets are dropped.
	for _, list := range [][]string{netpolicy.DeniedRanges, netpolicy.DeniedRangesV6, squidOnlyBlocked} {

		var ps []netip.Prefix
		for _, cidr := range list {

			if p, err := netip.ParsePrefix(cidr); err == nil {

				ps = append(ps, p)
			}
		}
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Bits() < ps[j].Bits() })
		for _, p := range ps {

			add(p)
		}
	}
	if c.hostAddrs != nil {

		hosts := c.hostAddrs()
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Less(hosts[j]) })
		for _, a := range hosts {

			add(netip.PrefixFrom(a, a.BitLen()))
		}
	}
	out := make([]string, 0, len(kept))
	for _, p := range kept {

		out = append(out, p.String())
	}
	return out
}

// ProxyIP is the proxy's fixed address on the egress network, which is the
// destination of every per-grant DOCKER-USER accept.
func (c *Controller) ProxyIP() (netip.Addr, error) {

	pool, err := netip.ParsePrefix(c.cfg.EgressSubnet)
	if err != nil {

		return netip.Addr{}, fmt.Errorf("egressctl: egress subnet: %w", err)
	}
	return netpolicy.EgressProxyIP(pool)
}

// Ensure brings the proxy up with the given allowlist and returns whether the
// allowlist changed.
//
// Idempotent and safe to call on every reconcile tick: it renders, compares
// against what is on disk, and reloads only on a difference. Reloading a proxy
// every five seconds would drop long-lived CONNECT tunnels for no reason.
func (c *Controller) Ensure(ctx context.Context, acls []TenantACL) (EnsureResult, error) {

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureDirs(); err != nil {

		return EnsureResult{}, err
	}
	if err := c.pullImage(ctx); err != nil {

		return EnsureResult{}, err
	}
	if err := c.probeSNI(ctx); err != nil {

		return EnsureResult{}, err
	}
	res, err := c.render(acls)
	if err != nil {

		return res, err
	}
	running, err := c.ensureContainer(ctx)
	if err != nil {

		return res, err
	}
	// A container the tick just created has read the new configuration already;
	// HUPing it would be a reload of something it never had.
	if res.Changed && running {

		if err := c.reload(ctx); err != nil {

			return res, err
		}
	}
	return res, nil
}

// DetachTenant removes a tenant from the egress network.
//
// Tolerant of an already-detached container: NetworkDisconnect on a network the
// container has already left is an error rather than a no-op, and a teardown
// was lost to exactly that (design.md §8.3).
func (c *Controller) DetachTenant(ctx context.Context, containerName string) error {

	err := c.docker.NetworkDisconnect(ctx, c.cfg.EgressNetwork, containerName, true)
	if err == nil || client.IsErrNotFound(err) || alreadyDetached(err) {

		return nil
	}
	return fmt.Errorf("egressctl: detach %s from %s: %w", containerName, c.cfg.EgressNetwork, err)
}

func alreadyDetached(err error) bool {

	return err != nil && strings.Contains(err.Error(), "is not connected to")
}

// SNIEnforced reports whether the running proxy is filtering the ClientHello as
// well as the CONNECT target.
func (c *Controller) SNIEnforced() bool { return c.sni }

func (c *Controller) ensureDirs() error {

	if err := os.MkdirAll(c.cfg.EgressDir(), 0o755); err != nil {

		return fmt.Errorf("egressctl: mkdir %s: %w", c.cfg.EgressDir(), err)
	}
	logDir := c.cfg.EgressLogDir()
	if err := os.MkdirAll(logDir, 0o750); err != nil {

		return fmt.Errorf("egressctl: mkdir %s: %w", logDir, err)
	}
	// Squid drops privileges and then opens its access log. A root-owned
	// directory makes it FATAL before it proxies anything, and under
	// userns-remap the uid it needs is the remapped one.
	//
	// The CONTENTS are chowned too, not just the directory. A log file left
	// behind by a proxy image with a different uid is unwritable to the new
	// one, and Squid reports it as "the parent directory must be writeable by
	// the user 'squid'" — which is true of the directory and not the problem.
	// Changing the proxy image is exactly when this bites (design.md
	// §9.4).
	uid := c.usernsBase + squidUID
	if err := os.Chown(logDir, uid, uid); err != nil {

		return fmt.Errorf("egressctl: chown %s to %d: %w", logDir, uid, err)
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {

		return fmt.Errorf("egressctl: read %s: %w", logDir, err)
	}
	for _, e := range entries {

		if e.Name() == cursorName {

			continue // the control plane's own bookkeeping, not Squid's
		}
		// Lchown, not Chown: the proxy can write this directory, so any entry
		// in it may be a symlink the proxy planted, and following it would
		// have root hand an arbitrary host file to the proxy's uid.
		path := filepath.Join(logDir, e.Name())
		if err := os.Lchown(path, uid, uid); err != nil {

			return fmt.Errorf("egressctl: chown %s to %d: %w", path, uid, err)
		}
	}
	return nil
}

func (c *Controller) confPath() string { return filepath.Join(c.cfg.EgressDir(), confName) }

// lastPath is a root-only copy of the last configuration this control plane
// wrote. It lives under the audit directory, not next to squid.conf: the egress
// directory is mounted into the proxy, and the reference a tamper check
// compares against must not be reachable from what it is checking.
func (c *Controller) lastPath() string { return filepath.Join(c.cfg.AuditDir(), "egress-acl.last") }

// rememberWritten records body as the last write, in memory and on disk.
func (c *Controller) rememberWritten(body []byte) {

	c.lastWritten = body
	path := c.lastPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {

		c.log.Error("cannot keep the last-written egress allowlist; a restart will not detect an edit", "err", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {

		c.log.Error("cannot keep the last-written egress allowlist; a restart will not detect an edit", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {

		_ = os.Remove(tmp)
		c.log.Error("cannot keep the last-written egress allowlist; a restart will not detect an edit", "err", err)
	}
}

// render writes the configuration and reports whether it differs from what was
// already on disk, and whether what was on disk is what this controller wrote.
//
// The reference for "what this controller wrote" survives a restart (lastPath),
// so an edit made while the control plane was down — or one made and followed
// by a restart to cover it — is reported like any other, not silently
// overwritten on the first render (INV-19). Only a host that has never had a
// render recorded has nothing to compare against.
func (c *Controller) render(acls []TenantACL) (EnsureResult, error) {

	body, err := c.renderBytes(acls, c.sni)
	if err != nil {

		return EnsureResult{}, err
	}
	if c.lastWritten == nil {

		if prev, err := os.ReadFile(c.lastPath()); err == nil {

			c.lastWritten = prev

		} else if !errors.Is(err, os.ErrNotExist) {

			c.log.Error("cannot read the last-written egress allowlist", "err", err)
		}
	}
	path := c.confPath()
	old, readErr := os.ReadFile(path)
	if readErr == nil && bytes.Equal(old, body) {

		if !bytes.Equal(c.lastWritten, body) {

			c.rememberWritten(body)
		}
		return EnsureResult{}, nil
	}
	var res EnsureResult
	if readErr == nil && c.lastWritten != nil && !bytes.Equal(old, c.lastWritten) {

		res.Tampered = tamperOf(old, c.lastWritten)
		res.Tampered.EvidencePath = c.keepEvidence(old, res.Tampered.FoundDigest)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {

		return res, fmt.Errorf("egressctl: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {

		return res, fmt.Errorf("egressctl: rename %s: %w", tmp, err)
	}
	c.rememberWritten(body)
	res.Changed = true
	return res, nil
}

// keepEvidence stores the allowlist as found, under the audit directory, before
// render overwrites it. The audit row carries only its digest (§14.4: subject
// refs, never payloads); this file is what an investigation reads.
func (c *Controller) keepEvidence(found []byte, digest string) string {

	dir := filepath.Join(c.cfg.AuditDir(), "evidence")
	if err := os.MkdirAll(dir, 0o700); err != nil {

		c.log.Error("cannot keep the tampered egress allowlist as evidence", "err", err)
		return ""
	}
	path := filepath.Join(dir, "egress-acl-"+strings.TrimPrefix(digest, "sha256:")+".conf")
	if err := os.WriteFile(path, found, 0o600); err != nil {

		c.log.Error("cannot keep the tampered egress allowlist as evidence", "path", path, "err", err)
		return ""
	}
	return path
}

// tamperOf describes how found differs from want, line by line.
func tamperOf(found, want []byte) *Tamper {

	lines := func(b []byte) map[string]bool {

		m := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {

			m[l] = true
		}
		return m
	}
	f, w := lines(found), lines(want)
	t := &Tamper{FoundDigest: digestOf(found), WantDigest: digestOf(want)}
	for _, l := range strings.Split(string(found), "\n") {

		if !w[l] && len(t.Added) < maxTamperLines {

			t.Added = append(t.Added, l)
		}
	}
	for _, l := range strings.Split(string(want), "\n") {

		if !f[l] && len(t.Removed) < maxTamperLines {

			t.Removed = append(t.Removed, l)
		}
	}
	return t
}

func (c *Controller) renderBytes(acls []TenantACL, sni bool) ([]byte, error) {

	// Sorted so an unchanged grant set renders byte-identically and does not
	// look like a change worth reloading for.
	sorted := append([]TenantACL{}, acls...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TenantID < sorted[j].TenantID })
	for i := range sorted {

		sorted[i].Hosts = SquidDomains(sorted[i].Hosts)
	}
	mgr, err := c.MgrIP()
	if err != nil {

		return nil, err
	}
	var buf bytes.Buffer
	err = c.tmpl.Execute(&buf, struct {
		Port    int
		SNI     bool
		MgrIP   string
		Blocked []string
		Tenants []TenantACL
	}{Port: c.cfg.EgressProxyPort, SNI: sni, MgrIP: mgr.String(), Blocked: c.blockedDestinations(), Tenants: sorted})
	if err != nil {

		return nil, fmt.Errorf("egressctl: render: %w", err)
	}
	return buf.Bytes(), nil
}

// ConfigDigest is the sha256 of the configuration on disk, used as an audit
// subject ref so an ACL change is traceable without copying the allowlist into
// the audit row (§14.4: subject refs, never payloads).
func (c *Controller) ConfigDigest() string {

	b, err := os.ReadFile(c.confPath())
	if err != nil {

		return ""
	}
	return digestOf(b)
}

func digestOf(b []byte) string {

	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// reload asks Squid to re-read its configuration.
//
// A signal through the Docker API, not `docker exec`: the control plane has no
// exec path into any container in the production path; the last one went away
// when Caddy moved onto an admin socket.
func (c *Controller) reload(ctx context.Context) error {

	if err := c.docker.ContainerKill(ctx, c.cfg.EgressProxyContainer, "HUP"); err != nil {

		return fmt.Errorf("egressctl: reload %s: %w", c.cfg.EgressProxyContainer, err)
	}
	c.log.Info("egress proxy allowlist reloaded", "digest", c.ConfigDigest())
	return nil
}

// ensureContainer converges the proxy container, reporting whether it was
// already running (as opposed to just created, which needs no reload).
func (c *Controller) ensureContainer(ctx context.Context) (wasRunning bool, err error) {

	insp, err := c.docker.ContainerInspect(ctx, c.cfg.EgressProxyContainer)
	switch {

	case err == nil:
		// Check WHAT is running, not merely that something is.
		//
		// This shipped as a bare `is it running?` once and cost an afternoon
		// to it: the proxy image changed, the container kept running the old
		// one, the generated allowlist on disk was correct, and every request
		// was refused by a binary that had never read it. §14.5's rule — attest
		// the ACL as loaded in the RUNNING proxy, never as templated on disk —
		// is the same lesson, and it applies to the control plane's own view
		// too (design.md §9.4).
		if stale := c.staleReason(ctx, insp); stale != "" {

			c.log.Warn("recreating the egress proxy", "reason", stale,
				"container", c.cfg.EgressProxyContainer)

		} else if insp.State != nil && insp.State.Running {

			return true, nil

		} else if err := c.docker.ContainerStart(ctx, insp.ID, container.StartOptions{}); err == nil {

			return false, nil

		} else {

			c.log.Warn("recreating the egress proxy: it would not start",
				"container", c.cfg.EgressProxyContainer)
		}
		if err := c.docker.ContainerRemove(ctx, c.cfg.EgressProxyContainer,
			container.RemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {

			return false, err
		}
	case client.IsErrNotFound(err):
	default:
		return false, fmt.Errorf("egressctl: inspect %s: %w", c.cfg.EgressProxyContainer, err)
	}

	ip, err := c.ProxyIP()
	if err != nil {

		return false, err
	}
	created, err := c.docker.ContainerCreate(ctx,
		&container.Config{
			Image: c.cfg.EgressProxyImage,
			Labels: map[string]string{
				netpolicy.LabelManaged: "true",
				"v2p.role":             "egress-proxy",
			},
			// No ExposedPorts and no PortBindings: the proxy is reached across
			// the egress bridge, never from the host's network (the
			// no-published-ports rule is about tenants, but there is no reason
			// to publish this either).
		},
		&container.HostConfig{
			Binds: []string{
				// :ro — a proxy that can rewrite its own allowlist is not an
				// allowlist, and this container is one hop from hostile code.
				c.cfg.EgressDir() + ":" + confMountDir + ":ro",
				c.cfg.EgressLogDir() + ":" + logMount + ":rw",
			},
			Tmpfs: map[string]string{
				"/var/spool/squid": "rw,noexec,nosuid,size=64m",
				"/run":             "rw,noexec,nosuid,size=8m",
			},
			CapDrop: []string{"ALL"},
			// Squid starts as root and drops to the proxy user; those four are
			// what the drop itself needs and nothing more. NET_ADMIN in
			// particular is absent.
			CapAdd:      []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"},
			SecurityOpt: []string{"no-new-privileges:true"},
			// Bounded like a tenant: the proxy parses hostile traffic, and an
			// unbounded one is a way for a tenant to exhaust the host.
			Resources: container.Resources{
				PidsLimit: &proxyPidsLimit,
				Memory:    proxyMemoryBytes,
			},
			// The reconciler owns restarts here as it does for tenants: Docker's
			// restart policy has no backoff ladder and no visibility (§4).
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
			// Platform code stays on runc. runsc is for tenant workloads.
			Runtime:     "runc",
			NetworkMode: container.NetworkMode(c.cfg.EgressNetwork),
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				c.cfg.EgressNetwork: {
					IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: ip.String()},
				},
			},
		}, nil, c.cfg.EgressProxyContainer)
	if err != nil {

		return false, fmt.Errorf("egressctl: create %s: %w", c.cfg.EgressProxyContainer, err)
	}
	if err := c.docker.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return false, fmt.Errorf("egressctl: start %s: %w", c.cfg.EgressProxyContainer, err)
	}
	return false, nil
}

// staleReason names why the running proxy no longer matches what the control
// plane would create, or "" when it matches.
//
// Deliberately narrow: the image it runs, the configuration it was handed, and
// the address it answers on. Those are the three that make a running proxy
// enforce something other than the current allowlist.
func (c *Controller) staleReason(ctx context.Context, insp container.InspectResponse) string {

	if insp.Config != nil && insp.Config.Image != c.cfg.EgressProxyImage {

		return fmt.Sprintf("running image %s, want %s", insp.Config.Image, c.cfg.EgressProxyImage)
	}
	// The tag is not the image. `make egress-image` rebuilds v2p-squid:6-r2 in
	// place, so a tag comparison says "unchanged" while the container runs the
	// previous build — which is how a fixed configuration bug survives its own
	// fix. Compare the resolved ID, as the tenant driver does.
	if img, err := c.docker.ImageInspect(ctx, c.cfg.EgressProxyImage); err == nil {

		if insp.Image != img.ID {

			return fmt.Sprintf("running image id %s, want %s", short(insp.Image), short(img.ID))
		}
	}
	if insp.HostConfig != nil && insp.HostConfig.PidsLimit == nil {

		return "created without the proxy's resource limits"
	}
	if insp.HostConfig != nil {

		want := c.cfg.EgressDir() + ":" + confMountDir + ":ro"
		found := false
		for _, b := range insp.HostConfig.Binds {

			if b == want {

				found = true
			}
		}
		if !found {

			return "the generated allowlist is not the file it has mounted"
		}
	}
	ip, err := c.ProxyIP()
	if err != nil {

		return ""
	}
	if ep, ok := insp.NetworkSettings.Networks[c.cfg.EgressNetwork]; !ok {

		return "not attached to " + c.cfg.EgressNetwork

	} else if ep.IPAddress != ip.String() {

		// Every per-grant DOCKER-USER accept names this address as its only
		// permitted destination, so a proxy at a different one is unreachable.
		return fmt.Sprintf("address %s, want %s", ep.IPAddress, ip)
	}
	return ""
}

// short trims an image id to something readable in a log line.
func short(id string) string {

	if i := strings.Index(id, ":"); i >= 0 && len(id) > i+13 {

		return id[:i+13]
	}
	return id
}

func (c *Controller) pullImage(ctx context.Context) error {

	if _, err := c.docker.ImageInspect(ctx, c.cfg.EgressProxyImage); err == nil {

		return nil
	}
	rc, err := c.docker.ImagePull(ctx, c.cfg.EgressProxyImage, image.PullOptions{})
	if err != nil {

		// The default image is built locally rather than pulled, because the
		// distro images that are easy to pull have no OpenSSL support and so
		// cannot do the §9.4 SNI check at all. Say which command builds it
		// rather than reporting a bare registry error.
		return fmt.Errorf("egressctl: the proxy image %s is not present and could not be pulled "+
			"(run `make egress-image`, or set egress_proxy_image to one you have): %w",
			c.cfg.EgressProxyImage, err)
	}
	defer rc.Close()
	_, err = io.Copy(io.Discard, rc)
	return err
}

// probeSNI asks the real binary whether it understands ssl_bump, once.
//
// A Squid built without --with-openssl parses every other line of the template
// happily and rejects only these, so the failure is a proxy that will not start
// rather than a proxy that quietly stops filtering. Probing turns that into a
// recorded downgrade: CONNECT-target filtering still applies, and the gap is
// named in the log and in the tenant-facing surface rather than assumed away.
func (c *Controller) probeSNI(ctx context.Context) error {

	if c.sniKnown || !c.cfg.EgressSNIEnforce {

		c.sniKnown = true
		return nil
	}
	c.sniKnown = true

	body, err := c.renderBytes(nil, true)
	if err != nil {

		return err
	}
	probe := filepath.Join(c.cfg.EgressDir(), "sni-probe.conf")
	if err := os.WriteFile(probe, body, 0o644); err != nil {

		return fmt.Errorf("egressctl: write %s: %w", probe, err)
	}
	defer os.Remove(probe)

	out, err := c.parseConfig(ctx, probe)
	if err == nil {

		c.sni = true
		c.log.Info("egress proxy enforces the ClientHello SNI as well as the CONNECT target")
		return nil
	}
	c.sni = false
	c.log.Error("egress proxy build does not accept ssl_bump; falling back to CONNECT-target filtering only. "+
		"A hook can then CONNECT to an allowed host and negotiate TLS for another one. "+
		"Use an openssl-enabled squid build, or set egress_sni_enforce:false to make the downgrade deliberate",
		"image", c.cfg.EgressProxyImage, "err", err, "parse_output", out)
	return nil
}

// parseConfig runs `squid -k parse` against a candidate file in a throwaway
// container with no network at all.
func (c *Controller) parseConfig(ctx context.Context, path string) (string, error) {

	name := c.cfg.EgressProxyContainer + "-parse"
	_ = c.docker.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})

	created, err := c.docker.ContainerCreate(ctx,
		&container.Config{
			Image:  c.cfg.EgressProxyImage,
			Cmd:    []string{"-k", "parse", "-f", confMountDir + "/" + filepath.Base(path)},
			Labels: map[string]string{netpolicy.LabelManaged: "true"},
		},
		&container.HostConfig{
			Binds:       []string{filepath.Dir(path) + ":" + confMountDir + ":ro"},
			NetworkMode: "none",
			CapDrop:     []string{"ALL"},
			// The SAME capabilities as the real proxy, because `squid -k parse`
			// is not a dry run: it starts up far enough to drop privileges and
			// to load the port's certificate. Without SETUID/SETGID it dies in
			// the privilege drop and exits 139, which reads as "this build has
			// no ssl_bump" and silently downgrades the whole platform to
			// CONNECT-target filtering (design.md §9.4). A probe whose
			// environment differs from production answers the wrong question.
			CapAdd:        []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"},
			SecurityOpt:   []string{"no-new-privileges:true"},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
			Runtime:       "runc",
			AutoRemove:    false,
		}, nil, nil, name)
	if err != nil {

		return "", err
	}
	defer c.docker.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})

	if err := c.docker.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return "", err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	statusCh, errCh := c.docker.ContainerWait(waitCtx, created.ID, container.WaitConditionNotRunning)
	var code int64
	select {

	case err := <-errCh:
		return "", err
	case st := <-statusCh:
		code = st.StatusCode
	}
	logs := c.containerOutput(ctx, created.ID)
	if code != 0 {

		return logs, fmt.Errorf("squid -k parse exited %d", code)
	}
	return logs, nil
}

func (c *Controller) containerOutput(ctx context.Context, id string) string {

	rc, err := c.docker.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {

		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 16<<10))
	if err != nil {

		return ""
	}
	return strings.TrimSpace(stripStreamHeaders(b))
}

// stripStreamHeaders removes Docker's 8-byte multiplexing frame headers from a
// non-TTY log stream.
func stripStreamHeaders(b []byte) string {

	var out strings.Builder
	for len(b) >= 8 {

		n := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		if n < 0 || n > len(b)-8 {

			out.Write(b[8:])
			return out.String()
		}
		out.Write(b[8 : 8+n])
		b = b[8+n:]
	}
	return out.String()
}

// ProxyEnv is the HTTP_PROXY set injected into every tenant container.
//
// ERGONOMICS, NOT ENFORCEMENT. PocketBase's $http.send goes through
// Go's http.Client, which honours ProxyFromEnvironment, so a cooperating hook
// works with no code change. A hostile hook opens a raw socket and ignores
// these entirely; the DOCKER-USER DROP is what stops it. Never let the two get
// conflated in review.
//
// Set unconditionally, whether or not the tenant has a grant, for a reason
// worth stating: it makes the variables a constant of the tenant's life, so
// granting or revoking access never needs a container recreate. With no grant
// the tenant is not on the egress network at all, and a hook that honours the
// variable gets an immediate "no route to host" instead of a silent timeout —
// which is the better error either way.
func (c *Controller) ProxyEnv() map[string]string {

	ip, err := c.ProxyIP()
	if err != nil {

		return nil
	}
	url := "http://" + ip.String() + ":" + strconv.Itoa(c.cfg.EgressProxyPort)
	return map[string]string{
		"HTTP_PROXY":  url,
		"HTTPS_PROXY": url,
		"http_proxy":  url,
		"https_proxy": url,
		// Localhost must not go through the proxy: a hook calling its own
		// instance would otherwise leave the container and be denied.
		"NO_PROXY": "localhost,127.0.0.1",
		"no_proxy": "localhost,127.0.0.1",
	}
}
