package egressctl

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

func renderTest(t *testing.T, sni bool) string {

	t.Helper()
	cfg := config.Default()
	c := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
	c.hostAddrs = func() []netip.Addr {

		return []netip.Addr{
			netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9"),
			// Already covered by 10.0.0.0/8 and 127.0.0.0/8: left out.
			netip.MustParseAddr("10.0.2.15"), netip.MustParseAddr("127.0.0.1"),
		}
	}
	b, err := c.renderBytes([]TenantACL{
		{TenantID: "t-1", IP: "10.214.0.10", Hosts: []string{"api.example.com", "b.example.org"}},
	}, sni)
	if err != nil {

		t.Fatal(err)
	}
	return string(b)
}

// Without -n, a CONNECT to a bare IP falls back to the address's PTR record,
// which whoever owns the address controls.
func TestRenderedAllowlistNeverReverseResolves(t *testing.T) {

	for _, sni := range []bool{false, true} {

		conf := renderTest(t, sni)
		if !strings.Contains(conf, "acl t_t_1_dst dstdomain -n api.example.com b.example.org") {

			t.Fatalf("dstdomain without -n (sni=%v):\n%s", sni, conf)
		}
	}
}

// A granted name the tenant controls can resolve to the metadata endpoint,
// a private address or the host itself. The deny must cover them and sit
// above every allow.
func TestRenderedAllowlistDeniesPrivateDestinationsFirst(t *testing.T) {

	conf := renderTest(t, true)
	var acl string
	for line := range strings.SplitSeq(conf, "\n") {

		if strings.HasPrefix(line, "acl v2p_blocked_dst dst ") {

			acl = line
		}
	}
	for _, want := range []string{
		"169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128", "203.0.113.9/32", "2001:db8::9/128",
	} {

		if !strings.Contains(" "+acl+" ", " "+want+" ") {

			t.Errorf("blocked destinations %q do not include %s", acl, want)
		}
	}
	// Ranges inside another are left out; Squid would warn and drop them.
	if strings.Contains(acl, "fd00:ec2::254") || strings.Contains(acl, "10.0.2.15") || strings.Contains(acl, "127.0.0.1/") {

		t.Errorf("blocked destinations %q list a range inside another", acl)
	}
	// Every tenant allow carries the port and destination conditions, and no
	// http_access deny exists but the manager's and the final one: on an
	// ssl-bump port any other deny is answered with an error page inside the
	// tunnel, under a certificate the proxy generated.
	var allows, denies []string
	for line := range strings.SplitSeq(conf, "\n") {

		switch {

		case strings.HasPrefix(line, "http_access allow t_"):
			allows = append(allows, line)
		case strings.HasPrefix(line, "http_access deny"):
			denies = append(denies, line)
		}
	}
	if len(allows) != 2 {

		t.Fatalf("want a CONNECT allow and a plain-HTTP allow, got %v", allows)
	}
	for _, a := range allows {

		if !strings.HasSuffix(a, " !v2p_blocked_dst") {

			t.Errorf("allow %q does not exclude blocked destinations", a)
		}
	}
	if !strings.Contains(allows[0], " CONNECT SSL_ports ") || !strings.Contains(allows[1], " !CONNECT Safe_ports ") {

		t.Errorf("allows do not carry the port rules: %v", allows)
	}
	if strings.Join(denies, "|") != "http_access deny manager|http_access deny all" {

		t.Errorf("deny lines other than the manager's and the final one: %v", denies)
	}
}

// The running proxy prints flags with the ACL; the live allowlist must not
// mistake -n for a host.
func TestParseLiveACLSkipsFlags(t *testing.T) {

	got := parseLiveACL("acl t_t_1_dst dstdomain -n api.example.com\n")
	if hosts := got["t_1"]; len(hosts) != 1 || hosts[0] != "api.example.com" {

		t.Fatalf("parsed %v", got)
	}
}

// The proxy can write its log directory. A cursor name it replaced with a
// symlink must be replaced, not written through.
func TestCursorWriteNeverFollowsASymlink(t *testing.T) {

	dir, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "shadow")
	if err := os.WriteFile(target, []byte("root:x:0:0"), 0o600); err != nil {

		t.Fatal(err)
	}
	path := filepath.Join(dir, cursorName)
	if err := os.Symlink(target, path); err != nil {

		t.Fatal(err)
	}
	if err := writeNoFollow(path, []byte(`{"offset":1}`)); err != nil {

		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "root:x:0:0" {

		t.Fatalf("the symlink's target was overwritten: %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {

		t.Fatalf("the cursor is still a symlink: %v", err)
	}
}

// An approved wildcard must reach Squid in the form Squid understands, and a
// host it already covers must not be listed twice: Squid drops one of the two.
func TestSquidDomainsRendersWildcardsOnce(t *testing.T) {

	got := strings.Join(SquidDomains([]string{
		"*.example.com", "api.example.com", "example.com", "*.deep.example.com",
		"other.org", "other.org", "*.stripe.com",
	}), " ")
	want := ".example.com .stripe.com other.org"
	if got != want {

		t.Fatalf("SquidDomains = %q, want %q", got, want)
	}
	conf := renderTestACL(t, []string{"*.example.com", "api.example.com"})
	if !strings.Contains(conf, "dstdomain -n .example.com\n") {

		t.Fatalf("wildcard not rendered as a domain match:\n%s", conf)
	}
	// And it reads back as the grant it came from.
	live := parseLiveACL("acl t_t_1_dst dstdomain -n .example.com other.org\n")
	if h := live["t_1"]; len(h) != 2 || h[0] != "*.example.com" || h[1] != "other.org" {

		t.Fatalf("live ACL read back as %v", h)
	}
}

func renderTestACL(t *testing.T, hosts []string) string {

	t.Helper()
	c := New(config.Default(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
	c.hostAddrs = func() []netip.Addr { return nil }
	b, err := c.renderBytes([]TenantACL{{TenantID: "t-1", IP: "10.214.0.10", Hosts: hosts}}, true)
	if err != nil {

		t.Fatal(err)
	}
	return string(b)
}

// A hand edit to the live allowlist is overwritten on the next render — the
// proxy must not go on admitting a host nobody granted — but never silently:
// an entry with no grant behind it is enforcement_without_grant (§14.5), and
// once the file is rewritten the report and the kept copy are all that is left.
func TestRenderReportsAnAllowlistEditedOutsideTheControlPlane(t *testing.T) {

	cfg := config.Default()
	cfg.PBRoot = t.TempDir()
	c := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
	c.hostAddrs = func() []netip.Addr { return nil }
	if err := os.MkdirAll(cfg.EgressDir(), 0o755); err != nil {

		t.Fatal(err)
	}
	acls := []TenantACL{{TenantID: "t-1", IP: "10.214.0.10", Hosts: []string{"api.example.com"}}}

	if res, err := c.render(acls); err != nil || !res.Changed || res.Tampered != nil {

		t.Fatalf("first render: %+v, %v", res, err)
	}
	if res, err := c.render(acls); err != nil || res.Changed || res.Tampered != nil {

		t.Fatalf("an unchanged render: %+v, %v", res, err)
	}

	b, err := os.ReadFile(c.confPath())
	if err != nil {

		t.Fatal(err)
	}
	edited := strings.Replace(string(b), "dstdomain -n api.example.com",
		"dstdomain -n api.example.com evil.example.net", 1)
	if edited == string(b) {

		t.Fatal("the fixture's allow line was not found")
	}
	if err := os.WriteFile(c.confPath(), []byte(edited), 0o644); err != nil {

		t.Fatal(err)
	}

	res, err := c.render(acls)
	if err != nil {

		t.Fatal(err)
	}
	if !res.Changed {

		t.Fatal("the edited allowlist was left in place")
	}
	if res.Tampered == nil {

		t.Fatal("the edited allowlist was overwritten silently")
	}
	if !strings.Contains(strings.Join(res.Tampered.Added, "\n"), "evil.example.net") {

		t.Errorf("the report does not name the added host: %+v", res.Tampered)
	}
	if kept, err := os.ReadFile(res.Tampered.EvidencePath); err != nil || string(kept) != edited {

		t.Errorf("the edited copy was not kept as evidence (%q): %v", res.Tampered.EvidencePath, err)
	}
	if now, _ := os.ReadFile(c.confPath()); strings.Contains(string(now), "evil.example.net") {

		t.Error("the unbacked host is still in the allowlist")
	}

	// A grant change is the control plane's own write, never a tamper.
	acls[0].Hosts = append(acls[0].Hosts, "b.example.org")
	if res, err := c.render(acls); err != nil || !res.Changed || res.Tampered != nil {

		t.Fatalf("a legitimate change: %+v, %v", res, err)
	}
}

// An edit made while the control plane is down is still reported on the first
// render after it starts: the reference copy survives the restart (INV-19).
func TestRenderReportsAnEditMadeAcrossARestart(t *testing.T) {

	cfg := config.Default()
	cfg.PBRoot = t.TempDir()
	mk := func() *Controller {

		c := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
		c.hostAddrs = func() []netip.Addr { return nil }
		return c
	}
	if err := os.MkdirAll(cfg.EgressDir(), 0o755); err != nil {

		t.Fatal(err)
	}
	acls := []TenantACL{{TenantID: "t-1", IP: "10.214.0.10", Hosts: []string{"api.example.com"}}}
	first := mk()
	if _, err := first.render(acls); err != nil {

		t.Fatal(err)
	}
	b, err := os.ReadFile(first.confPath())
	if err != nil {

		t.Fatal(err)
	}
	edited := strings.Replace(string(b), "dstdomain -n api.example.com",
		"dstdomain -n api.example.com evil.example.net", 1)
	if err := os.WriteFile(first.confPath(), []byte(edited), 0o644); err != nil {

		t.Fatal(err)
	}

	res, err := mk().render(acls)
	if err != nil {

		t.Fatal(err)
	}
	if res.Tampered == nil {

		t.Fatal("an edit made across a restart was overwritten silently")
	}
}
