package egressctl

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
)

// mgrTimeout bounds the manager read. An attestation that hangs is an
// attestation that silently stops happening.
const mgrTimeout = 5 * time.Second

// MgrIP is the host's address on the egress bridge, and therefore the source
// address the proxy's manager ACL allows.
func (c *Controller) MgrIP() (netip.Addr, error) {

	pool, err := netip.ParsePrefix(c.cfg.EgressSubnet)
	if err != nil {

		return netip.Addr{}, fmt.Errorf("egressctl: egress subnet: %w", err)
	}
	return netpolicy.EgressGatewayIP(pool)
}

// LiveACL reports the allowlist the RUNNING proxy is enforcing, per tenant.
//
// Not the file on disk. The generated allowlist on disk was correct once while
// every request was refused by a binary that had never read it, so a digest of
// the file proves only that the platform intended something. This asks Squid
// what it actually holds, which is the distinction §14.5 turns on and the
// reason the attestation is worth signing.
//
// Read over HTTP from the host rather than through an exec into the container:
// the control plane has no exec path into any container in the production path.
func (c *Controller) LiveACL(ctx context.Context) (map[string][]string, error) {

	body, err := c.mgrConfig(ctx)
	if err != nil {

		return nil, err
	}
	return parseLiveACL(body), nil
}

func (c *Controller) mgrConfig(ctx context.Context) (string, error) {

	ip, err := c.ProxyIP()
	if err != nil {

		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, mgrTimeout)
	defer cancel()

	addr := net.JoinHostPort(ip.String(), fmt.Sprint(c.cfg.EgressProxyPort))
	url := "http://" + addr + "/squid-internal-mgr/config"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {

		return "", err
	}
	// No proxy from the environment: this request is TO the proxy, and letting
	// it be proxied would produce a CONNECT the allowlist would refuse.
	cl := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Do(req)
	if err != nil {

		return "", fmt.Errorf("egressctl: read proxy manager at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		return "", fmt.Errorf("egressctl: proxy manager at %s returned %s", addr, resp.Status)
	}
	var sb strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {

		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
	}
	return sb.String(), sc.Err()
}

// parseLiveACL turns the manager's configuration dump back into tenant → hosts.
//
// It reads the `acl t_<name>_dst dstdomain …` lines, which are what actually
// gate a request, rather than the `_sni` lines that only terminate a mismatched
// handshake. The ACL name is the tenant id with Squid-unsafe characters
// replaced, so the mapping back is by comparing against the known tenant ids
// the caller already holds — done in internal/attest, not here.
func parseLiveACL(dump string) map[string][]string {

	out := map[string][]string{}
	for line := range strings.SplitSeq(dump, "\n") {

		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 4 || f[0] != "acl" || f[2] != "dstdomain" {

			continue
		}
		name, ok := strings.CutPrefix(f[1], "t_")
		if !ok {

			continue
		}
		name, ok = strings.CutSuffix(name, "_dst")
		if !ok {

			continue
		}
		hosts := out[name]
		for _, h := range f[3:] {

			// Flags such as -n are printed with the ACL; a host never starts
			// with a hyphen (pkgvalidate rejects it). A leading dot is how a
			// wildcard grant is rendered (SquidDomains), and goes back to the
			// form the grant was recorded in.
			switch {

			case strings.HasPrefix(h, "-"):
			case strings.HasPrefix(h, "."):
				hosts = append(hosts, "*"+h)
			default:
				hosts = append(hosts, h)
			}
		}
		sort.Strings(hosts)
		out[name] = hosts
	}
	return out
}
