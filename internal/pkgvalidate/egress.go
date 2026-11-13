package pkgvalidate

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// HostPolicy is the platform-side context an egress host is judged against.
type HostPolicy struct {
	// PlatformDomains are the platform's own names — the apps domain and
	// anything else the platform serves. Never allowlistable: a tenant
	// reaching another tenant through the edge is escape route 3 with extra
	// steps.
	PlatformDomains []string
}

// reservedTLDs never resolve on the public internet, so a request for one is
// either a mistake or an attempt to reach something on the platform's own
// network. Neither is grantable.
var reservedTLDs = map[string]bool{
	"internal": true, "local": true, "localdomain": true, "localhost": true,
	"home": true, "lan": true, "corp": true, "intranet": true, "test": true,
	"example": true, "invalid": true, "onion": true,
}

// IsWildcard reports whether the host is a wildcard pattern. A wildcard is
// legal to request but never auto-granted: internal/grantpolicy sends it to a
// human (Tier 2), because "*.example.com" is an unbounded set of destinations.
func IsWildcard(host string) bool {

	return strings.HasPrefix(host, "*.")
}

// ValidateEgressHost applies the §6 host rules: a hostname, not a URL, not an
// address literal, not a platform name, not a wildcard at the apex.
//
// It says nothing about whether the host is *allowed* — that is a grant
// decision, made in internal/grantpolicy from the tier rules and
// recorded in access_grant. This function only rejects what can never be a
// legitimate request.
func ValidateEgressHost(host string, p HostPolicy) error {

	if host == "" {

		return fmt.Errorf("%w: empty host", ErrEgressPolicy)
	}
	if host != strings.ToLower(host) {

		return fmt.Errorf("%w: %q must be lowercase", ErrEgressPolicy, host)
	}
	if strings.ContainsAny(host, "/:@ \t") {

		return fmt.Errorf("%w: %q is a hostname, not a URL, port or user@host", ErrEgressPolicy, host)
	}
	if len(host) > 253 {

		return fmt.Errorf("%w: %q is longer than 253 characters", ErrEgressPolicy, host)
	}

	bare := host
	if IsWildcard(host) {

		bare = host[2:]

	} else if strings.Contains(host, "*") {

		return fmt.Errorf("%w: %q may only wildcard the leftmost label, as *.example.com", ErrEgressPolicy, host)
	}

	// An address literal is never allowlistable. Netfilter matches addresses and
	// the proxy matches names (§9.4); a literal here is either an attempt at the
	// metadata endpoint or at an RFC1918 host on the platform's network.
	if _, err := netip.ParseAddr(bare); err == nil {

		return fmt.Errorf("%w: %q is an IP address; egress is allowlisted by hostname only", ErrEgressPolicy, host)
	}

	// netip only parses the dotted-quad form, but resolvers and inet_aton
	// also accept shorthand and hex — 10.0.1, 169.254.43518, 0x7f.1 — and a
	// proxy built on one would treat such a "name" as an address. No real
	// top-level domain is numeric, so an all-digit final label is refused too.
	if looksLikeIPv4(bare) {

		return fmt.Errorf("%w: %q is an IP address in shorthand form; egress is allowlisted by hostname only", ErrEgressPolicy, host)
	}

	labels := strings.Split(bare, ".")
	if len(labels) < 2 {

		if IsWildcard(host) {

			return fmt.Errorf("%w: %q wildcards a whole top-level domain", ErrEgressPolicy, host)
		}
		return fmt.Errorf("%w: %q is not a fully-qualified domain name", ErrEgressPolicy, host)
	}
	for _, l := range labels {

		if err := validateLabel(host, l); err != nil {

			return err
		}
	}
	// A wildcard over a public suffix is every domain anyone registers under
	// it: *.co.uk is all of the UK's companies, *.github.io every user's
	// pages. The private section of the list counts too — those are the
	// suffixes where strangers get names. (Wildcard-DNS services that are not
	// on the list, such as nip.io, are caught at the proxy instead, which
	// refuses any name that resolves to a private or host address.)
	if IsWildcard(host) {

		if suffix, _ := publicsuffix.PublicSuffix(bare); suffix == bare {

			return fmt.Errorf("%w: %q wildcards a public suffix, which anyone can register names under", ErrEgressPolicy, host)
		}
	}
	// Platform domains are checked before the reserved-namespace rule so the
	// tenant gets the reason that actually applies: an apps domain under a
	// reserved TLD, such as apps.localhost, would otherwise be refused as "reserved" and
	// leave a tenant guessing about a rule that is really deny-by-default egress.
	for _, d := range p.PlatformDomains {

		d = strings.ToLower(strings.TrimPrefix(d, "."))
		if d == "" {

			continue
		}
		if bare == d || strings.HasSuffix(bare, "."+d) {

			return fmt.Errorf("%w: %q is a platform domain; reaching another tenant is escape route 3", ErrEgressPolicy, host)
		}
	}
	if reservedTLDs[labels[len(labels)-1]] {

		return fmt.Errorf("%w: %q is in a reserved namespace that never resolves publicly", ErrEgressPolicy, host)
	}
	return nil
}

func validateLabel(host, l string) error {

	if l == "" {

		return fmt.Errorf("%w: %q has an empty label", ErrEgressPolicy, host)
	}
	if len(l) > 63 {

		return fmt.Errorf("%w: %q has a label longer than 63 characters", ErrEgressPolicy, host)
	}
	if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {

		return fmt.Errorf("%w: label %q in %q starts or ends with a hyphen", ErrEgressPolicy, l, host)
	}
	for _, r := range l {

		switch {

		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("%w: label %q in %q contains %q", ErrEgressPolicy, l, host, string(r))
		}
	}
	return nil
}

// looksLikeIPv4 reports whether s could be read as an IPv4 address by
// inet_aton: one to four parts, each decimal, octal or 0x-hex. It also reports
// a name whose last label is all digits, which no real top-level domain is.
func looksLikeIPv4(s string) bool {

	labels := strings.Split(s, ".")
	if last := labels[len(labels)-1]; last != "" && strings.Trim(last, "0123456789") == "" {

		return true
	}
	if len(labels) > 4 {

		return false
	}
	for _, l := range labels {

		if l == "" {

			return false
		}
		digits := l
		if strings.HasPrefix(l, "0x") {

			digits = l[2:]
			if strings.Trim(digits, "0123456789abcdef") != "" {

				return false
			}
			continue
		}
		if strings.Trim(digits, "0123456789") != "" {

			return false
		}
	}
	return true
}
