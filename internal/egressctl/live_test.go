package egressctl

import (
	"errors"
	"slices"
	"testing"
)

// The manager dump is the only evidence of what the proxy is ACTUALLY
// enforcing. A parser that silently returns nothing on an unexpected line would
// make every tenant look like it can reach nothing, which reads as "no
// problem" on exactly the screen that must never be wrong.
func TestParseLiveACLReadsTheDstdomainLines(t *testing.T) {

	dump := `
http_port 3128 ssl-bump tls-cert=/etc/squid/bump.pem
acl SSL_ports port 443
acl v2p_mgr src 10.214.0.1
acl t_t_abc123_src src 10.214.0.3
acl t_t_abc123_dst dstdomain api.stripe.com hooks.slack.com
acl t_t_abc123_sni ssl::server_name api.stripe.com hooks.slack.com
http_access allow t_t_abc123_src t_t_abc123_dst
acl t_t_def456_src src 10.214.0.4
acl t_t_def456_dst dstdomain example.com
http_access deny all
`
	got := parseLiveACL(dump)
	if len(got) != 2 {

		t.Fatalf("parsed %d tenants, want 2: %+v", len(got), got)
	}
	want := []string{"api.stripe.com", "hooks.slack.com"}
	if !slices.Equal(got["t_abc123"], want) {

		t.Fatalf("t_abc123 = %v, want %v", got["t_abc123"], want)
	}
	if !slices.Equal(got["t_def456"], []string{"example.com"}) {

		t.Fatalf("t_def456 = %v", got["t_def456"])
	}
}

// The SNI lines terminate a mismatched handshake; the dstdomain lines are what
// gate a request. Reading both would double-count and, worse, would report a
// host as reachable on a proxy build with no ssl_bump support.
func TestParseLiveACLIgnoresSNIAndSourceLines(t *testing.T) {

	dump := `acl t_x_sni ssl::server_name only.sni.example
acl t_x_src src 10.214.0.9`

	if got := parseLiveACL(dump); len(got) != 0 {

		t.Fatalf("parsed %+v from lines that gate nothing", got)
	}
}

func TestParseLiveACLToleratesAnEmptyDump(t *testing.T) {

	if got := parseLiveACL(""); len(got) != 0 {

		t.Fatalf("parsed %+v from an empty dump", got)
	}
}

// Both engine wordings must count as already-detached, or a teardown that
// retries after a partial detach wedges on every tick.
func TestAlreadyDetachedAcceptsBothEngineWordings(t *testing.T) {

	cases := map[string]bool{
		"Error response from daemon: container abc is not connected to the network t-demo": true,
		"Error response from daemon: container abc is not connected to network t-demo":     true,
		"Error response from daemon: permission denied":                                    false,
	}
	for msg, want := range cases {

		if got := alreadyDetached(errors.New(msg)); got != want {

			t.Errorf("alreadyDetached(%q) = %v, want %v", msg, got, want)
		}
	}
	if alreadyDetached(nil) {

		t.Error("alreadyDetached(nil) = true, want false")
	}
}
