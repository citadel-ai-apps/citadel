package proxyctl

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/config"
)

func TestParseSizeFailsClosedAtTheDefault(t *testing.T) {

	cases := map[string]int64{
		"32MB":  32 << 20,
		"32MiB": 32 << 20,
		"1GB":   1 << 30,
		"512KB": 512 << 10,
		"1024":  1024,
		// Unparseable and nonsensical values fall back rather than being handed
		// to Caddy, where a rejected config would take the whole edge's reload
		// with it.
		"":        DefaultBodyCap,
		"lots":    DefaultBodyCap,
		"-5MB":    DefaultBodyCap,
		"0":       DefaultBodyCap,
		"32 MB":   32 << 20,
		" 32mb  ": 32 << 20,
	}
	for in, want := range cases {

		if got := parseSize(in); got != want {

			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestTenantRouteCarriesTheSSEAndBodyCapSettings covers the §10
// must-get-right list. flush_interval -1 is the one that fails silently: a
// buffering proxy breaks PocketBase realtime and the tenant blames their own
// code.
func TestTenantRouteCarriesTheSSEAndBodyCapSettings(t *testing.T) {

	route := tenantRoute(RouteSpec{Slug: "demo", Hostname: "demo.apps.localhost", BodyCap: "32MB"}, false)
	b, err := json.Marshal(route)
	if err != nil {

		t.Fatal(err)
	}
	raw := string(b)

	if !strings.Contains(raw, `"flush_interval":-1`) {

		t.Errorf("route has no flush_interval -1; SSE would be buffered:\n%s", raw)
	}
	if !strings.Contains(raw, `"max_size":33554432`) {

		t.Errorf("route has no 32 MiB body cap:\n%s", raw)
	}
	// Routing is by subdomain, never by path prefix: PocketBase assumes
	// it is at root, so a path prefix breaks the admin UI at /_/.
	if !strings.Contains(raw, `"host":["demo.apps.localhost"]`) {

		t.Errorf("route does not match on host:\n%s", raw)
	}
	top, err := json.Marshal(route["match"])
	if err != nil {

		t.Fatal(err)
	}
	if strings.Contains(string(top), `"path"`) {

		t.Errorf("route matches on a path prefix:\n%s", top)
	}
	// The upstream is the container name, resolved by Docker's embedded resolver
	// on the tenant network — which is why the tenant needs no published port.
	if !strings.Contains(raw, `"dial":"pb-demo:8090"`) {

		t.Errorf("upstream is not pb-demo:8090:\n%s", raw)
	}
	if !strings.Contains(raw, `"@id":"v2p-route-demo"`) {

		t.Errorf("route has no stable @id for idempotent replacement:\n%s", raw)
	}
}

// TestRateLimitsAreScopedPerTenantAndPerPathGroup covers §10: separate budgets
// for /api/ and /_/, and a zone name no other tenant can share.
func TestRateLimitsAreScopedPerTenantAndPerPathGroup(t *testing.T) {

	spec := RouteSpec{
		Slug: "demo", Hostname: "demo.apps.localhost", BodyCap: "32MB",
		RateLimits: []RateLimit{
			{Name: "api", PathPrefix: "/api/*", Events: 600, Window: time.Minute},
			{Name: "admin", PathPrefix: "/_/*", Events: 60, Window: time.Minute},
		},
	}
	b, err := json.Marshal(tenantRoute(spec, true))
	if err != nil {

		t.Fatal(err)
	}
	raw := string(b)

	for _, want := range []string{
		`"v2p-demo-api"`, `"v2p-demo-admin"`,
		`"max_events":600`, `"max_events":60`,
		`"/api/*"`, `"/_/*"`,
	} {

		if !strings.Contains(raw, want) {

			t.Errorf("rate-limited route is missing %s:\n%s", want, raw)
		}
	}
	// Keyed on the client, not the tenant: one abusive client must not be able
	// to lock the tenant's own users out of their instance.
	if !strings.Contains(raw, `"key":"{http.request.remote.host}"`) {

		t.Errorf("rate limit is not keyed on the client address:\n%s", raw)
	}
	// The limiter has to run BEFORE the body is read, or an oversized flood
	// costs the platform the upload before it costs the client the 429.
	if strings.Index(raw, `"rate_limit"`) > strings.Index(raw, `"request_body"`) {

		t.Errorf("rate limit runs after the body handler:\n%s", raw)
	}

	// Without the handler the route must still be a working route, because an
	// unreachable tenant is a worse answer than a visible rate-limit gap.
	plain, _ := json.Marshal(tenantRoute(spec, false))
	if strings.Contains(string(plain), `"rate_limit"`) {

		t.Errorf("the fallback route still carries the rate_limit handler:\n%s", plain)
	}
	if !strings.Contains(string(plain), `"reverse_proxy"`) {

		t.Errorf("the fallback route does not proxy:\n%s", plain)
	}
}

// TestQuarantineServes503AndNeverProxies covers §12's alternative to a forced
// upgrade: ingress stops, the data is untouched.
func TestQuarantineServes503AndNeverProxies(t *testing.T) {

	b, err := json.Marshal(tenantRoute(RouteSpec{
		Slug: "demo", Hostname: "demo.apps.localhost", BodyCap: "32MB", Quarantined: true,
	}, false))
	if err != nil {

		t.Fatal(err)
	}
	raw := string(b)

	if !strings.Contains(raw, `"status_code":503`) {

		t.Errorf("quarantined route does not answer 503:\n%s", raw)
	}
	// If the route still proxies, quarantine is decoration.
	if strings.Contains(raw, `"reverse_proxy"`) {

		t.Errorf("quarantined route still proxies to the tenant:\n%s", raw)
	}
	if !strings.Contains(raw, `"host":["demo.apps.localhost"]`) {

		t.Errorf("quarantined route stopped matching its own hostname:\n%s", raw)
	}
}

// TestAdminListenerIsAUnixSocket: Caddy acquires an interface on every tenant
// bridge under the join-every-network design, so the admin endpoint must not be
// a TCP listener at all (§10, design.md §10).
func TestAdminListenerIsAUnixSocket(t *testing.T) {

	c := &Controller{}
	c.cfg.EdgeHTTPPort = 80
	cfg := c.bootstrapConfig()

	admin, ok := cfg["admin"].(map[string]any)
	if !ok {

		t.Fatal("bootstrap config has no admin block")
	}
	listen, _ := admin["listen"].(string)
	if !strings.HasPrefix(listen, "unix/") {

		t.Fatalf("admin listens on %q; it must be a unix socket, never a TCP port", listen)
	}
	if strings.Contains(listen, ":") {

		t.Fatalf("admin listen %q looks like a host:port", listen)
	}
}

func TestBootstrapConfigHasACatchAllAndNoAutoHTTPS(t *testing.T) {

	c := &Controller{}
	c.cfg.EdgeHTTPPort = 80
	b, err := json.Marshal(c.bootstrapConfig())
	if err != nil {

		t.Fatal(err)
	}
	raw := string(b)
	// A hostname the platform does not serve should get a clear 404 rather than
	// a connection that hangs.
	if !strings.Contains(raw, "no such app") {

		t.Errorf("bootstrap config has no catch-all route:\n%s", raw)
	}
	// TLS is not handled here yet. Leaving automatic HTTPS on would make Caddy
	// try to issue certificates for *.apps.localhost.
	if !strings.Contains(raw, `"automatic_https":{"disable":true}`) {

		t.Errorf("automatic HTTPS is not disabled:\n%s", raw)
	}
}

func TestRouteIDRoundTrip(t *testing.T) {

	id := routeID("demo")
	slug, ok := trimPrefix(id, "v2p-route-")
	if !ok || slug != "demo" {

		t.Fatalf("routeID/trimPrefix round trip gave %q/%v", slug, ok)
	}
	// trimPrefix must not claim the prefix itself, or an empty slug would be
	// reported as a route.
	if _, ok := trimPrefix("v2p-route-", "v2p-route-"); ok {

		t.Error("an empty slug was accepted")
	}
	if _, ok := trimPrefix("v2p-catchall", "v2p-route-"); ok {

		t.Error("the catch-all route was read as a tenant route")
	}
}

// The admin handoff page is answered by the edge, ahead of the proxy, so the
// tenant can never serve that path itself; and its CSP admits exactly the one
// inline script it carries.
func TestAdminBridgeIsServedByTheEdgeAheadOfTheProxy(t *testing.T) {

	route := tenantRoute(RouteSpec{Slug: "demo", Hostname: "demo.apps.localhost", BodyCap: "32MB"}, false)
	handlers := route["handle"].([]any)
	sub := handlers[len(handlers)-1].(map[string]any)
	if sub["handler"] != "subroute" {

		t.Fatalf("last handler is %v, want subroute", sub["handler"])
	}
	routes := sub["routes"].([]any)
	if len(routes) != 2 {

		t.Fatalf("subroute has %d routes, want bridge then proxy", len(routes))
	}
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), `"path":["`+AdminBridgePath+`"]`) ||
		!strings.Contains(string(first), `"static_response"`) || strings.Contains(string(first), `"reverse_proxy"`) {

		t.Fatalf("first subroute is not the edge-served bridge:\n%s", first)
	}
	second, _ := json.Marshal(routes[1])
	if !strings.Contains(string(second), `"reverse_proxy"`) {

		t.Fatalf("second subroute is not the proxy:\n%s", second)
	}

	sum := sha256.Sum256([]byte(bridgeScript))
	if !strings.Contains(bridgeCSP, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {

		t.Fatalf("CSP %q does not admit the bridge script", bridgeCSP)
	}
	if !strings.Contains(bridgeHTML, "<script>"+bridgeScript+"</script>") {

		t.Fatal("the page does not carry the exact script the CSP hashes")
	}
}

func TestQuarantinedRouteHasNoAdminBridge(t *testing.T) {

	b, err := json.Marshal(tenantRoute(RouteSpec{Slug: "demo", Hostname: "demo.apps.localhost", Quarantined: true}, false))
	if err != nil {

		t.Fatal(err)
	}
	if strings.Contains(string(b), AdminBridgePath) {

		t.Fatalf("a quarantined route serves the admin bridge:\n%s", b)
	}
}

// A tenant reaching the edge on its own bridge and naming another tenant's
// Host must match no tenant route.
func TestTenantRouteRefusesTenantSources(t *testing.T) {

	route := tenantRoute(RouteSpec{
		Slug: "demo", Hostname: "demo.apps.localhost", BodyCap: "32MB",
		DenySources: []string{"10.213.0.0/16", "10.214.0.0/24"},
	}, false)
	b, err := json.Marshal(route["match"])
	if err != nil {

		t.Fatal(err)
	}
	want := `[{"host":["demo.apps.localhost"],"not":[{"remote_ip":{"ranges":["10.213.0.0/16","10.214.0.0/24"]}}]}]`
	if string(b) != want {

		t.Fatalf("match = %s\nwant    %s", b, want)
	}
	c := &Controller{cfg: config.Config{SubnetPool: "10.213.0.0/16", EgressSubnet: "10.214.0.0/24"}}
	if got := c.tenantSources(); len(got) != 2 {

		t.Fatalf("tenant sources = %v", got)
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
