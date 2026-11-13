// Package proxyctl drives the Caddy edge proxy (design §10).
//
// Caddy's admin API is bound to a UNIX SOCKET, not a TCP port. Design §10 calls
// for the admin API, and the host probes established the contract that the admin
// endpoint must never be reachable from a tenant network — which is a live
// concern here because the join-every-network design gives Caddy an interface on
// every tenant bridge. A socket satisfies both: there is no listener for a
// tenant to reach at all, and the control plane reaches it through a
// root-only bind mount.
//
// This replaces the obvious approach (write a per-tenant Caddyfile fragment,
// then `docker exec caddy reload`), which needed an exec path into a platform
// container and had no rollback if a reload failed.
package proxyctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// AdminSocketName is the admin socket inside the edge container's bind mount.
const AdminSocketName = "admin.sock"

// adminMount is where the admin socket directory appears in the container.
const adminMount = "/run/caddy-admin"

// serverName is the Caddy HTTP server the control plane owns.
const serverName = "edge"

// upstreamPort is the port PocketBase listens on inside a tenant container.
const upstreamPort = config.PocketBasePort

// Resource bounds for the edge container.
const (
	edgePidsLimit   = 512
	edgeMemoryBytes = 1 << 30
)

func ptr[T any](v T) *T { return &v }

// Controller manages the edge proxy.
type Controller struct {
	cfg    config.Config
	docker client.APIClient
	admin  *http.Client
	log    *slog.Logger
	// usernsBase is the host uid that container uid 0 maps to, or 0 when the
	// daemon has no userns-remap. Caddy runs as root inside its container, so
	// its view of the admin directory is at this uid on the host.
	usernsBase int
}

// New returns a Controller.
func New(cfg config.Config, docker client.APIClient, log *slog.Logger, usernsBase int) *Controller {

	sock := filepath.Join(cfg.EdgeAdminDir, AdminSocketName)
	return &Controller{
		cfg:        cfg,
		docker:     docker,
		log:        log,
		usernsBase: usernsBase,
		admin: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {

					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
		},
	}
}

// bootstrapConfig is the Caddyfile-equivalent JSON the edge starts with.
//
// The catch-all 404 route is last and matches everything, so a request for a
// hostname the platform does not serve gets a clear answer rather than a
// connection that hangs.
func (c *Controller) bootstrapConfig() map[string]any {

	return map[string]any{
		"admin": map[string]any{
			// Loopback-only is not enough here: Caddy acquires an interface on
			// every tenant bridge, so the admin endpoint gets a unix socket and
			// no TCP listener at all (§10, design.md §10).
			"listen": "unix/" + adminMount + "/" + AdminSocketName,
		},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					serverName: map[string]any{
						"listen": []string{":" + strconv.Itoa(c.cfg.EdgeHTTPPort)},
						// auto_https off: TLS needs a real wildcard
						// certificate). Turning it on here would make Caddy
						// try to issue certificates for every tenant hostname
						// under the apps domain.
						"automatic_https": map[string]any{"disable": true},
						"routes":          []any{catchAllRoute()},
					},
				},
			},
		},
	}
}

func catchAllRoute() map[string]any {

	return map[string]any{
		"@id": "v2p-catchall",
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": 404,
			"body":        "no such app\n",
		}},
	}
}

// EnsureEdge makes sure the Caddy edge container is running with the config the
// control plane expects, and that its admin socket answers.
//
// The edge is the one container that publishes a host port: tenants are forbidden
// published ports on TENANT containers, and the whole point of the edge is to
// be the single place ingress enters. It stays on runc — runsc is for tenant
// workloads, and the edge is platform code.
func (c *Controller) EnsureEdge(ctx context.Context) error {

	if err := c.ensureAdminDir(); err != nil {

		return err
	}

	insp, err := c.docker.ContainerInspect(ctx, c.cfg.EdgeContainer)
	switch {

	case err == nil:
		// The image it is RUNNING, not merely that it is running. Pointing
		// edge_image at a new digest — the whole reason images/edge-caddy
		// exists — would otherwise change nothing, and the platform would keep
		// reporting a rate-limit gap it had already been given the fix for.
		// egressctl learned the same lesson the same way (design.md
		// §8.3).
		if stale := c.staleImage(ctx, insp); stale != "" {

			c.log.Warn("recreating the edge proxy", "reason", stale,
				"container", c.cfg.EdgeContainer)
			if err := c.docker.ContainerRemove(ctx, c.cfg.EdgeContainer,
				container.RemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {

				return err
			}
			break
		}
		if insp.State != nil && insp.State.Running && c.adminReachable(ctx) {

			return nil
		}
		if insp.State != nil && !insp.State.Running {

			if err := c.docker.ContainerStart(ctx, insp.ID, container.StartOptions{}); err == nil {

				if c.waitAdmin(ctx, 10*time.Second) == nil {

					return nil
				}
			}
		}
		// Running but the admin socket does not answer: recreate. This costs
		// every tenant network attachment, which EnsureAttachments restores on
		// the same tick — without that restoration the routes resolve
		// to nothing after a reboot.
		c.log.Warn("recreating the edge proxy: its admin socket is not answering",
			"container", c.cfg.EdgeContainer)
		if err := c.docker.ContainerRemove(ctx, c.cfg.EdgeContainer,
			container.RemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {

			return err
		}
	case client.IsErrNotFound(err):
	default:
		return fmt.Errorf("proxyctl: inspect %s: %w", c.cfg.EdgeContainer, err)
	}

	if err := c.writeBootstrap(); err != nil {

		return err
	}
	if err := c.pullEdgeImage(ctx); err != nil {

		return err
	}

	port := nat.Port(strconv.Itoa(c.cfg.EdgeHTTPPort) + "/tcp")
	created, err := c.docker.ContainerCreate(ctx,
		&container.Config{
			Image: c.cfg.EdgeImage,
			Cmd:   []string{"caddy", "run", "--config", adminMount + "/caddy.json"},
			Labels: map[string]string{
				netpolicy.LabelManaged: "true",
				"v2p.role":             "edge",
			},
			ExposedPorts: nat.PortSet{port: struct{}{}},
		},
		&container.HostConfig{
			Binds: []string{c.cfg.EdgeAdminDir + ":" + adminMount + ":rw"},
			// The edge survives a control-plane restart on its own: an outage of
			// the control plane should not take ingress down with it.
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			PortBindings:  nat.PortMap{port: []nat.PortBinding{{HostPort: strconv.Itoa(c.cfg.EdgeHTTPPort)}}},
			Runtime:       "runc",
			// The edge sits on every tenant bridge and parses every tenant's
			// traffic, so it gets the platform-container baseline: no
			// capabilities beyond binding its port, no privilege gain through
			// exec, and bounded memory and processes so a flood of requests
			// cannot take the host with it.
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"NET_BIND_SERVICE"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Resources: container.Resources{
				PidsLimit: ptr(int64(edgePidsLimit)),
				Memory:    edgeMemoryBytes,
			},
		}, nil, nil, c.cfg.EdgeContainer)
	if err != nil {

		return fmt.Errorf("proxyctl: create %s: %w", c.cfg.EdgeContainer, err)
	}
	if err := c.docker.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return fmt.Errorf("proxyctl: start %s: %w", c.cfg.EdgeContainer, err)
	}
	return c.waitAdmin(ctx, 30*time.Second)
}

// ensureAdminDir creates the admin directory and gives it to the uid Caddy runs
// as on the host.
//
// Under userns-remap (D3) the edge container's root is host uid <base>, so a
// root-owned 0700 directory is unreadable to it and Caddy exits with "permission
// denied" on its own config before it ever opens the admin socket. The
// directory holds Caddy's config and socket and nothing secret; 0700 at the
// remapped uid still excludes every other uid on the host, and tenant
// containers run as <base>+10001 and have no mount of it in any case.
// staleImage names why the running edge is not the image the config asks for,
// or "" when it is.
//
// Compared by resolved ID as well as by reference: a tag can be rebuilt in
// place, and "same tag" is not "same image".
func (c *Controller) staleImage(ctx context.Context, insp container.InspectResponse) string {

	if insp.Config != nil && insp.Config.Image != c.cfg.EdgeImage {

		return fmt.Sprintf("running image %s, want %s", insp.Config.Image, c.cfg.EdgeImage)
	}
	// An edge created before its hardening keeps running without it until it
	// is recreated, so the missing capability drop is itself a reason to.
	if insp.HostConfig != nil && !slices.ContainsFunc(insp.HostConfig.CapDrop, func(c string) bool {

		return strings.EqualFold(c, "ALL") || strings.EqualFold(c, "CAP_ALL")
	}) {

		return "created without the edge's capability drop and resource limits"
	}
	img, err := c.docker.ImageInspect(ctx, c.cfg.EdgeImage)
	if err != nil {

		return "" // not pulled yet; pullEdgeImage reports that
	}
	if insp.Image != img.ID {

		return "running a different build of the same tag"
	}
	return ""
}

func (c *Controller) ensureAdminDir() error {

	dir := c.cfg.EdgeAdminDir
	if err := os.MkdirAll(dir, 0o700); err != nil {

		return fmt.Errorf("proxyctl: mkdir %s: %w", dir, err)
	}
	if err := os.Chown(dir, c.usernsBase, c.usernsBase); err != nil {

		return fmt.Errorf("proxyctl: chown %s to %d: %w", dir, c.usernsBase, err)
	}
	return nil
}

func (c *Controller) writeBootstrap() error {

	b, err := json.MarshalIndent(c.bootstrapConfig(), "", "  ")
	if err != nil {

		return err
	}
	path := filepath.Join(c.cfg.EdgeAdminDir, "caddy.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {

		return err
	}
	if err := os.Chown(tmp, c.usernsBase, c.usernsBase); err != nil {

		return fmt.Errorf("proxyctl: chown %s to %d: %w", tmp, c.usernsBase, err)
	}
	return os.Rename(tmp, path)
}

func (c *Controller) pullEdgeImage(ctx context.Context) error {

	if _, err := c.docker.ImageInspect(ctx, c.cfg.EdgeImage); err == nil {

		return nil
	}
	rc, err := c.docker.ImagePull(ctx, c.cfg.EdgeImage, image.PullOptions{})
	if err != nil {

		return fmt.Errorf("proxyctl: pull %s: %w", c.cfg.EdgeImage, err)
	}
	defer rc.Close()
	_, err = io.Copy(io.Discard, rc)
	return err
}

func (c *Controller) adminReachable(ctx context.Context) bool {

	resp, err := c.get(ctx, "/config/apps/http/servers/"+serverName+"/listen")
	if err != nil {

		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func (c *Controller) waitAdmin(ctx context.Context, budget time.Duration) error {

	deadline := time.Now().Add(budget)
	for {

		if c.adminReachable(ctx) {

			return nil
		}
		if time.Now().After(deadline) {

			return fmt.Errorf("proxyctl: edge admin socket %s did not answer within %s",
				filepath.Join(c.cfg.EdgeAdminDir, AdminSocketName), budget)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// routeID is the Caddy @id of a tenant's route, which is how the control plane
// addresses it for replacement and deletion without rewriting the whole config.
func routeID(slug string) string { return "v2p-route-" + slug }

// RateLimit is one per-tenant limit at the edge (§10).
//
// Separate limits for /api/ and /_/ because they fail differently: an app
// hammering its own API is usually a bug in the app, while sustained traffic to
// the admin UI is usually someone else.
type RateLimit struct {
	Name       string
	PathPrefix string
	Events     int
	Window     time.Duration
}

// RouteSpec is everything the edge needs to know about one tenant.
type RouteSpec struct {
	Slug     string
	Hostname string
	BodyCap  string
	// Quarantined replaces the reverse proxy with a 503 and touches nothing
	// else (§12). The container keeps running, the data is untouched, and the
	// tenant is reachable again the moment the flag comes off.
	Quarantined bool
	RateLimits  []RateLimit
	// DenySources are client ranges the route never answers: the tenant
	// subnet pool and the egress subnet. Filled in by the Controller from its
	// own configuration, never by the caller.
	DenySources []string
}

// tenantRoute is the per-tenant route.
//
// Four settings are not decoration:
//
//   - flush_interval -1 disables response buffering. PocketBase realtime is
//     SSE; a buffering proxy breaks it silently and the tenant blames their own
//     code (§10).
//   - max_size returns 413 at the edge, so an oversized upload never reaches
//     the tenant's disk quota.
//   - rate_limit keys on the client address, per tenant and per path group.
//   - The upstream is the container NAME, resolved by Docker's embedded resolver
//     on the tenant network. That is why the container is named pb-<slug> and
//     why it needs no published port.
func tenantRoute(spec RouteSpec, withLimits bool) map[string]any {

	handlers := []any{}
	if withLimits && len(spec.RateLimits) > 0 {

		handlers = append(handlers, rateLimitHandler(spec))
	}
	handlers = append(handlers, map[string]any{
		"handler":  "request_body",
		"max_size": parseSize(spec.BodyCap),
	})

	if spec.Quarantined {

		handlers = append(handlers, map[string]any{
			"handler":     "static_response",
			"status_code": 503,
			"headers":     map[string]any{"Retry-After": []string{"3600"}},
			"body":        "This instance is temporarily unavailable. Its data is untouched.\n",
		})

	} else {

		proxy := map[string]any{
			"handler":        "reverse_proxy",
			"upstreams":      []any{map[string]any{"dial": config.ContainerName(spec.Slug) + ":" + upstreamPort}},
			"flush_interval": -1,
			// PocketBase's realtime stream is long-lived; a read timeout
			// here would cut it at the proxy.
			"transport": map[string]any{
				"protocol":                "http",
				"response_header_timeout": 0,
			},
		}
		// The admin handoff page is answered by the edge itself and never
		// proxied (bridge.go); everything else goes to the tenant.
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				bridgeRoute(),
				map[string]any{"handle": []any{proxy}},
			},
		})
	}

	match := map[string]any{"host": []string{spec.Hostname}}
	if len(spec.DenySources) > 0 {

		// Second line behind the tenant's intra-network accept, which only
		// admits the edge dialling the tenant: a request whose client address
		// is a tenant's — reaching the edge on its own bridge and naming
		// another tenant's Host — matches no tenant route and falls through to
		// the catch-all 404.
		match["not"] = []any{map[string]any{"remote_ip": map[string]any{"ranges": spec.DenySources}}}
	}
	return map[string]any{
		"@id":      routeID(spec.Slug),
		"match":    []any{match},
		"handle":   handlers,
		"terminal": true,
	}
}

// tenantSources are the client ranges a tenant route refuses: anything a
// tenant container can be addressed from.
func (c *Controller) tenantSources() []string {

	var out []string
	for _, cidr := range []string{c.cfg.SubnetPool, c.cfg.EgressSubnet} {

		if cidr != "" {

			out = append(out, cidr)
		}
	}
	return out
}

// rateLimitHandler renders the caddy-ratelimit module's configuration.
//
// Zones are named per tenant so one tenant's traffic cannot consume another's
// budget, and keyed on the client address so one abusive client cannot lock the
// tenant's own users out.
func rateLimitHandler(spec RouteSpec) map[string]any {

	zones := map[string]any{}
	for _, rl := range spec.RateLimits {

		zones["v2p-"+spec.Slug+"-"+rl.Name] = map[string]any{
			"match":      []any{map[string]any{"path": []string{rl.PathPrefix}}},
			"key":        "{http.request.remote.host}",
			"window":     rl.Window.String(),
			"max_events": rl.Events,
		}
	}
	return map[string]any{
		"handler":     "rate_limit",
		"rate_limits": zones,
		// The key is a client address; keeping it out of the log avoids
		// writing one every time someone is throttled.
		"log_key": false,
	}
}

// PublishRoute installs or replaces a tenant's route, reporting whether the
// rate limits went with it.
//
// Routes are inserted ahead of the catch-all, which is the last route and
// matches everything. Replacing by @id is idempotent, so a reconcile tick that
// publishes an unchanged route is a no-op at the proxy.
//
// A stock caddy:2 has no rate_limit handler and rejects the whole route rather
// than the one handler it does not know. Rather than let a rejected route take
// ingress down, the publish is retried without the limits and the caller is told
// — a missing control has to be visible, not silent, and an unreachable tenant
// is a worse answer than a rate-limit gap an operator can see on the fleet view.
func (c *Controller) PublishRoute(ctx context.Context, spec RouteSpec) (rateLimited bool, err error) {

	if len(spec.RateLimits) > 0 {

		if err := c.publish(ctx, spec, true); err == nil {

			return true, nil

		} else {

			c.log.Warn("the edge rejected a route carrying per-tenant rate limits; "+
				"republishing without them. The running edge image probably has no rate_limit handler "+
				"— build images/edge-caddy and point edge_image at its digest",
				"tenant", spec.Slug, "err", err)
		}
	}
	return false, c.publish(ctx, spec, false)
}

func (c *Controller) publish(ctx context.Context, spec RouteSpec, withLimits bool) error {

	spec.DenySources = c.tenantSources()
	body, err := json.Marshal(tenantRoute(spec, withLimits))
	if err != nil {

		return err
	}
	// PATCH on an existing @id replaces it in place; if it does not exist yet,
	// prepend it to the route list.
	resp, err := c.request(ctx, http.MethodPatch, "/id/"+routeID(spec.Slug), body)
	if err != nil {

		return err
	}
	drain(resp)
	if resp.StatusCode/100 == 2 {

		return nil
	}
	// The PATCH can fail for two different reasons, and only one of them means
	// "no such route": Caddy also rejects a route whose handlers it cannot
	// load. In that case the @id still exists, and prepending another copy
	// earns "duplicate ID ... found at routes/0 and routes/1" — which then
	// looks like the handler problem all over again. Delete first, so the PUT
	// below is always an insert.
	if resp, err := c.request(ctx, http.MethodDelete, "/id/"+routeID(spec.Slug), nil); err == nil {

		drain(resp)
	}
	resp, err = c.request(ctx, http.MethodPut,
		"/config/apps/http/servers/"+serverName+"/routes/0", body)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode/100 != 2 {

		return fmt.Errorf("proxyctl: publish route for %s: %d: %s", spec.Slug, resp.StatusCode, raw)
	}
	return nil
}

// RemoveRoute deletes a tenant's route. A route that is already gone is not an
// error: teardown has to be re-runnable.
func (c *Controller) RemoveRoute(ctx context.Context, slug string) error {

	resp, err := c.request(ctx, http.MethodDelete, "/id/"+routeID(slug), nil)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusNotFound {

		return nil
	}
	return fmt.Errorf("proxyctl: remove route for %s: %d: %s", slug, resp.StatusCode, raw)
}

// RouteIDs lists the tenant slugs the edge currently has routes for.
//
// Read from the running proxy, not from the config file on disk: §14.5 requires
// the attestation to observe "the ACL as loaded in the running proxy", and the
// same logic applies to drift detection here.
func (c *Controller) RouteIDs(ctx context.Context) (map[string]bool, error) {

	resp, err := c.get(ctx, "/config/apps/http/servers/"+serverName+"/routes")
	if err != nil {

		return nil, err
	}
	defer resp.Body.Close()
	var routes []struct {
		ID string `json:"@id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {

		return nil, fmt.Errorf("proxyctl: decode routes: %w", err)
	}
	out := map[string]bool{}
	for _, r := range routes {

		if slug, ok := trimPrefix(r.ID, "v2p-route-"); ok {

			out[slug] = true
		}
	}
	return out, nil
}

// EnsureAttachment joins the edge to a tenant's network at its pinned address.
//
// Re-asserted on every reconcile tick. A boot recovery that recreates the
// edge container without re-joining the tenant networks leaves every
// upstream name failed to resolve and no tenant was reachable — the reconciler
// owning this idempotently is the fix.
//
// Checked against the SDK's network map by exact key, not by grepping inspect
// JSON: a substring match would let `t-demo` false-positive against `t-demo2`.
func (c *Controller) EnsureAttachment(ctx context.Context, slug, edgeIP string) error {

	insp, err := c.docker.ContainerInspect(ctx, c.cfg.EdgeContainer)
	if err != nil {

		return fmt.Errorf("proxyctl: inspect %s: %w", c.cfg.EdgeContainer, err)
	}
	netName := config.NetworkName(slug)
	if ep, ok := insp.NetworkSettings.Networks[netName]; ok {

		if ep.IPAddress == edgeIP {

			return nil
		}
		// Attached at the wrong address: firewall rules and proxy ACLs are
		// written against these addresses, so a drifted one must be corrected
		// rather than tolerated (§8.1).
		if err := c.docker.NetworkDisconnect(ctx, netName, c.cfg.EdgeContainer, true); err != nil {

			return fmt.Errorf("proxyctl: disconnect %s from %s: %w", c.cfg.EdgeContainer, netName, err)
		}
	}
	err = c.docker.NetworkConnect(ctx, netName, c.cfg.EdgeContainer, &network.EndpointSettings{
		IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: edgeIP},
	})
	if err != nil {

		return fmt.Errorf("proxyctl: connect %s to %s at %s: %w", c.cfg.EdgeContainer, netName, edgeIP, err)
	}
	return nil
}

// DetachNetwork removes the edge from a tenant's network, which must happen
// before the network can be deleted.
func (c *Controller) DetachNetwork(ctx context.Context, slug string) error {

	err := c.docker.NetworkDisconnect(ctx, config.NetworkName(slug), c.cfg.EdgeContainer, true)
	if err == nil || client.IsErrNotFound(err) || alreadyDetached(err) {

		return nil
	}
	return fmt.Errorf("proxyctl: disconnect %s from %s: %w", c.cfg.EdgeContainer, config.NetworkName(slug), err)
}

// alreadyDetached recognises Docker's answer when the edge is not on the
// network at all.
//
// Detach has to be idempotent: it runs on every teardown tick until the tenant
// row is gone, and the engine reports "container ... is not connected to the
// network ..." rather than a not-found error. Treating that as a failure wedges
// the teardown forever — the destroy never completes, the row never clears, and
// the next provisioning of the same slug is refused by the unique hostname
// index. Observed in the acceptance suite.
//
// The wording differs between engine versions — older ones say "is not
// connected to the network X", newer ones "is not connected to network X" —
// so match the common prefix (as egressctl does). Matching the older phrase
// only wedged a teardown on a Debian 13 host.
func alreadyDetached(err error) bool {

	return err != nil && strings.Contains(err.Error(), "is not connected to")
}

// AttachedNetworks lists the tenant networks the edge is currently joined to.
func (c *Controller) AttachedNetworks(ctx context.Context) (map[string]string, error) {

	insp, err := c.docker.ContainerInspect(ctx, c.cfg.EdgeContainer)
	if err != nil {

		return nil, err
	}
	out := map[string]string{}
	for name, ep := range insp.NetworkSettings.Networks {

		if slug, ok := trimPrefix(name, "t-"); ok {

			out[slug] = ep.IPAddress
		}
	}
	return out, nil
}

func (c *Controller) get(ctx context.Context, path string) (*http.Response, error) {

	return c.request(ctx, http.MethodGet, path, nil)
}

func (c *Controller) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {

	var rdr io.Reader
	if body != nil {

		rdr = bytes.NewReader(body)
	}
	// The host in the URL is ignored: the transport dials the unix socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://caddy-admin"+path, rdr)
	if err != nil {

		return nil, err
	}
	if body != nil {

		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.admin.Do(req)
	if err != nil {

		return nil, fmt.Errorf("proxyctl: %s %s: %w", method, path, err)
	}
	return resp, nil
}

func drain(resp *http.Response) {

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func trimPrefix(s, prefix string) (string, bool) {

	if len(s) > len(prefix) && s[:len(prefix)] == prefix {

		return s[len(prefix):], true
	}
	return "", false
}

// ErrNoEdge means the edge container is not present.
var ErrNoEdge = errors.New("proxyctl: edge proxy is not running")
