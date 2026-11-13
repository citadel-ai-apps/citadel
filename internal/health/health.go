// Package health probes a tenant instance through the edge proxy.
//
// Two facts force this shape, both verified rather than assumed:
//
//  1. The control plane CANNOT reach a tenant by dialling its bridge IP. The
//     host-protection `INPUT -i br-t-+ -j DROP` rule also drops the SYN-ACK
//     of a host-initiated connection, so host→tenant is blocked as well as
//     tenant→host (design.md §9.3). Every check goes through the edge
//     with a Host header, which is FORWARD-path traffic and unaffected.
//
//  2. `/api/health` LIES. A version-mismatched binary starts, logs a warning and
//     serves /api/health 200 while auth and settings are broken
//     (design.md INV-4). So "healthy" means a real data-plane
//     request succeeded, not that the health endpoint answered.
//
// It makes no Docker calls, which is why it is not in internal/driver.
package health

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// LegacyRefreshPath is the superuser token refresh endpoint before PocketBase
// 0.23.
const LegacyRefreshPath = "/api/admins/auth-refresh"

// RefreshPath is the superuser token refresh endpoint from 0.23 onward.
const RefreshPath = "/api/collections/_superusers/auth-refresh"

// HealthPath is the liveness endpoint. Necessary but never sufficient.
const HealthPath = "/api/health"

// Checker probes instances through the edge.
type Checker struct {
	client   *http.Client
	edgeAddr string
}

// NewChecker returns a Checker that reaches the edge at host:port on the
// loopback interface.
func NewChecker(edgeHost string, edgePort int) *Checker {

	addr := net.JoinHostPort(edgeHost, strconv.Itoa(edgePort))
	return &Checker{
		edgeAddr: addr,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// No redirect following: a redirect would mean the edge routed this
			// somewhere other than the tenant, which is a result, not a step.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Ping reports whether the instance answers /api/health through the edge.
func (c *Checker) Ping(ctx context.Context, hostname string) error {

	resp, err := c.do(ctx, http.MethodGet, hostname, HealthPath, nil)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {

		return fmt.Errorf("health: %s%s returned %d", hostname, HealthPath, resp.StatusCode)
	}
	return nil
}

// TokenSource produces a superuser token for one data-plane attempt. The
// control plane signs a fresh one from pb_data for every attempt (an instance
// that is still migrating may not have its superusers yet); the rehearsal probe,
// which cannot read pb_data, is handed one.
type TokenSource func(ctx context.Context) (string, error)

// StaticToken is a TokenSource that always returns tok.
func StaticToken(tok string) TokenSource {

	return func(context.Context) (string, error) { return tok, nil }
}

// DataPlane presents a superuser token and requires a fresh one back.
//
// This is what "healthy" means. It is the check that caught the one-way
// migration's silent failure on a real tenant: old binary on migrated data
// served /api/health 200 and failed superuser auth (design.md INV-4). A refresh
// is as demanding as a password login was: the instance has to load the
// account from its database and verify the signature against secrets stored
// there. It needs no password, so none is stored, and it is not tied to any one
// account: the token is signed for whichever superuser exists.
func (c *Checker) DataPlane(ctx context.Context, hostname, pbVersion, token string) error {

	path := RefreshPath
	if legacy(pbVersion) {

		path = LegacyRefreshPath
	}
	resp, err := c.doAuth(ctx, http.MethodPost, hostname, path, token)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {

		return fmt.Errorf("health: superuser auth refresh at %s%s returned %d: %s",
			hostname, path, resp.StatusCode, trim(raw, 200))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {

		return fmt.Errorf("health: superuser auth refresh at %s%s returned 200 with no token: %s",
			hostname, path, trim(raw, 200))
	}
	return nil
}

// WaitReady polls Ping then DataPlane until both pass or the budget runs out.
//
// The budget is 60 s: a cold start is well under a second (design.md §4), but a tenant's own pb_migrations run at startup and a large one takes
// real time.
func (c *Checker) WaitReady(ctx context.Context, hostname, pbVersion string, token TokenSource, budget time.Duration) error {

	deadline := time.Now().Add(budget)
	var lastErr error
	for {

		if err := c.Ping(ctx, hostname); err != nil {

			lastErr = err

		} else if tok, err := token(ctx); err != nil {

			lastErr = err

		} else if err := c.DataPlane(ctx, hostname, pbVersion, tok); err != nil {

			lastErr = err

		} else {

			return nil
		}
		if time.Now().After(deadline) {

			return fmt.Errorf("health: %s did not become ready within %s: %w", hostname, budget, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// SmokeRequest is one manifest smoke entry, replayed after a deploy and during
// upgrade rehearsal (§6, §12). Declared here rather than imported so this
// package stays a leaf: it is the one thing in the control plane that talks to
// a tenant over HTTP, and it should depend on nothing that might one day want
// to talk to a tenant over HTTP.
type SmokeRequest struct {
	Method       string
	Path         string
	ExpectStatus int
}

// Expect issues one request through the edge and requires the given status.
func (c *Checker) Expect(ctx context.Context, hostname, method, path string, want int) error {

	resp, err := c.do(ctx, method, hostname, path, nil)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != want {

		return fmt.Errorf("health: %s %s%s returned %d, want %d: %s",
			method, hostname, path, resp.StatusCode, want, trim(raw, 200))
	}
	return nil
}

// Replay runs a release's smoke set and stops at the first failure.
//
// This is how the platform tells a tenant "your app still works" with evidence.
// A deploy that passes the health check and fails here is rolled back: §12
// showed a version-mismatched binary serving /api/health happily while its data
// plane was broken, and only real requests catch that.
func (c *Checker) Replay(ctx context.Context, hostname string, reqs []SmokeRequest) error {

	for i, r := range reqs {

		if err := c.Expect(ctx, hostname, r.Method, r.Path, r.ExpectStatus); err != nil {

			return fmt.Errorf("smoke[%d] failed: %w", i, err)
		}
	}
	return nil
}

func (c *Checker) do(ctx context.Context, method, hostname, path string, body []byte) (*http.Response, error) {

	return c.send(ctx, method, hostname, path, body, "")
}

// doAuth sends a bodiless request carrying a PocketBase token. The token goes
// in the header and nowhere else: never a URL, never an error string.
func (c *Checker) doAuth(ctx context.Context, method, hostname, path, token string) (*http.Response, error) {

	return c.send(ctx, method, hostname, path, nil, token)
}

func (c *Checker) send(ctx context.Context, method, hostname, path string, body []byte, token string) (*http.Response, error) {

	var rdr io.Reader
	if body != nil {

		rdr = bytes.NewReader(body)
	}
	// The URL targets the edge; the Host header is what selects the tenant
	// (routing is by subdomain).
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.edgeAddr+path, rdr)
	if err != nil {

		return nil, err
	}
	req.Host = hostname
	if body != nil {

		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {

		req.Header.Set("Authorization", token)
	}
	resp, err := c.client.Do(req)
	if err != nil {

		return nil, fmt.Errorf("health: %s %s via edge %s: %w", method, hostname+path, c.edgeAddr, err)
	}
	return resp, nil
}

// legacy mirrors the version split in the PocketBase CLI and auth API.
func legacy(version string) bool {

	var major, minor int
	if n, _ := fmt.Sscanf(version, "%d.%d", &major, &minor); n < 2 {

		return false
	}
	return major == 0 && minor < 23
}

func trim(b []byte, n int) string {

	if len(b) > n {

		return string(b[:n]) + "…"
	}
	return string(b)
}
