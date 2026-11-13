package rehearsal

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/health"
)

// egressDialTimeout bounds one outbound attempt.
//
// Short on purpose. On an `internal: true` network the failure is an immediate
// "network is unreachable" rather than a timeout, so a long budget only slows
// down the case where something is wrong — and if a target DOES hang instead of
// refusing, that is itself worth reporting quickly rather than waiting out.
const egressDialTimeout = 3 * time.Second

// Run executes a plan and returns the report. It never returns an error for a
// failed rehearsal: a failure is a result.
func Run(ctx context.Context, p Plan, token string) Report {

	started := time.Now()
	rep := Report{}
	defer func() { rep.Elapsed = Duration(time.Since(started)) }()

	host, port, err := splitTarget(p.Target)
	if err != nil {

		rep.Error = err.Error()
		return rep
	}
	c := health.NewChecker(host, port)

	// Egress first, and unconditionally. If the instance never comes up the
	// isolation evidence is still wanted: "the rehearsal failed" and "the
	// rehearsal could reach the internet" are independent findings, and the
	// second one does not stop mattering because the first happened.
	rep.Egress = probeEgress(ctx, p.Egress)

	budget := p.ReadyBudget.D()
	if budget <= 0 {

		budget = time.Minute
	}
	if err := c.WaitReady(ctx, p.Hostname, p.PBVersion, health.StaticToken(token), budget); err != nil {

		rep.Error = err.Error()
		return rep
	}
	rep.Ready, rep.Auth = true, true

	if p.Healthcheck != nil {

		step := StepResult{Method: p.Healthcheck.Method, Path: p.Healthcheck.Path, Want: p.Healthcheck.ExpectStatus}
		if err := c.Expect(ctx, p.Hostname, step.Method, step.Path, step.Want); err != nil {

			step.Error = err.Error()

		} else {

			step.OK = true
		}
		rep.Health = append(rep.Health, step)
	}
	for _, s := range p.Smoke {

		step := StepResult{Method: s.Method, Path: s.Path, Want: s.ExpectStatus}
		if err := c.Expect(ctx, p.Hostname, s.Method, s.Path, s.ExpectStatus); err != nil {

			step.Error = err.Error()

		} else {

			step.OK = true
		}
		// Every step runs, rather than stopping at the first failure as a deploy
		// does. A tenant reading a rehearsal report wants the whole list of what
		// broke, not the first thing — they are about to go and fix it.
		rep.Smoke = append(rep.Smoke, step)
	}
	rep.Passed = rep.Verdict()
	return rep
}

// Verdict is the pass/fail rule, in one place so the probe and any reader of a
// stored report agree.
//
// A connected egress target fails the rehearsal. It means the isolation §12
// promises did not hold, and continuing to an upgrade on that basis would be
// upgrading on the strength of a test that was not the test described.
func (r Report) Verdict() bool {

	if !r.Ready || !r.Auth {

		return false
	}
	for _, s := range r.Health {

		if !s.OK {

			return false
		}
	}
	for _, s := range r.Smoke {

		if !s.OK {

			return false
		}
	}
	for _, e := range r.Egress {

		if e.Connected {

			return false
		}
	}
	return true
}

// Failures renders the report's failed steps as lines for the tenant.
func (r Report) Failures() []string {

	var out []string
	if !r.Ready {

		out = append(out, "the instance did not become ready on the target version")
	}
	if r.Error != "" {

		out = append(out, r.Error)
	}
	for _, s := range append(append([]StepResult{}, r.Health...), r.Smoke...) {

		if !s.OK {

			out = append(out, fmt.Sprintf("%s %s: %s", s.Method, s.Path, s.Error))
		}
	}
	for _, e := range r.Egress {

		if e.Connected {

			out = append(out, "SECURITY: the rehearsal reached "+e.Target+", which it must not")
		}
	}
	return out
}

func probeEgress(ctx context.Context, targets []string) []EgressResult {

	var out []EgressResult
	for _, t := range targets {

		res := EgressResult{Target: t}
		d := net.Dialer{Timeout: egressDialTimeout}
		conn, err := d.DialContext(ctx, "tcp", t)
		if err != nil {

			res.Error = err.Error()

		} else {

			// Reported, not merely closed: this is the finding, and the report
			// is the only place it exists.
			res.Connected = true
			conn.Close()
		}
		out = append(out, res)
	}
	return out
}

func splitTarget(target string) (string, int, error) {

	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {

		return "", 0, fmt.Errorf("rehearsal: target %q is not host:port: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {

		return "", 0, fmt.Errorf("rehearsal: target %q has no numeric port", target)
	}
	return host, port, nil
}
