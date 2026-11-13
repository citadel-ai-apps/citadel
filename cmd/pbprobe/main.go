// Command pbprobe checks an upgrade rehearsal from inside its network (§12).
//
// It exists because the control plane cannot reach a rehearsal itself. The
// rehearsal bridge matches `br-t-+` — deliberately, because a rehearsal runs
// the tenant's own hooks and must not get the host path that wildcard closes —
// and the host-protection INPUT drop also kills the SYN-ACK of a host-initiated
// connection (design.md §9.3). So something on the network has to do
// the asking, and §12 says it is a throwaway container with nothing else on the
// network beside it.
//
// It ships FROM scratch: one static binary, no shell, no CA bundle. It speaks
// plaintext HTTP to a private address on an internal bridge, and the one thing
// it must never be able to do is reach anything else.
//
// Exit 0 with "passed": false is a rehearsal that failed. A non-zero exit means
// the PROBE failed, which is a different thing and is handled differently.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/rehearsal"
)

// hardStop bounds the whole run regardless of the plan's own budget, so a probe
// can never become the thing that hangs an upgrade job.
const hardStop = 15 * time.Minute

func main() {

	if err := run(); err != nil {

		fmt.Fprintln(os.Stderr, "pbprobe:", err)
		os.Exit(1)
	}
}

func run() error {

	raw, err := os.ReadFile(rehearsal.PlanPath)
	if err != nil {

		return fmt.Errorf("cannot read %s: %w", rehearsal.PlanPath, err)
	}
	var plan rehearsal.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {

		return fmt.Errorf("cannot parse %s: %w", rehearsal.PlanPath, err)
	}
	if plan.Target == "" || plan.Hostname == "" {

		return fmt.Errorf("plan is missing target or hostname")
	}

	ctx, cancel := context.WithTimeout(context.Background(), hardStop)
	defer cancel()

	rep := rehearsal.Run(ctx, plan, os.Getenv(rehearsal.EnvToken))

	out, err := json.Marshal(rep)
	if err != nil {

		return err
	}
	// stdout is the channel: the control plane reads it back through the
	// container log, which is why nothing else is ever printed there.
	fmt.Println(string(out))
	return nil
}
