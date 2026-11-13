// Package rehearsal is the wire contract between the control plane and the
// probe container that runs inside an upgrade rehearsal (§12).
//
// It exists as its own package because both ends need it and neither can import
// the other: cmd/pbprobe ships inside a FROM-scratch image and must not drag in
// Docker, SQLite or the store, and internal/reconcile must not depend on a
// command. Everything here is data plus the probe's own logic.
package rehearsal

import (
	"time"

	"github.com/citadel-ai-apps/citadel/internal/health"
)

// PlanPath is where the probe reads its instructions inside the container.
//
// A file rather than argv: argv is visible to anything that can list processes,
// and the plan names a real tenant's hostname and smoke paths.
const PlanPath = "/plan.json"

// EnvToken is the env var the probe reads its superuser token from. The token
// is NOT in the plan file, so the plan can be written to disk and kept with the
// job.
//
// The control plane signs it from the rehearsal's copy of pb_data before the
// instance boots (internal/pbauth), for the TARGET version's claims. The probe
// never holds a password, because there is none to hold.
const EnvToken = "PB_SUPERUSER_TOKEN"

// Plan is what the control plane asks the probe to check.
type Plan struct {
	// Target is host:port of the rehearsal instance on the rehearsal network.
	Target string `json:"target"`
	// Hostname is the tenant's real hostname, sent as the Host header so the
	// instance sees the requests it would see in production.
	Hostname string `json:"hostname"`
	// PBVersion is the TARGET version, which selects the superuser refresh path:
	// pre-0.23 and later lines differ, and a rehearsal that authenticates at the
	// wrong path reports a failure that is the probe's, not the tenant's.
	PBVersion string `json:"pb_version"`
	// Healthcheck is the manifest's own liveness request, if it declared one.
	Healthcheck *health.SmokeRequest `json:"healthcheck,omitempty"`
	// Smoke is the manifest's smoke set, replayed against the rehearsal. This
	// is what makes a rehearsal more than a health check: a version-mismatched
	// binary serves /api/health 200 with a broken data plane
	// (design.md INV-4).
	Smoke []health.SmokeRequest `json:"smoke,omitempty"`
	// Egress lists host:port targets that MUST fail to connect. The rehearsal
	// network is internal with no proxy attachment, so every one of these is
	// expected to be unreachable; a success is a failed rehearsal AND a
	// platform bug.
	Egress []string `json:"egress,omitempty"`
	// ReadyBudget bounds the wait for the instance to come up, which on a
	// version upgrade includes PocketBase's own system migrations.
	ReadyBudget Duration `json:"ready_budget"`
}

// Report is what the probe hands back on stdout.
//
// Passed is the verdict, and it is carried in the JSON rather than in the exit
// code on purpose: a rehearsal that fails because the tenant's hooks are broken
// is a SUCCESSFUL probe run, and the control plane has to tell that apart from
// a probe that crashed.
type Report struct {
	Passed  bool           `json:"passed"`
	Ready   bool           `json:"ready"`
	Auth    bool           `json:"auth"`
	Health  []StepResult   `json:"health,omitempty"`
	Smoke   []StepResult   `json:"smoke,omitempty"`
	Egress  []EgressResult `json:"egress,omitempty"`
	Error   string         `json:"error,omitempty"`
	Elapsed Duration       `json:"elapsed"`
}

// StepResult is one request the probe made.
type StepResult struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Want   int    `json:"want"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// EgressResult is one attempt to reach the outside world.
//
// Connected is the field that matters and it is reported for every target,
// successful or not: "we tried these five and none connected" is evidence,
// where a silent absence is not.
type EgressResult struct {
	Target    string `json:"target"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

// Duration is a time.Duration that marshals as a string, so a plan and a report
// are both readable by a human reading the job row.
type Duration time.Duration

// D returns the duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON writes "10m0s".
func (d Duration) MarshalJSON() ([]byte, error) {

	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// UnmarshalJSON accepts "10m0s".
func (d *Duration) UnmarshalJSON(b []byte) error {

	s := string(b)
	if len(s) >= 2 && s[0] == '"' {

		s = s[1 : len(s)-1]
	}
	v, err := time.ParseDuration(s)
	if err != nil {

		return err
	}
	*d = Duration(v)
	return nil
}
