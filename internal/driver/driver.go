// Package driver is the container-runtime abstraction (design §8.2).
//
// There is no general-purpose exec on a live instance and no shell in the
// production path (INV-9): if you cannot debug without a shell, the log
// pipeline is missing, and an exec path is also an escalation path. The one
// exec there is, Snapshot, runs a fixed platform-owned binary, pbsnap, which
// must run inside the instance's sandbox to take a live copy of pb_data
// (INV-20); it takes no argv. Throwaway rehearsal and CLI containers get their
// own methods.
package driver

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotImplemented marks a method that is not built yet.
var ErrNotImplemented = errors.New("driver: not implemented yet")

// Under runsc the memory cgroup bounds the whole sandbox, not just PocketBase:
// the gVisor sentry's own runtime (~30 MiB on arm64) plus its memory file,
// which holds the guest's heap AND its page cache of pb_data and /tmp. That
// memory file is shmem, which with swap disabled the host cannot reclaim.
const (
	// RunscOverheadMiB is what the sentry takes before the guest runs anything.
	RunscOverheadMiB = 48
	// RunscMinMemMiB is the smallest limit a runsc tenant is created with. At
	// 64 MiB the sentry plus the page cache of a 30 MB database fill the cgroup
	// and the sandbox is OOM-killed in minutes, whatever GOMEMLIMIT says.
	RunscMinMemMiB = 128
)

// InstanceSpec is the desired shape of one tenant's container.
type InstanceSpec struct {
	TenantID    string
	Name        string
	ImageDigest string // sha256:..., never a tag
	AppDir      string // host path, bind-mounted read-only at /pb/app
	DataDir     string // host path, bind-mounted at /pb/pb_data
	Network     string // the tenant's internal network
	IP          string // static address within Network
	// EgressNet and EgressIP attach the tenant to the shared egress network,
	// and are empty when it has no approved egress grant.
	//
	// Part of the CREATE spec rather than applied to a running container,
	// because `docker network connect` on a live runsc container is accepted by
	// the daemon and does nothing inside the sandbox: `docker inspect` reports
	// the attachment, the container has no interface for it, and every dial
	// fails with "network is unreachable" (design.md §9.4). D2 put
	// tenants on runsc, so the create spec is the only place this works.
	EgressNet string
	EgressIP  string
	CPUs      float64
	MemMiB    int
	PidsLimit int
	Runtime   string            // "runc" or "runsc"
	Env       map[string]string // PB_ENCRYPTION_KEY, proxy vars, GOMEMLIMIT

	// LogMaxBytes caps the container runtime's own copy of the tenant's
	// stdout. pb_data is bounded by the quota image; stdout is a second write
	// path onto the host's disk, and without a cap a hook printing in a loop
	// fills /var/lib/docker for every tenant at once. The control plane keeps
	// the history in its collected copy; the runtime's file only has to bridge
	// the gap until the collector reads it.
	LogMaxBytes int64

	// Seccomp and AppArmor are applied ONLY under runc. runsc supplies its own
	// syscall filter and ignores per-container seccomp, so passing the profile
	// there is harmless but proves nothing (design.md §5).
	SeccompProfilePath string
	AppArmorProfile    string

	// RehearsalJob, when set, marks this spec as belonging to an upgrade
	// rehearsal rather than to the tenant's live instance (§12). It changes the
	// container's name and its labels, never its hardening.
	RehearsalJob string
}

// Handle identifies a created instance.
type Handle struct {
	TenantID    string
	ContainerID string
	Name        string
}

// Status is what the runtime reports about an instance.
type Status struct {
	Exists     bool
	Running    bool
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
	// ImageDigest is what is ACTUALLY running, which the reconciler compares
	// against the desired digest. A difference is drift to alert on, never to
	// act on.
	ImageDigest string
	// DataDeviceID is the device backing /pb/pb_data inside the container. A
	// mismatch against the host's current loop device means the container was
	// started before (or without) its mount and is serving an empty pb_data.
	DataDeviceID uint64
	// SpecMatches is false when the running container's configuration differs
	// from the spec. Most container settings are immutable after create, so the
	// answer to a mismatch is recreate.
	SpecMatches bool
	SpecDiff    []string
	// PublishedPorts must always be empty. Reported so a violation is
	// visible rather than assumed impossible.
	PublishedPorts []string
	// Posture is the subset of SpecDiff that no tenant container may ever
	// have (INV-12, INV-15): published ports, privilege, added capabilities,
	// extra mounts or devices, host namespaces. Non-empty means something
	// outside the control plane changed the container — security drift, not
	// configuration drift.
	Posture []string
}

// Stats is per-instance resource usage (§15).
type Stats struct {
	CPUPercent float64
	MemBytes   uint64
	MemLimit   uint64
}

// LogOpts controls a log stream.
type LogOpts struct {
	Follow bool
	Tail   string
	Since  time.Time
}

// Driver converges a container to a spec.
type Driver interface {
	// Ensure makes the running container match spec, recreating it when a
	// setting that cannot be changed in place differs.
	Ensure(ctx context.Context, spec InstanceSpec) (Handle, error)
	Stop(ctx context.Context, h Handle) error
	Destroy(ctx context.Context, h Handle) error
	Status(ctx context.Context, spec InstanceSpec) (Status, error)
	Logs(ctx context.Context, h Handle, opts LogOpts) (io.ReadCloser, error)
	Stats(ctx context.Context, h Handle) (Stats, error)

	// Rehearse boots a throwaway container on targetImage against a COPY of the
	// tenant's data, on an isolated rehearsal network with no egress (§12).
	//
	// spec.RehearsalJob must be set, and the implementation REFUSES a spec that
	// carries an egress attachment or proxy environment: a rehearsal's isolation
	// is a promise to the tenant, and a promise quietly repaired instead of
	// enforced is one nobody is checking.
	Rehearse(ctx context.Context, spec InstanceSpec, targetImage, dataCopy string) (Handle, error)

	// Snapshot streams a live copy of the database dbName in pb_data to w,
	// read by the platform's pbsnap inside the instance's own sandbox — the
	// only place a live pb_data database may be read from (INV-20), and the
	// only exec into a live instance there is (INV-9). dbName is a bare
	// "<name>.db". Returns ErrExecNotFound when the image predates pbsnap.
	Snapshot(ctx context.Context, spec InstanceSpec, dbName string, w io.Writer) error
}

// ValidDBName reports whether name is a bare database file name in pb_data:
// no path, no leading dot, a .db suffix. pbsnap applies the same rule.
func ValidDBName(name string) bool {

	return name != "" && name == filepath.Base(name) && strings.HasSuffix(name, ".db") && !strings.HasPrefix(name, ".")
}

// ErrExecNotFound means the instance's image does not contain the program
// Exec was asked to run: an image built before that program shipped.
var ErrExecNotFound = errors.New("driver: program not found in the instance image")
