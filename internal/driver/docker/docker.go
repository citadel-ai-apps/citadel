// Package docker is the only implementation of driver.Driver.
//
// It speaks the official Go SDK rather than shelling out to the docker CLI
// (design §8.2), with API version negotiation: the SDK here is v28 and the target
// daemon is 29.x with MinAPIVersion 1.40, so the client negotiates down.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// Driver converges tenant containers on a local Docker daemon.
type Driver struct {
	cli client.APIClient
	log *slog.Logger
	// dataDevice reports the host device backing a tenant's data mount. Injected
	// so the driver can detect a container running against the wrong (or an
	// absent) mount without importing internal/hostfs.
	dataDevice func(tenantID string) (uint64, error)
}

// New returns a Driver over cli.
func New(cli client.APIClient, log *slog.Logger, dataDevice func(string) (uint64, error)) *Driver {

	return &Driver{cli: cli, log: log, dataDevice: dataDevice}
}

// Connect opens a Docker client against the host daemon.
func Connect() (client.APIClient, error) {

	return client.NewClientWithOpts(
		client.FromEnv,
		// The daemon is newer than this SDK; negotiate rather than assume.
		client.WithAPIVersionNegotiation(),
	)
}

var _ driver.Driver = (*Driver)(nil)

// Ensure converges the tenant's container to spec.
//
// Convergence, not creation: given a spec, compare the running container's
// configuration against it and recreate if they differ, because nearly every
// container setting is immutable after create (§8.2).
//
// The caller must already have mounted the data image and asserted the network
// and firewall rules. Never start a container and then apply policy — that is a
// window in which a hook has open egress (§8.3).
func (d *Driver) Ensure(ctx context.Context, spec driver.InstanceSpec) (driver.Handle, error) {

	cfg, host, netCfg, err := buildConfigs(spec)
	if err != nil {

		return driver.Handle{}, err
	}

	insp, err := d.cli.ContainerInspect(ctx, spec.Name)
	switch {

	case err == nil:
		diff := diffSpec(insp, spec, host, cfg)
		if len(diff) == 0 {

			if insp.State != nil && insp.State.Running {

				if ok, reason := d.dataMountCurrent(spec, insp); !ok {

					d.log.Warn("recreating container: its data mount is stale",
						"tenant", spec.TenantID, "reason", reason)
					if err := d.remove(ctx, spec.Name); err != nil {

						return driver.Handle{}, err
					}
					break
				}
				return driver.Handle{TenantID: spec.TenantID, ContainerID: insp.ID, Name: spec.Name}, nil
			}
			// Config matches but it is stopped: start it rather than recreate,
			// which keeps the container id and the restart ladder meaningful.
			if err := d.cli.ContainerStart(ctx, insp.ID, container.StartOptions{}); err != nil {

				return driver.Handle{}, fmt.Errorf("docker: start %s: %w", spec.Name, err)
			}
			return driver.Handle{TenantID: spec.TenantID, ContainerID: insp.ID, Name: spec.Name}, nil
		}
		d.log.Info("recreating container: running config does not match spec",
			"tenant", spec.TenantID, "diff", strings.Join(diff, "; "))
		if err := d.remove(ctx, spec.Name); err != nil {

			return driver.Handle{}, err
		}
	case client.IsErrNotFound(err):
		// Fall through to create.
	default:
		return driver.Handle{}, fmt.Errorf("docker: inspect %s: %w", spec.Name, err)
	}

	if err := d.ensureImage(ctx, spec.ImageDigest); err != nil {

		return driver.Handle{}, err
	}
	// Recorded at create because that is when Docker resolves the bind source.
	// See dataMountCurrent.
	if d.dataDevice != nil {

		dev, err := d.dataDevice(spec.TenantID)
		if err != nil {

			return driver.Handle{}, fmt.Errorf("docker: refusing to create %s before its data image is mounted: %w",
				spec.Name, err)
		}
		cfg.Labels[dataDevLabel] = strconv.FormatUint(dev, 10)
	}
	created, err := d.cli.ContainerCreate(ctx, cfg, host, netCfg, nil, spec.Name)
	if err != nil {

		return driver.Handle{}, fmt.Errorf("docker: create %s: %w", spec.Name, err)
	}
	if err := d.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return driver.Handle{}, fmt.Errorf("docker: start %s: %w", spec.Name, err)
	}
	return driver.Handle{TenantID: spec.TenantID, ContainerID: created.ID, Name: spec.Name}, nil
}

// dataMountCurrent checks that a running container was created against the loop
// device currently mounted on the host.
//
// A tenant container is `--restart no`, but a stray `docker start` — or a daemon
// that restarts one for any reason — before the loopback mount is back leaves
// PocketBase serving an *empty* pb_data, with no error anywhere
// (design.md §8.3). Loopback mounts do not survive a reboot, so this
// is the normal case after one, not an exotic one.
//
// Docker resolves a bind source at create time, so the device the container
// actually has is the device the host had then. The driver records it in a
// label at create (see dataDevLabel) and compares it here. That is exact, works
// identically under runc and runsc, and needs no exec into the container
// and no poking at /proc.
func (d *Driver) dataMountCurrent(spec driver.InstanceSpec, insp container.InspectResponse) (bool, string) {

	if d.dataDevice == nil {

		return true, ""
	}
	want, err := d.dataDevice(spec.TenantID)
	if err != nil {

		return false, "host data mount is not present: " + err.Error()
	}
	if insp.Config == nil {

		return true, ""
	}
	recorded, ok := insp.Config.Labels[dataDevLabel]
	if !ok {

		// Created by an older control plane, or by hand. Recreate rather than
		// assume: the cost is a few seconds of downtime, the cost of being
		// wrong is serving an empty database.
		return false, "container has no recorded data device"
	}
	got, err := strconv.ParseUint(recorded, 10, 64)
	if err != nil {

		return false, "container has an unparseable recorded data device: " + recorded
	}
	if got != want {

		return false, fmt.Sprintf("container was created against device %d at %s, host now has %d",
			got, DataMount, want)
	}
	return true, ""
}

// Stop stops the container. The reconciler holds the tenant's instance.lock
// across the whole stop/start sequence.
func (d *Driver) Stop(ctx context.Context, h driver.Handle) error {

	timeout := 30
	err := d.cli.ContainerStop(ctx, h.Name, container.StopOptions{Timeout: &timeout})
	if err == nil || client.IsErrNotFound(err) {

		return nil
	}
	return fmt.Errorf("docker: stop %s: %w", h.Name, err)
}

// Destroy removes the container.
func (d *Driver) Destroy(ctx context.Context, h driver.Handle) error {

	return d.remove(ctx, h.Name)
}

func (d *Driver) remove(ctx context.Context, name string) error {

	err := d.cli.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})
	if err == nil || client.IsErrNotFound(err) {

		return nil
	}
	return fmt.Errorf("docker: remove %s: %w", name, err)
}

// Status reports what the daemon currently shows for spec's container.
func (d *Driver) Status(ctx context.Context, spec driver.InstanceSpec) (driver.Status, error) {

	insp, err := d.cli.ContainerInspect(ctx, spec.Name)
	if client.IsErrNotFound(err) {

		return driver.Status{}, nil
	}
	if err != nil {

		return driver.Status{}, fmt.Errorf("docker: inspect %s: %w", spec.Name, err)
	}

	st := driver.Status{Exists: true, ImageDigest: insp.Image, PublishedPorts: publishedPorts(insp)}
	if insp.State != nil {

		st.Running = insp.State.Running
		st.ExitCode = insp.State.ExitCode
		st.StartedAt, _ = time.Parse(time.RFC3339Nano, insp.State.StartedAt)
		st.FinishedAt, _ = time.Parse(time.RFC3339Nano, insp.State.FinishedAt)
	}
	// The digest a container is running is reported as the image ID, not the
	// repo digest, so resolve the spec's repo digest to an ID to compare them.
	if want, err := d.imageID(ctx, spec.ImageDigest); err == nil {

		st.ImageDigest = insp.Image
		if insp.Image == want {

			st.ImageDigest = spec.ImageDigest
		}
	}

	cfg, host, _, err := buildConfigs(spec)
	if err != nil {

		return st, err
	}
	st.SpecDiff = diffSpec(insp, spec, host, cfg)
	st.Posture = postureDiff(insp)
	if ok, reason := d.dataMountCurrent(spec, insp); !ok && st.Running {

		st.SpecDiff = append(st.SpecDiff, "stale data mount: "+reason)
	}
	st.SpecMatches = len(st.SpecDiff) == 0
	if insp.Config != nil {

		if dev, err := strconv.ParseUint(insp.Config.Labels[dataDevLabel], 10, 64); err == nil {

			st.DataDeviceID = dev
		}
	}
	return st, nil
}

// Logs streams the container's stdout and stderr.
//
// This is the whole observability path for a tenant (§15): the image has no
// shell, so there is nothing to exec into and nothing else to read.
func (d *Driver) Logs(ctx context.Context, h driver.Handle, opts driver.LogOpts) (io.ReadCloser, error) {

	o := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: opts.Follow, Timestamps: true}
	if opts.Tail != "" {

		o.Tail = opts.Tail
	}
	if !opts.Since.IsZero() {

		o.Since = opts.Since.UTC().Format(time.RFC3339)
	}
	rc, err := d.cli.ContainerLogs(ctx, h.Name, o)
	if err != nil {

		return nil, fmt.Errorf("docker: logs %s: %w", h.Name, err)
	}
	return rc, nil
}

// Stats samples CPU and memory for one instance.
func (d *Driver) Stats(ctx context.Context, h driver.Handle) (driver.Stats, error) {

	resp, err := d.cli.ContainerStatsOneShot(ctx, h.Name)
	if err != nil {

		return driver.Stats{}, fmt.Errorf("docker: stats %s: %w", h.Name, err)
	}
	defer resp.Body.Close()
	var raw container.StatsResponse
	if err := decodeJSON(resp.Body, &raw); err != nil {

		return driver.Stats{}, err
	}
	s := driver.Stats{MemBytes: workingSet(raw.MemoryStats), MemLimit: raw.MemoryStats.Limit}
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage) - float64(raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemUsage) - float64(raw.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta > 0 {

		s.CPUPercent = cpuDelta / sysDelta * float64(raw.CPUStats.OnlineCPUs) * 100
	}
	return s, nil
}

// workingSet is raw cgroup usage minus the reclaimable file cache, the same
// figure `docker stats` shows. Raw usage counts the pages of the pocketbase
// binary and of the SQLite files, which the kernel drops under pressure; an
// operator reading it as the tenant's footprint sees tens of MB that are not.
func workingSet(m container.MemoryStats) uint64 {

	inactive, ok := m.Stats["inactive_file"] // cgroup v2
	if !ok {

		inactive = m.Stats["total_inactive_file"] // cgroup v1
	}
	if inactive > m.Usage {

		return m.Usage
	}
	return m.Usage - inactive
}

func (d *Driver) ensureImage(ctx context.Context, digestRef string) error {

	if _, err := d.imageID(ctx, digestRef); err == nil {

		return nil
	}
	rc, err := d.cli.ImagePull(ctx, digestRef, image.PullOptions{})
	if err != nil {

		return fmt.Errorf("docker: pull %s: %w", digestRef, err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {

		return fmt.Errorf("docker: pull %s: %w", digestRef, err)
	}
	return nil
}

func (d *Driver) imageID(ctx context.Context, digestRef string) (string, error) {

	insp, err := d.cli.ImageInspect(ctx, digestRef)
	if err != nil {

		return "", err
	}
	return insp.ID, nil
}

// ManagedContainers lists every container the control plane owns.
//
// Recovery enumerates the host rather than trusting the database, so a
// container left behind by a crash mid-create is still found (§16 task 8).
func (d *Driver) ManagedContainers(ctx context.Context) (map[string]string, error) {

	f := filters.NewArgs(filters.Arg("label", netpolicy.LabelManaged+"=true"))
	list, err := d.cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {

		return nil, fmt.Errorf("docker: list managed containers: %w", err)
	}
	out := map[string]string{}
	for _, c := range list {

		if tenant := c.Labels[netpolicy.LabelTenant]; tenant != "" {

			out[tenant] = c.ID
		}
	}
	return out, nil
}

// ManagedNetworks lists every network the control plane owns, by tenant.
func (d *Driver) ManagedNetworks(ctx context.Context) (map[string]string, error) {

	f := filters.NewArgs(filters.Arg("label", netpolicy.LabelManaged+"=true"))
	list, err := d.cli.NetworkList(ctx, network.ListOptions{Filters: f})
	if err != nil {

		return nil, fmt.Errorf("docker: list managed networks: %w", err)
	}
	out := map[string]string{}
	for _, n := range list {

		if tenant := n.Labels[netpolicy.LabelTenant]; tenant != "" {

			out[tenant] = n.Name
		}
	}
	return out, nil
}

// HostFacts are the daemon properties the control plane refuses to assume.
type HostFacts struct {
	ServerVersion   string
	FirewallBackend string
	UsernsRemap     bool
	HasRunsc        bool
}

// Inspect reads the daemon's own view of itself.
func (d *Driver) Inspect(ctx context.Context) (HostFacts, error) {

	info, err := d.cli.Info(ctx)
	if err != nil {

		return HostFacts{}, fmt.Errorf("docker: info: %w", err)
	}
	f := HostFacts{ServerVersion: info.ServerVersion}
	if info.FirewallBackend != nil {

		f.FirewallBackend = info.FirewallBackend.Driver
	}
	for _, opt := range info.SecurityOptions {

		if strings.Contains(opt, "name=userns") {

			f.UsernsRemap = true
		}
	}
	_, f.HasRunsc = info.Runtimes["runsc"]
	return f, nil
}

// dataDevLabel records the host device number of the data mount a container was
// created against. See dataMountCurrent for why it is a label rather than
// something read out of the running container.
const dataDevLabel = "v2p.data-device"

func decodeJSON(r io.Reader, v any) error {

	if err := json.NewDecoder(r).Decode(v); err != nil {

		return fmt.Errorf("docker: decode response: %w", err)
	}
	return nil
}
