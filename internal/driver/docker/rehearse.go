package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
)

// ProbePlanMount is where the probe container reads its instructions.
const ProbePlanMount = "/plan.json"

// RehearsalPrefix names a rehearsal container. A distinct prefix from a
// tenant's `pb-<slug>`, so nothing that matches on the name can confuse the two.
const RehearsalPrefix = "pb-rh-"

// proxyEnvVars are stripped from every tenant spec before it becomes a
// rehearsal spec — see Rehearse.
var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}

// Rehearse boots targetImage against dataCopy on the spec's network.
//
// The caller has already built the isolated network and the data copy; this is
// the container half. It is not a second process on the tenant's pb_data
// (INV-3) — dataCopy is a copy — and nothing execs into it (INV-9): the probe
// is a separate container that only speaks HTTP to it.
//
// Three refusals rather than three silent fixes. Every one of them is a promise
// §12 makes to the tenant ("a rehearsal cannot reach the world, so your hooks
// cannot send mail or charge cards from it"), and a promise that is quietly
// repaired instead of enforced is a promise nobody is checking:
//
//   - a non-digest target image;
//   - a spec carrying an egress attachment;
//   - a spec carrying proxy environment variables. This one is not hypothetical:
//     the reconciler injects them into EVERY spec as ergonomics, so a rehearsal
//     spec derived from a tenant spec has them unless the caller stripped them.
func (d *Driver) Rehearse(ctx context.Context, spec driver.InstanceSpec, targetImage, dataCopy string) (driver.Handle, error) {

	jobID := spec.RehearsalJob
	if jobID == "" {

		return driver.Handle{}, fmt.Errorf("docker: a rehearsal spec must carry its job id")
	}
	if !strings.Contains(targetImage, "@sha256:") {

		return driver.Handle{}, fmt.Errorf("docker: rehearsal target %q is not a digest reference", targetImage)
	}
	if spec.EgressNet != "" || spec.EgressIP != "" {

		return driver.Handle{}, fmt.Errorf(
			"docker: a rehearsal never gets the tenant's egress attachment, whatever the manifest asked for")
	}
	for _, k := range proxyEnvVars {

		if _, ok := spec.Env[k]; ok {

			return driver.Handle{}, fmt.Errorf(
				"docker: a rehearsal spec must not carry %s; a rehearsal has no proxy to reach", k)
		}
	}
	if dataCopy == "" {

		return driver.Handle{}, fmt.Errorf("docker: a rehearsal needs a data copy, never the tenant's own directory")
	}

	spec.DataDir = dataCopy
	spec.Name = RehearsalPrefix + jobID
	cfg, host, netCfg, err := buildConfigsOpt(spec, buildOpts{Image: targetImage, RehearsalJob: jobID})
	if err != nil {

		return driver.Handle{}, err
	}
	if err := d.ensureImage(ctx, targetImage); err != nil {

		return driver.Handle{}, err
	}
	// Any leftover from a previous attempt goes first: a rehearsal id is reused
	// on retry, and a stale container would be adopted rather than replaced.
	_ = d.cli.ContainerRemove(ctx, spec.Name, container.RemoveOptions{Force: true})

	created, err := d.cli.ContainerCreate(ctx, cfg, host, netCfg, nil, spec.Name)
	if err != nil {

		return driver.Handle{}, fmt.Errorf("docker: create rehearsal %s: %w", spec.Name, err)
	}
	if err := d.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return driver.Handle{}, fmt.Errorf("docker: start rehearsal %s: %w", spec.Name, err)
	}
	d.log.Info("rehearsal instance started", "job", jobID, "image", targetImage, "network", spec.Network)
	return driver.Handle{TenantID: spec.TenantID, Name: spec.Name, ContainerID: created.ID}, nil
}

// Ceilings for the rehearsal probe: a Go HTTP client with a small plan.
const (
	probeMemBytes = 128 << 20
	probePids     = 64
)

// ProbeOptions describes one probe run.
type ProbeOptions struct {
	JobID    string
	Network  string
	IP       string
	Image    string
	PlanPath string            // host path bind-mounted read-only at /plan.json
	Env      map[string]string // credentials; never the plan itself
}

// Probe runs the rehearsal probe to completion and returns its stdout.
//
// The probe exists because the control plane cannot reach a rehearsal itself:
// the rehearsal bridge matches `br-t-+`, whose host-protection INPUT drop also
// kills the SYN-ACK of a host-initiated connection (design.md §9.3).
// Something on the network has to do the asking, and §12 says it is a container
// with nothing else on the network beside it.
//
// The plan arrives on a read-only bind mount rather than in argv: argv is
// visible to anything that can list processes, and the plan names the hostname
// and paths of a real tenant.
//
// Exit codes are NOT the verdict. A rehearsal whose hooks are broken is a
// successful probe reporting a failure, and the caller has to be able to tell
// that apart from a probe that crashed — so a non-zero exit means the probe
// malfunctioned, and the verdict is in the JSON.
func (d *Driver) Probe(ctx context.Context, opts ProbeOptions) (string, error) {

	if opts.Image == "" {

		return "", fmt.Errorf("docker: no probe image configured; set probe_image (see `make probe-image`)")
	}
	if err := d.ensureImage(ctx, opts.Image); err != nil {

		return "", err
	}
	env := make([]string, 0, len(opts.Env))
	for k, v := range opts.Env {

		env = append(env, k+"="+v)
	}
	cfg := &container.Config{
		Image:  opts.Image,
		Env:    env,
		Labels: map[string]string{netpolicy.LabelManaged: "true", netpolicy.LabelRehearsal: opts.JobID},
	}
	host := &container.HostConfig{
		Binds:          []string{opts.PlanPath + ":" + ProbePlanMount + ":ro"},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,size=8m"},
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		NetworkMode:    container.NetworkMode(opts.Network),
		// runc, not the tenant runtime: the probe is platform code, and running
		// it under gVisor buys nothing while adding a boot the rehearsal budget
		// has to pay for.
		Runtime:    "runc",
		AutoRemove: false, // removed explicitly, so its output can be read first
		// It shares a network with the tenant's hooks and parses their
		// responses: bounded like anything else that handles hostile input.
		Resources: container.Resources{
			Memory:     probeMemBytes,
			MemorySwap: probeMemBytes,
			PidsLimit:  new(int64(probePids)),
		},
	}
	netCfg := probeNetworking(opts)

	created, err := d.cli.ContainerCreate(ctx, cfg, host, netCfg, nil, "")
	if err != nil {

		return "", fmt.Errorf("docker: create probe: %w", err)
	}
	defer func() {

		_ = d.cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})
	}()

	if err := d.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {

		return "", fmt.Errorf("docker: start probe: %w", err)
	}
	waitCh, errCh := d.cli.ContainerWait(ctx, created.ID, container.WaitConditionNotRunning)
	var code int64
	select {
	case err := <-errCh:
		return "", fmt.Errorf("docker: wait for probe: %w", err)
	case res := <-waitCh:
		code = res.StatusCode
	case <-ctx.Done():
		return "", ctx.Err()
	}
	out := d.oneShotLogs(ctx, created.ID)
	if code != 0 {

		return out, fmt.Errorf("docker: the rehearsal probe itself failed (exit %d): %s", code, out)
	}
	return out, nil
}

func probeNetworking(opts ProbeOptions) *network.NetworkingConfig {

	if opts.IP == "" {

		return nil
	}
	return &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			opts.Network: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: opts.IP}},
		},
	}
}

// RehearsalContainers maps job id to container name for every rehearsal
// container on the host, found by label rather than by name.
func (d *Driver) RehearsalContainers(ctx context.Context) (map[string]string, error) {

	f := filters.NewArgs(filters.Arg("label", netpolicy.LabelRehearsal))
	list, err := d.cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {

		return nil, fmt.Errorf("docker: list rehearsal containers: %w", err)
	}
	out := map[string]string{}
	for _, c := range list {

		if job := c.Labels[netpolicy.LabelRehearsal]; job != "" {

			out[job] = c.ID
		}
	}
	return out, nil
}

// RemoveRehearsal force-removes every container belonging to one job.
func (d *Driver) RemoveRehearsal(ctx context.Context, jobID string) error {

	f := filters.NewArgs(filters.Arg("label", netpolicy.LabelRehearsal+"="+jobID))
	list, err := d.cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {

		return fmt.Errorf("docker: list rehearsal containers for %s: %w", jobID, err)
	}
	var firstErr error
	for _, c := range list {

		// Every container is attempted even after a failure: leaving the probe
		// behind because the instance would not delete is how a rehearsal
		// network becomes undeletable.
		if err := d.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err != nil &&
			!client.IsErrNotFound(err) && firstErr == nil {

			firstErr = err
		}
	}
	return firstErr
}
