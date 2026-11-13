package docker

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/citadel-ai-apps/citadel/internal/config"
	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// Container paths the hardened image fixes (§5). The entrypoint's flags point
// at these, so they are not configurable.
const (
	DataMount = "/pb/pb_data"
	AppMount  = "/pb/app"
	HTTPPort  = config.PocketBasePort
)

// apparmorEnabledPath is how the image scripts detect AppArmor. On kernels
// without it (some shared-kernel VMs, design.md §5) the file is
// absent, and the profile is skipped with a warning rather than silently.
const apparmorEnabledPath = "/sys/module/apparmor/parameters/enabled"

// AppArmorAvailable reports whether the host kernel can enforce a profile.
func AppArmorAvailable() bool {

	b, err := os.ReadFile(apparmorEnabledPath)
	return err == nil && strings.TrimSpace(string(b)) == "Y"
}

// buildConfigs renders an InstanceSpec into the three Docker create structs.
//
// The mapping below is the §4 flag list. Two entries are load-bearing in a way
// the flag name hides:
//
//   - MemorySwap must equal Memory. That is what disables swap; leaving it zero
//     means "unlimited swap" and the memory limit stops bounding anything.
//   - NanoCPUs is the SDK's --cpus. A hand-rolled CPUQuota/CPUPeriod pair is a
//     different, subtly weaker control.
func buildConfigs(spec driver.InstanceSpec) (*container.Config, *container.HostConfig, *network.NetworkingConfig, error) {

	return buildConfigsOpt(spec, buildOpts{})
}

// buildOpts varies the few things a rehearsal container does differently.
//
// A rehearsal goes through THIS function rather than a parallel one on purpose:
// there is one hardening list in the tree, so a rehearsal can never end up less
// confined than the instance it stands in for — which would make it a rehearsal
// of a configuration nobody runs.
type buildOpts struct {
	// Image overrides spec.ImageDigest. A rehearsal boots the TARGET version
	// against a copy of the data, so the image and the spec disagree by design.
	Image string
	// RehearsalJob labels the container for one rehearsal job instead of for a
	// tenant, so ManagedContainers cannot mistake it for the tenant's instance.
	RehearsalJob string
}

// goMemLimitMiB is the GC soft limit for a spec, 0 for none.
//
// Under runc the cgroup holds little but the Go heap, so 85% of it is safe.
// Under runsc the cgroup also holds the sentry and the guest's page cache
// (driver.RunscOverheadMiB), so the heap gets 70% of what is left after the
// sentry. Below 16 MiB a limit would only make the GC thrash, so none is set.
func goMemLimitMiB(spec driver.InstanceSpec) int {

	mib := spec.MemMiB * 85 / 100
	if spec.Runtime == "runsc" {

		mib = (spec.MemMiB - driver.RunscOverheadMiB) * 70 / 100
	}
	if mib < 16 {

		return 0
	}
	return mib
}

func buildConfigsOpt(spec driver.InstanceSpec, opts buildOpts) (*container.Config, *container.HostConfig, *network.NetworkingConfig, error) {

	image := spec.ImageDigest
	if opts.Image != "" {

		image = opts.Image
	}
	if !strings.Contains(image, "@sha256:") {

		// a tag could be retagged, silently changing what a tenant runs.
		return nil, nil, nil, fmt.Errorf("docker: image %q is not a digest reference", image)
	}
	if spec.IP == "" || spec.Network == "" {

		return nil, nil, nil, fmt.Errorf("docker: %s has no static address on a named network", spec.TenantID)
	}

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {

		env = append(env, k+"="+v)
	}
	if _, set := spec.Env["GOMEMLIMIT"]; !set {

		// A soft limit for the Go GC, below the cgroup's hard one. Without it
		// the heap may grow to twice its live size before a collection, and
		// PocketBase's SQLite (pure Go) caches live in that heap, so an idle
		// tenant sits far above what it uses and a busy one hits the OOM kill
		// where a collection would have done.
		if mib := goMemLimitMiB(spec); mib > 0 {

			env = append(env, fmt.Sprintf("GOMEMLIMIT=%dMiB", mib))
		}
	}
	sort.Strings(env)

	labels := map[string]string{netpolicy.LabelManaged: "true"}
	if opts.RehearsalJob != "" {

		// Deliberately no v2p.tenant label. ManagedContainers maps by that
		// label, and a rehearsal appearing there would be read as the tenant's
		// instance running the wrong digest — an INV-11 drift alert the platform
		// itself manufactured.
		labels[netpolicy.LabelRehearsal] = opts.RehearsalJob

	} else {

		labels[netpolicy.LabelTenant] = spec.TenantID
	}

	cfg := &container.Config{
		Image:  image,
		Env:    env,
		Labels: labels,
		// No ExposedPorts and no PortBindings below: a tenant container
		// publishes nothing, ever. Ingress happens because the edge
		// proxy joins the tenant's network.
	}

	secOpt := []string{"no-new-privileges:true"}
	// Under runsc these are inert: gVisor applies its own syscall filter and
	// ignores per-container seccomp (design.md §5). Passing them
	// anyway would look like enforcement in a `docker inspect` without being it.
	if spec.Runtime == "runc" {

		if spec.SeccompProfilePath != "" {

			secOpt = append(secOpt, "seccomp="+spec.SeccompProfilePath)
		}
		if spec.AppArmorProfile != "" && AppArmorAvailable() {

			secOpt = append(secOpt, "apparmor="+spec.AppArmorProfile)
		}
	}

	pids := int64(spec.PidsLimit)
	mem := int64(spec.MemMiB) * 1024 * 1024

	host := &container.HostConfig{
		Binds: []string{
			spec.DataDir + ":" + DataMount + ":rw",
			// :ro — a hook must not be able to rewrite its own release.
			spec.AppDir + ":" + AppMount + ":ro",
		},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"},
		CapDrop:        []string{"ALL"},
		SecurityOpt:    secOpt,
		// The reconciler owns restarts, not Docker: Docker's restart policy has
		// no backoff ladder, no health semantics and no visibility to the
		// control plane (§4).
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
		Runtime:       spec.Runtime,
		NetworkMode:   container.NetworkMode(spec.Network),
		PortBindings:  nat.PortMap{},
		LogConfig:     logConfig(spec),
		Resources: container.Resources{
			Memory:     mem,
			MemorySwap: mem, // equal to Memory => swap disabled
			NanoCPUs:   int64(spec.CPUs * 1e9),
			PidsLimit:  &pids,
		},
	}

	netCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			spec.Network: {
				IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: spec.IP},
			},
		},
	}
	// Both endpoints at CREATE. Connecting the egress network to a running
	// container is accepted by the daemon and silently does nothing under runsc
	// — the engine records the attachment, the sandbox's netstack never sees an
	// interface, and every dial through the proxy fails with "network is
	// unreachable" (design.md §9.4). The cost is that a first grant or
	// a last revocation recreates the container; diffSpec is what notices.
	if spec.EgressNet != "" && spec.EgressIP != "" {

		netCfg.EndpointsConfig[spec.EgressNet] = &network.EndpointSettings{
			IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: spec.EgressIP},
		}
	}
	return cfg, host, netCfg, nil
}

// logMaxFiles is how many json-file generations the runtime keeps. The
// collector (internal/logcollect) holds the history; the runtime's file only
// bridges the gap until it is read, and one rotation is enough for that.
const logMaxFiles = 2

// logConfig bounds the runtime's own copy of the tenant's stdout.
//
// The quota image bounds what a tenant writes to pb_data (D4). Its stdout is a
// different write path onto the host: json-file with no options keeps every
// byte under /var/lib/docker, outside every quota the platform enforces, so a
// hook printing in a loop would fill the disk every tenant and the control
// plane share. json-file rather than another driver because the collector
// follows the stream through the logs API, which json-file serves across
// rotations.
func logConfig(spec driver.InstanceSpec) container.LogConfig {

	lc := container.LogConfig{Type: "json-file"}
	if spec.LogMaxBytes > 0 {

		lc.Config = map[string]string{
			"max-size": strconv.FormatInt(spec.LogMaxBytes, 10),
			"max-file": strconv.Itoa(logMaxFiles),
		}
	}
	return lc
}

// diffSpec compares a running container against the spec it should match.
//
// Returned as a list of human-readable differences rather than a bool, because
// the reconciler logs the reason it is about to recreate a tenant's container —
// "recreating pb-demo" with no cause is the kind of log line that costs an hour
// during an incident.
func diffSpec(insp container.InspectResponse, spec driver.InstanceSpec, want *container.HostConfig, wantCfg *container.Config) []string {

	var diff []string
	add := func(format string, args ...any) { diff = append(diff, fmt.Sprintf(format, args...)) }

	if insp.Image != spec.ImageDigest && !imageMatches(insp, spec.ImageDigest) {

		add("image: running %s, want %s", insp.Image, spec.ImageDigest)
	}
	if insp.HostConfig == nil {

		return append(diff, "host config unavailable")
	}
	if insp.HostConfig.Runtime != want.Runtime {

		add("runtime: running %q, want %q", insp.HostConfig.Runtime, want.Runtime)
	}
	if !insp.HostConfig.ReadonlyRootfs {

		add("rootfs is writable, want --read-only")
	}
	if insp.HostConfig.Memory != want.Memory {

		add("memory: running %d, want %d", insp.HostConfig.Memory, want.Memory)
	}
	if insp.HostConfig.MemorySwap != want.MemorySwap {

		add("memory-swap: running %d, want %d (equal to memory disables swap)",
			insp.HostConfig.MemorySwap, want.MemorySwap)
	}
	if insp.HostConfig.NanoCPUs != want.NanoCPUs {

		add("cpus: running %d nanocpus, want %d", insp.HostConfig.NanoCPUs, want.NanoCPUs)
	}
	if got, w := derefPids(insp.HostConfig.PidsLimit), derefPids(want.PidsLimit); got != w {

		add("pids-limit: running %d, want %d", got, w)
	}
	if !sameStrings(insp.HostConfig.CapDrop, want.CapDrop) {

		add("cap-drop: running %v, want %v", insp.HostConfig.CapDrop, want.CapDrop)
	}
	if !sameStrings(insp.HostConfig.SecurityOpt, want.SecurityOpt) {

		add("security-opt: running %v, want %v", insp.HostConfig.SecurityOpt, want.SecurityOpt)
	}
	if !sameStrings(insp.HostConfig.Binds, want.Binds) {

		add("binds: running %v, want %v", insp.HostConfig.Binds, want.Binds)
	}
	if d := logConfigDiff(insp.HostConfig.LogConfig, want.LogConfig); d != "" {

		add("%s", d)
	}
	if insp.HostConfig.RestartPolicy.Name != want.RestartPolicy.Name {

		add("restart policy: running %q, want %q",
			insp.HostConfig.RestartPolicy.Name, want.RestartPolicy.Name)
	}
	diff = append(diff, postureDiff(insp)...)
	if ep, ok := insp.NetworkSettings.Networks[spec.Network]; !ok {

		add("not attached to %s", spec.Network)

	} else if ep.IPAddress != spec.IP {

		add("address on %s: running %s, want %s", spec.Network, ep.IPAddress, spec.IP)
	}
	// Both directions. A MISSING egress attachment means an approved grant is
	// not in effect; an EXTRA one means a revoked or expired grant still has an
	// interface behind it. The second is the one that matters, and it is the
	// only way the attachment goes away at all, since the change has to happen
	// at create time (see buildConfigs).
	diff = append(diff, egressDiff(insp, spec)...)
	if insp.Config != nil && !sameStrings(envOf(insp.Config.Env), envOf(wantCfg.Env)) {

		// Compared by name and value: the encryption key is re-read from disk
		// on every create, and a stale one means undecryptable settings.
		add("environment differs from spec")
	}
	return diff
}

// postureDiff is the part of the spec diff that is a security boundary rather
// than configuration: settings INV-12 and INV-15 say no tenant container may
// ever have. Anything here was put there outside the control plane, so the
// reconciler reports it as security drift before it recreates the container.
func postureDiff(insp container.InspectResponse) []string {

	var diff []string
	add := func(format string, args ...any) { diff = append(diff, fmt.Sprintf(format, args...)) }
	h := insp.HostConfig
	if h == nil {

		return nil
	}
	if ports := publishedPorts(insp); len(ports) > 0 {

		// A published port is a DNAT rule and a path around the host
		// firewall's INPUT rules (INV-12).
		add("published ports %v; a tenant container must publish none", ports)
	}
	if h.Privileged {

		add("privileged; a tenant container is never privileged")
	}
	if len(h.CapAdd) > 0 {

		add("cap-add %v; a tenant container adds no capabilities", h.CapAdd)
	}
	if len(h.Mounts) > 0 {

		// Binds are compared exactly elsewhere; --mount lands here instead,
		// and is the other way to hand a container the Docker socket.
		add("mounts %v; a tenant container has only its two binds", mountSources(h.Mounts))
	}
	if len(h.Devices) > 0 {

		add("devices %v; a tenant container has none", h.Devices)
	}
	for name, mode := range map[string]string{
		"network": string(h.NetworkMode), "pid": string(h.PidMode), "ipc": string(h.IpcMode),
		"uts": string(h.UTSMode), "userns": string(h.UsernsMode),
	} {

		if mode == "host" {

			add("%s namespace is the host's", name)
		}
	}
	// A different (non-host) network mode shows up as "not attached to" in
	// diffSpec, which compares the attachment itself.
	return diff
}

func mountSources(ms []mount.Mount) []string {

	out := make([]string, 0, len(ms))
	for _, m := range ms {

		out = append(out, string(m.Type)+":"+m.Source+":"+m.Target)
	}
	return out
}

// egressDiff compares the running container's egress attachment against the
// spec, which is derived from the tenant's active grants.
//
// A container can be attached to at most one egress network, so any attachment
// to a network other than the wanted one is also reported — that is the shape a
// stale spec or a hand-run `docker network connect` would take.
func egressDiff(insp container.InspectResponse, spec driver.InstanceSpec) []string {

	var diff []string
	want := spec.EgressNet

	for name, ep := range insp.NetworkSettings.Networks {

		if name == spec.Network {

			continue
		}
		switch {

		case name != want:
			diff = append(diff, fmt.Sprintf(
				"attached to %s, which no grant justifies", name))
		case ep.IPAddress != spec.EgressIP:
			diff = append(diff, fmt.Sprintf(
				"address on %s: running %s, want %s", name, ep.IPAddress, spec.EgressIP))
		}
	}
	if want != "" {

		if _, ok := insp.NetworkSettings.Networks[want]; !ok {

			diff = append(diff, fmt.Sprintf(
				"not attached to %s, so an approved egress grant is not in effect", want))
		}
	}
	return diff
}

func imageMatches(insp container.InspectResponse, digestRef string) bool {

	_, want, ok := strings.Cut(digestRef, "@")
	if !ok {

		return false
	}
	if insp.Image == want {

		return true
	}
	if insp.Config != nil && insp.Config.Image == digestRef {

		return true
	}
	return false
}

func publishedPorts(insp container.InspectResponse) []string {

	var out []string
	for port, bindings := range insp.NetworkSettings.Ports {

		for _, b := range bindings {

			out = append(out, fmt.Sprintf("%s->%s:%s", port, b.HostIP, b.HostPort))
		}
	}
	if insp.HostConfig != nil {

		for port, bindings := range insp.HostConfig.PortBindings {

			for _, b := range bindings {

				out = append(out, fmt.Sprintf("%s->%s:%s", port, b.HostIP, b.HostPort))
			}
		}
	}
	sort.Strings(out)
	return out
}

func derefPids(p *int64) int64 {

	if p == nil {

		return 0
	}
	return *p
}

func sameStrings(a, b []string) bool {

	if len(a) != len(b) {

		return false
	}
	as := append([]string{}, a...)
	bs := append([]string{}, b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {

		if as[i] != bs[i] {

			return false
		}
	}
	return true
}

// envOf keeps only the variables the platform sets, so Docker's own additions
// (PATH and friends, injected from the image) do not read as drift.
//
// GOMEMLIMIT is included: without it a container created before the limit was
// introduced, or before goMemLimitMiB changed, would never be recreated with
// the current one.
func envOf(env []string) []string {

	var out []string
	for _, e := range env {

		if strings.HasPrefix(e, "PB_") || strings.HasPrefix(e, "GOMEMLIMIT=") {

			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// logConfigDiff compares only what the spec sets: the daemon may merge its own
// log-opts into what it reports, and those are not a difference worth a
// recreate.
func logConfigDiff(got, want container.LogConfig) string {

	if got.Type != want.Type {

		return fmt.Sprintf("log driver: running %q, want %q", got.Type, want.Type)
	}
	for k, v := range want.Config {

		if got.Config[k] != v {

			return fmt.Sprintf("log %s: running %q, want %q", k, got.Config[k], v)
		}
	}
	return ""
}
