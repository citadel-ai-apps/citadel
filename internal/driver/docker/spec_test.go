package docker

import (
	"strings"
	"testing"

	"github.com/citadel-ai-apps/citadel/internal/driver"
	"github.com/citadel-ai-apps/citadel/internal/netpolicy"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

const digest = "127.0.0.1:5000/pb-hardened@sha256:" +
	"c84a2f4ce9f1235448c41c5495dbcfdab052c5adec1e26d9b1349a77fba5016d"

func baseSpec() driver.InstanceSpec {

	return driver.InstanceSpec{
		TenantID:    "demo",
		Name:        "pb-demo",
		ImageDigest: digest,
		AppDir:      "/srv/citadel/tenants/demo/app/current",
		DataDir:     "/srv/citadel/tenants/demo/data",
		Network:     "t-demo",
		IP:          "10.213.1.3",
		CPUs:        1.0,
		MemMiB:      256,
		PidsLimit:   128,
		Runtime:     "runsc",
		Env:         map[string]string{"PB_ENCRYPTION_KEY": strings.Repeat("a", 32)},
		LogMaxBytes: 16 << 20,

		SeccompProfilePath: "images/pb-hardened/seccomp.json",
		AppArmorProfile:    "pb-hardened",
	}
}

// TestSpecMatchesTheVerifiedFlagSet walks the §4 container configuration. Two
// of these are the ones a hand-written mapping gets wrong.
func TestSpecMatchesTheVerifiedFlagSet(t *testing.T) {

	cfg, host, netCfg, err := buildConfigs(baseSpec())
	if err != nil {

		t.Fatal(err)
	}

	if !host.ReadonlyRootfs {

		t.Error("--read-only is missing")
	}
	if host.Tmpfs["/tmp"] != "rw,noexec,nosuid,size=64m" {

		t.Errorf("tmpfs options = %q", host.Tmpfs["/tmp"])
	}
	if len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" {

		t.Errorf("cap-drop = %v, want [ALL]", host.CapDrop)
	}
	if !hasOpt(host.SecurityOpt, "no-new-privileges:true") {

		t.Errorf("security-opt = %v, want no-new-privileges", host.SecurityOpt)
	}
	if host.PidsLimit == nil || *host.PidsLimit != 128 {

		t.Errorf("pids-limit = %v, want 128", host.PidsLimit)
	}

	wantMem := int64(256 * 1024 * 1024)
	if host.Memory != wantMem {

		t.Errorf("memory = %d, want %d", host.Memory, wantMem)
	}
	// Equal to Memory is what disables swap; zero would mean unlimited swap and
	// the memory limit would stop bounding anything.
	if host.MemorySwap != wantMem {

		t.Errorf("memory-swap = %d, want %d (equal to memory)", host.MemorySwap, wantMem)
	}
	// --cpus is NanoCPUs, not a hand-rolled CPUQuota/CPUPeriod pair.
	if host.NanoCPUs != 1_000_000_000 {

		t.Errorf("nanocpus = %d, want 1e9", host.NanoCPUs)
	}
	if host.CPUQuota != 0 || host.CPUPeriod != 0 {

		t.Errorf("CPUQuota/CPUPeriod are set (%d/%d); --cpus is NanoCPUs", host.CPUQuota, host.CPUPeriod)
	}

	// stdout is a write path onto the host's disk outside every quota: the
	// runtime's own copy of it must be capped.
	if host.LogConfig.Type != "json-file" ||
		host.LogConfig.Config["max-size"] != "16777216" || host.LogConfig.Config["max-file"] != "2" {

		t.Errorf("log config = %+v, want json-file capped at 16777216 bytes x 2 files", host.LogConfig)
	}

	if host.RestartPolicy.Name != container.RestartPolicyDisabled {

		t.Errorf("restart policy = %q, want disabled: the reconciler owns restarts", host.RestartPolicy.Name)
	}
	if host.Runtime != "runsc" {

		t.Errorf("runtime = %q, want runsc", host.Runtime)
	}

	if !hasOpt(host.Binds, "/srv/citadel/tenants/demo/data:"+DataMount+":rw") {

		t.Errorf("data bind missing from %v", host.Binds)
	}
	// :ro — a hook must not be able to rewrite its own release.
	if !hasOpt(host.Binds, "/srv/citadel/tenants/demo/app/current:"+AppMount+":ro") {

		t.Errorf("app bind is not read-only: %v", host.Binds)
	}

	ep := netCfg.EndpointsConfig["t-demo"]
	if ep == nil || ep.IPAMConfig == nil || ep.IPAMConfig.IPv4Address != "10.213.1.3" {

		t.Errorf("static address not pinned: %+v", netCfg.EndpointsConfig)
	}

	if cfg.Labels[netpolicy.LabelManaged] != "true" || cfg.Labels[netpolicy.LabelTenant] != "demo" {

		t.Errorf("labels = %v; recovery enumerates the host by these", cfg.Labels)
	}
}

// TestNoPublishedPorts asserts a tenant publishes nothing. Every published
// port is a DNAT rule, a chance to bind 0.0.0.0, and a path that bypasses the
// host firewall's INPUT rules.
func TestNoPublishedPorts(t *testing.T) {

	cfg, host, _, err := buildConfigs(baseSpec())
	if err != nil {

		t.Fatal(err)
	}
	if len(host.PortBindings) != 0 {

		t.Errorf("PortBindings = %v, want none", host.PortBindings)
	}
	if len(cfg.ExposedPorts) != 0 {

		t.Errorf("ExposedPorts = %v, want none", cfg.ExposedPorts)
	}
	if host.PublishAllPorts {

		t.Error("PublishAllPorts is set")
	}
	if host.NetworkMode.IsHost() {

		t.Error("network mode is host")
	}
}

// TestSecurityProfilesOnlyUnderRunc: runsc applies its own syscall filter and
// ignores per-container seccomp, so passing the profile there would look like
// enforcement in a `docker inspect` without being it
// (design.md §5).
func TestSecurityProfilesOnlyUnderRunc(t *testing.T) {

	spec := baseSpec()
	spec.Runtime = "runsc"
	_, host, _, err := buildConfigs(spec)
	if err != nil {

		t.Fatal(err)
	}
	for _, opt := range host.SecurityOpt {

		if strings.HasPrefix(opt, "seccomp=") || strings.HasPrefix(opt, "apparmor=") {

			t.Errorf("security-opt %q was applied under runsc, where it is inert", opt)
		}
	}

	spec.Runtime = "runc"
	_, host, _, err = buildConfigs(spec)
	if err != nil {

		t.Fatal(err)
	}
	if !hasOpt(host.SecurityOpt, "seccomp=images/pb-hardened/seccomp.json") {

		t.Errorf("seccomp was not applied under runc: %v", host.SecurityOpt)
	}
	// AppArmor depends on the host kernel, so only assert it where it can load.
	if AppArmorAvailable() && !hasOpt(host.SecurityOpt, "apparmor=pb-hardened") {

		t.Errorf("apparmor was not applied under runc on an AppArmor kernel: %v", host.SecurityOpt)
	}
}

// TestDigestRequired asserts digests only: a retagged image would silently
// change what a tenant runs.
func TestDigestRequired(t *testing.T) {

	spec := baseSpec()
	spec.ImageDigest = "127.0.0.1:5000/pb-hardened:0.40.4-h1"
	if _, _, _, err := buildConfigs(spec); err == nil {

		t.Fatal("a tag reference was accepted; only digests may be scheduled")
	}
}

func TestStaticAddressRequired(t *testing.T) {

	spec := baseSpec()
	spec.IP = ""
	if _, _, _, err := buildConfigs(spec); err == nil {

		t.Fatal("a spec with no static address was accepted; firewall rules are written against it")
	}
}

// TestDiffSpecAcceptsAMatchingContainer and the mutation cases below cover the
// converge path: Ensure recreates on any difference, because nearly every
// container setting is immutable after create (§8.2). A false positive here
// means gratuitous downtime; a false negative means a tenant keeps running with
// the wrong configuration.
func TestDiffSpecAcceptsAMatchingContainer(t *testing.T) {

	spec := baseSpec()
	insp := inspectMatching(t, spec)
	if diff := diffSpec(insp, spec, mustHost(t, spec), mustConfig(t, spec)); len(diff) != 0 {

		t.Fatalf("a matching container reported differences: %v", diff)
	}
}

func TestDiffSpecDetectsEachDivergence(t *testing.T) {

	cases := []struct {
		name    string
		mutate  func(*container.InspectResponse)
		wantSub string
	}{
		{"runtime", func(i *container.InspectResponse) { i.HostConfig.Runtime = "runc" }, "runtime"},
		{"privileged", func(i *container.InspectResponse) { i.HostConfig.Privileged = true }, "privileged"},
		{"cap-add", func(i *container.InspectResponse) { i.HostConfig.CapAdd = []string{"NET_ADMIN"} }, "cap-add"},
		{"docker socket via --mount", func(i *container.InspectResponse) {

			i.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeBind, Source: "/var/run/docker.sock", Target: "/run/docker.sock"}}
		}, "mounts"},
		{"device", func(i *container.InspectResponse) {

			i.HostConfig.Devices = []container.DeviceMapping{{PathOnHost: "/dev/kmsg", PathInContainer: "/dev/kmsg"}}
		}, "devices"},
		{"host pid", func(i *container.InspectResponse) { i.HostConfig.PidMode = "host" }, "pid namespace"},
		{"host network", func(i *container.InspectResponse) { i.HostConfig.NetworkMode = "host" }, "network namespace"},
		{"writable rootfs", func(i *container.InspectResponse) { i.HostConfig.ReadonlyRootfs = false }, "rootfs"},
		{"memory", func(i *container.InspectResponse) { i.HostConfig.Memory = 512 << 20 }, "memory"},
		{"swap enabled", func(i *container.InspectResponse) { i.HostConfig.MemorySwap = -1 }, "memory-swap"},
		{"cpus", func(i *container.InspectResponse) { i.HostConfig.NanoCPUs = 2e9 }, "cpus"},
		{"pids", func(i *container.InspectResponse) { n := int64(4096); i.HostConfig.PidsLimit = &n }, "pids-limit"},
		{"caps", func(i *container.InspectResponse) { i.HostConfig.CapDrop = nil }, "cap-drop"},
		{"security opts", func(i *container.InspectResponse) { i.HostConfig.SecurityOpt = nil }, "security-opt"},
		{"app mount writable", func(i *container.InspectResponse) {

			i.HostConfig.Binds = []string{
				"/srv/citadel/tenants/demo/data:" + DataMount + ":rw",
				"/srv/citadel/tenants/demo/app/current:" + AppMount + ":rw",
			}
		}, "binds"},
		{"uncapped runtime log", func(i *container.InspectResponse) {

			// A container created before the platform capped the log.
			i.HostConfig.LogConfig = container.LogConfig{Type: "json-file"}
		}, "log max-size"},
		{"log driver", func(i *container.InspectResponse) {

			i.HostConfig.LogConfig.Type = "local"
		}, "log driver"},
		{"restart policy", func(i *container.InspectResponse) {

			i.HostConfig.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyAlways}
		}, "restart policy"},
		{"published port", func(i *container.InspectResponse) {

			i.NetworkSettings.Ports = nat.PortMap{
				"8090/tcp": []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "8090"}},
			}
		}, "published ports"},
		{"wrong address", func(i *container.InspectResponse) {

			i.NetworkSettings.Networks["t-demo"].IPAddress = "10.213.1.4"
		}, "address on t-demo"},
		{"detached", func(i *container.InspectResponse) {

			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{}
		}, "not attached"},
		{"image", func(i *container.InspectResponse) {

			i.Image = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			i.Config.Image = i.Image
		}, "image"},
		{"stale encryption key", func(i *container.InspectResponse) {

			i.Config.Env = []string{"PB_ENCRYPTION_KEY=" + strings.Repeat("b", 32)}
		}, "environment"},
		{"missing GOMEMLIMIT", func(i *container.InspectResponse) {

			// A container created before the platform set the limit.
			i.Config.Env = []string{"PB_ENCRYPTION_KEY=" + strings.Repeat("a", 32)}
		}, "environment"},
		{"stale GOMEMLIMIT", func(i *container.InspectResponse) {

			i.Config.Env = []string{"GOMEMLIMIT=1MiB", "PB_ENCRYPTION_KEY=" + strings.Repeat("a", 32)}
		}, "environment"},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			spec := baseSpec()
			insp := inspectMatching(t, spec)
			tc.mutate(&insp)
			diff := diffSpec(insp, spec, mustHost(t, spec), mustConfig(t, spec))
			if len(diff) == 0 {

				t.Fatalf("%s was not detected as a difference", tc.name)
			}
			if !strings.Contains(strings.Join(diff, "; "), tc.wantSub) {

				t.Fatalf("diff %v does not mention %q", diff, tc.wantSub)
			}
		})
	}
}

// TestDiffSpecIgnoresImageInjectedEnv: Docker adds PATH and friends from the
// image, and treating those as drift would recreate every container on every
// tick.
func TestDiffSpecIgnoresImageInjectedEnv(t *testing.T) {

	spec := baseSpec()
	insp := inspectMatching(t, spec)
	insp.Config.Env = append([]string{"PATH=/usr/bin", "HOME=/"}, insp.Config.Env...)
	if diff := diffSpec(insp, spec, mustHost(t, spec), mustConfig(t, spec)); len(diff) != 0 {

		t.Fatalf("image-injected environment read as drift: %v", diff)
	}
}

func mustConfig(t *testing.T, spec driver.InstanceSpec) *container.Config {

	t.Helper()
	cfg, _, _, err := buildConfigs(spec)
	if err != nil {

		t.Fatal(err)
	}
	return cfg
}

func mustHost(t *testing.T, spec driver.InstanceSpec) *container.HostConfig {

	t.Helper()
	_, host, _, err := buildConfigs(spec)
	if err != nil {

		t.Fatal(err)
	}
	return host
}

// inspectMatching builds the inspect response a correctly-created container
// would produce for spec.
func inspectMatching(t *testing.T, spec driver.InstanceSpec) container.InspectResponse {

	t.Helper()
	cfg, host, _, err := buildConfigs(spec)
	if err != nil {

		t.Fatal(err)
	}
	pids := *host.PidsLimit
	// Docker reports the image as its ID; imageMatches also accepts the repo
	// digest recorded in Config.Image, which is what a real inspect shows.
	return container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID:    "deadbeef",
			Image: spec.ImageDigest,
			State: &container.State{Running: true},
			HostConfig: &container.HostConfig{
				Runtime:        host.Runtime,
				ReadonlyRootfs: host.ReadonlyRootfs,
				Binds:          host.Binds,
				CapDrop:        host.CapDrop,
				SecurityOpt:    host.SecurityOpt,
				RestartPolicy:  host.RestartPolicy,
				LogConfig:      host.LogConfig,
				Resources: container.Resources{
					Memory: host.Memory, MemorySwap: host.MemorySwap,
					NanoCPUs: host.NanoCPUs, PidsLimit: &pids,
				},
			},
		},
		Config: cfg,
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				spec.Network: {IPAddress: spec.IP},
			},
		},
	}
}

func hasOpt(list []string, want string) bool {

	for _, v := range list {

		if v == want {

			return true
		}
	}
	return false
}

// TestSpecSetsGoMemLimit: the GC's soft limit sits below the cgroup's hard one,
// and an explicit value in the spec wins.
func TestSpecSetsGoMemLimit(t *testing.T) {

	cfg, _, _, err := buildConfigs(baseSpec())
	if err != nil {

		t.Fatal(err)
	}
	// runsc, 256 MiB: (256-48)*70% — the sentry and the guest page cache share the cgroup.
	if !sameStrings(cfg.Env, []string{"GOMEMLIMIT=145MiB", "PB_ENCRYPTION_KEY=" + strings.Repeat("a", 32)}) {

		t.Errorf("env = %v", cfg.Env)
	}

	for _, tc := range []struct {
		runtime string
		mem     int
		want    int
	}{
		{"runc", 256, 217},
		{"runsc", 128, 56},
		{"runsc", 64, 0}, // 11 MiB would only make the GC thrash
		{"runsc", 0, 0},
		{"runc", 0, 0},
	} {

		s := baseSpec()
		s.Runtime, s.MemMiB = tc.runtime, tc.mem
		if got := goMemLimitMiB(s); got != tc.want {

			t.Errorf("%s %d MiB: GOMEMLIMIT = %d MiB, want %d", tc.runtime, tc.mem, got, tc.want)
		}
	}

	s := baseSpec()
	s.Env["GOMEMLIMIT"] = "100MiB"
	cfg, _, _, err = buildConfigs(s)
	if err != nil {

		t.Fatal(err)
	}
	n := 0
	for _, e := range cfg.Env {

		if strings.HasPrefix(e, "GOMEMLIMIT=") {

			n++
			if e != "GOMEMLIMIT=100MiB" {

				t.Errorf("explicit GOMEMLIMIT overridden: %s", e)
			}
		}
	}
	if n != 1 {

		t.Errorf("%d GOMEMLIMIT entries, want 1", n)
	}
}

// TestWorkingSetExcludesInactiveFileCache: the portal's figure matches
// `docker stats`, on cgroup v2 and v1, and never underflows.
func TestWorkingSetExcludesInactiveFileCache(t *testing.T) {

	const mib = 1 << 20
	for _, tc := range []struct {
		name string
		m    container.MemoryStats
		want uint64
	}{
		{"v2", container.MemoryStats{Usage: 90 * mib, Stats: map[string]uint64{"inactive_file": 40 * mib}}, 50 * mib},
		{"v1", container.MemoryStats{Usage: 90 * mib, Stats: map[string]uint64{"total_inactive_file": 30 * mib}}, 60 * mib},
		{"no stats", container.MemoryStats{Usage: 90 * mib}, 90 * mib},
		{"underflow", container.MemoryStats{Usage: 10 * mib, Stats: map[string]uint64{"inactive_file": 40 * mib}}, 10 * mib},
	} {

		if got := workingSet(tc.m); got != tc.want {

			t.Errorf("%s: workingSet = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The one exec into a live instance takes a bare database name and nothing
// else (INV-9): no path, no flag, no hidden file.
func TestSnapshotAcceptsOnlyABareDatabaseName(t *testing.T) {

	for _, name := range []string{"data.db", "auxiliary.db"} {

		if !driver.ValidDBName(name) {

			t.Errorf("%q was refused", name)
		}
	}
	for _, name := range []string{"", "../x.db", "/etc/passwd", ".hidden.db", "data.db-wal", "--help", "a/b.db"} {

		if driver.ValidDBName(name) {

			t.Errorf("%q was accepted", name)
		}
	}
}
