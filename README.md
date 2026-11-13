# Citadel - a PocketBase sandbox platform

Multi-tenant hosting for [PocketBase](https://pocketbase.io) applications. Every
tenant gets a **separate, hardened, independently-versioned PocketBase instance**
in its own container on its own internal network. Tenants ship application
packages (hooks, migrations, static assets) and never touch the binary, the
image, or its flags.

The design assumption behind everything: **a tenant's code is hostile**.
PocketBase's JSVM gives `pb_hooks` shell execution, raw SQL and an HTTP client,
so the platform treats every instance as already compromised and secures the
boundary around it: network, filesystem, kernel surface, and the record of who
authorised what.

---

## Features

- **Isolation.** Each tenant gets one container and one internal bridge network,
  with no published ports. Containers run read-only, with all capabilities
  dropped, under gVisor.
- **Deny-by-default egress.** Granted tenants reach the internet only through a
  forward proxy that filters by CONNECT target and TLS SNI. The allowlist is
  generated from active grants, so a revocation takes effect within one
  reconcile tick. Cloud metadata is never reachable.
- **Packages, not binaries.** Uploads are validated, stored content-addressed,
  and deployed through a ladder: snapshot, swap, health-check, smoke replay. A
  failure at any step rolls back code *and* data. Packages can be deployed from
  the CLI, the portal, or a CI token.
- **Hardened images by digest.** Images are built `FROM scratch` against a
  committed upstream checksum, reproducibly, and scheduled by digest, never by
  tag.
- **A reconciler that alerts instead of fighting.** It converges containers,
  networks and firewall rules every few seconds. Where converging would be
  dangerous (an image mismatch, a rule with no grant behind it) it raises drift
  instead.
- **Accountability.** Each tenant has exactly one owner, with ownership kept as
  a history. Access is granted in tiers (auto, named approver, break-glass),
  every grant expires, and break-glass notifies the tenant at grant time.
- **A checkable audit log.** The log is append-only and hash-chained, and chain
  heads are signed. Attestations are derived from the **host**, not the
  database, and a divergence raises an alert, never a silent repair.
- **Backups and one-way upgrades.** Live snapshots have per-kind retention, and
  a restore refuses to cross runtime versions. Upgrades are per-tenant and
  rehearsed on a throwaway copy with no egress.
- **Operations.** Subdomain routing with per-tenant rate limits and body caps,
  instant quarantine, per-tenant logs, and a fleet view that leads with drift.

The load-bearing invariants (INV-1…20) and the reasoning behind every choice are
in [docs/design.md](docs/design.md#1-invariants--read-first).

---

## Repository layout

| | |
|---|---|
| `cmd/` | the control-plane daemon, the operator CLI, and the rehearsal probe |
| `internal/` | reconciler, driver, network policy, grants, audit, packages, portal |
| `images/` | the hardened PocketBase image, the edge proxy, the egress proxy, the probe |
| `deploy/` | supporting service configuration |
| `hack/` | development-host tooling and the VM lifecycle |
| `test/` | acceptance suites, the red-team matrix, and the network probes |
| `docs/` | the design document |
| `rules/`, `rule-tests/` | repo-specific static-analysis rules |

---

## Running it locally

Anything touching containers, netfilter or loopback filesystems runs on Linux. In
development that is a **UTM** VM on a stock Ubuntu kernel, because the guarantees
are kernel guarantees. Go binaries cross-compile on the Mac, and `hack/in-vm.sh`
syncs the tree into the guest and runs commands there as root.

**Prerequisites:** Go (see `go.mod`), `make`, [UTM](https://mac.getutm.app)
(`brew install --cask utm`), `ast-grep` (`brew install ast-grep`) and
`shellcheck` (`brew install shellcheck`).

### First run

```sh
make vm-create      # download, seed and register the VM in UTM
make vm-up          # boot it and wait for cloud-init
make vm-provision   # Docker, gVisor, and the suites' dependencies
make vm-bootstrap   # user-namespace remapping, local registry, pb-hardened matrix
make images-all     # registry, pb-hardened matrix, edge, egress, probe
```

Nothing needs preparing by hand. `vm-bootstrap` is slow, because enabling
user-namespace remapping rebuilds the image store. Re-run `images-all` whenever
an image needs rebuilding. Builds append to `images/*/digests.txt`, which
`in-vm.sh` copies back to the Mac. These files hand the images over to the control
plane, which schedules **digests, never tags**. `PB_FROM`/`PB_TO` in the Makefile
name the version pair the upgrade suite uses.

See [hack/vm/README.md](hack/vm/README.md) for VM details and environment
variables.

### Starting the control plane

There is no systemd unit or `make` target for the daemon. Build it and run it by
hand:

```sh
make build          # static bin/controlplaned and bin/citadel, cross-compiled

hack/in-vm.sh bash -c 'IP=$(ip -4 addr show scope global | awk "/inet /{print \$2}" | cut -d/ -f1 | head -1)
cat >/tmp/dev-config.json <<EOF
{
  "apps_domain": "apps.$IP.nip.io",
  "portal_addr": "0.0.0.0:8080",
  "portal_allow_public": true
}
EOF'

hack/in-vm.sh bash -c 'setsid bin/controlplaned --config /tmp/dev-config.json \
  --seed-digests images/pb-hardened/digests.txt </dev/null \
  >>/tmp/controlplaned.log 2>&1 &'

hack/in-vm.sh bin/citadel fleet          # ready when this answers
hack/in-vm.sh pkill -f controlplaned   # stop it
```

The edge, the egress proxy and the rehearsal probe are scheduled by digest. Left
out of the config, `edge_image`, `egress_proxy_image` and `probe_image` are
resolved at start-up from the newest entry for the host's architecture in
`images/edge-caddy/digests.txt`, `images/egress-proxy/digests.txt` and
`images/rehearse-probe/digests.txt`, which `make edge-image`, `make egress-image`
and `make probe-image` append to. All three build in the VM and push to the local
registry:

```sh
hack/in-vm.sh make edge-image     # EDGE IMAGE DIGEST: 127.0.0.1:5000/edge-caddy@sha256:…
hack/in-vm.sh make egress-image   # EGRESS PROXY IMAGE DIGEST: 127.0.0.1:5000/egress-proxy@sha256:…
hack/in-vm.sh make probe-image    # PROBE IMAGE DIGEST: 127.0.0.1:5000/rehearse-probe@sha256:…
```

The digests files are resolved relative to the daemon's working directory (the
repo root in development). On a host where nothing has been built, the daemon
falls back to the unpinned tags `caddy:2` (no rate_limit handler, so the fleet view
reports `rate_limit` drift) and `v2p-squid:6-r2`, and logs a warning naming the
build that fixes it. The probe has no fallback: without one, upgrades cannot be
rehearsed, and the daemon warns about that too. A tag set explicitly in the config is refused unless
`allow_unpinned_images` is set. A container running a different image is recreated
on the next tick.

- **Config defaults** describe a single-host install, so a config only lists what
  differs.
- **The portal** binds to `127.0.0.1:8080` unless `portal_allow_public` is set.
  Binding a public address is fine in the dev VM because tenants cannot reach the
  host, but production needs a management interface. The portal speaks plain HTTP.
  Behind a TLS-terminating proxy, set `portal_secure_cookies` so the session cookie is
  `Secure` and `__Host-`-prefixed. Signing out or changing a password ends every
  portal session that principal holds. Failed logins are throttled per principal and per
  address.
- **`--seed-digests`** registers every version listed in a `digests.txt`.
- **Other flags:** `--log-level debug`, and `--once` for a single tick.
- **Startup checks:** the daemon refuses to start when it is not root, the firewall
  backend is not `iptables`, `runsc` is missing, or the `userns_remap` setting
  disagrees with the host.

### Provisioning a tenant

`citadel` talks to the root-only unix socket. Every mutation is attributed, and the
default principal comes from `SUDO_USER`, so create it first:

```sh
hack/in-vm.sh bin/citadel principal create person:ubuntu --name dev
hack/in-vm.sh bin/citadel runtime-version add 0.42.2
hack/in-vm.sh bin/citadel tenant create --slug demo --pb-version 0.42.2 \
    --owner person:ubuntu --disk-mib 256
hack/in-vm.sh bin/citadel tenant status demo

hack/in-vm.sh bin/citadel release upload demo --app-dir test/fixtures/pkg-basic --deploy
hack/in-vm.sh bin/citadel release list demo
hack/in-vm.sh bin/citadel rollback demo
```

Slugs are at most ten characters, because they become interface names. To act
as another principal, use `--as <principal>` or `CITADEL_PRINCIPAL`. `test/fixtures/`
holds working packages.

### Reaching a tenant

Routing is by subdomain, and the edge proxy publishes `:80`:

```sh
VM_IP=$(utmctl ip-address citadel | head -1)                # from the Mac
curl -fsS http://demo.apps.$VM_IP.nip.io/api/health

hack/in-vm.sh curl -fsS -H "Host: demo.apps.$VM_IP.nip.io" http://127.0.0.1/api/health
```

`apps_domain` is `apps.<VM_IP>.nip.io`. [nip.io](https://nip.io) resolves any
name with an IP in it to that IP, so the tenant opens in any browser at
`http://demo.apps.<VM_IP>.nip.io/` with no `/etc/hosts` entry. This needs public
DNS, and some routers refuse DNS answers that point at private addresses
(DNS-rebind protection). If the name does not resolve, send a `Host:` header or
add the name to `/etc/hosts`. The tenant's PocketBase dashboard is at
`http://demo.apps.<VM_IP>.nip.io/_/`. There is no superuser password to look up: sign in
to the portal as the tenant's owner (or an `admin`), open the tenant and press **Open PocketBase
admin**. The portal signs a short-lived superuser token from `pb_data` on the host and
the edge hands it to the admin UI. It never calls the instance's API.

### The operator console

`citadel` is the complete surface. Run it with no arguments to list every command.
Add `--json` for raw output, or `--socket` to use a different socket. Start any
investigation with:

```sh
hack/in-vm.sh bin/citadel fleet                # drift, denials, quarantines, chain head, anchor age
hack/in-vm.sh bin/citadel audit verify         # is the record itself still trustworthy?
hack/in-vm.sh bin/citadel tenant status demo   # intent vs. what the host shows
```

The portal's `/fleet` page is for the `platform` principal only. It is
deliberately not published through the edge, which joins every tenant network.
In the portal, `platform` opens only the projects it holds a role on (orphan
custody), like any other principal. Its pages are read-only apart from the
on-demand re-check on `/attestations`. Tier-2 decisions, break-glass and its
review need a named person (INV-16), so they are `citadel` commands on the host.

```sh
hack/in-vm.sh bin/citadel principal set-password platform --password <secret>
```

### The tenant portal

The portal is one listener, enabled whenever `portal_addr` is set. A tenant
appears for any principal with a role on it. Set a password and open
`http://<VM_IP>:8080/`:

```sh
hack/in-vm.sh bin/citadel principal set-password person:ubuntu --password <secret>
```

- **Credentials** are checked against the control plane's own store.
- **Sessions** are signed with `/srv/citadel/control/portal-session.key`.
  Delete that file to invalidate every session.
- **The CI API** is served under `/api/` and accepts bearer tokens only. A
  request without one gets 401, `/api/v1/admin/*` gets 403 (it is served on
  the unix socket only), and every `/api/v1/tenants/{id}` route needs a role on
  that tenant: any role to read, the design §14.1 capability to change it.
  There are two exceptions. Downloading a release package needs the deploy
  capability, because the package is the tenant's code. Accepting or declining
  an ownership transfer can only be done by the principal it was offered to.
  The platform principal cannot hold a token:

```sh
hack/in-vm.sh bin/citadel token create --principal person:ubuntu --name ci   # prints the secret once

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
    http://<VM_IP>:8080/api/v1/tenants/demo/releases/<rid>/deploy

curl -fsS -o <rid>.zip -H "Authorization: Bearer $TOKEN" \
    http://<VM_IP>:8080/api/v1/tenants/demo/releases/<rid>/download
```

### The short way

```sh
make accept-packages ARGS=--keep
```

This command leaves the daemon and a deployed tenant running, then prints the
portal URL, the sign-in and the `/etc/hosts` line. Tear it down with
`citadel tenant destroy` and `pkill -f controlplaned`.

### Day to day

```sh
make build          # static Linux binaries into bin/
make test           # unit tests, natively on the Mac
make vet lint       # go vet, then the repo's own static-analysis rules
make check          # EVERYTHING — lint, unit, images, every suite, the red team

make accept-controlplane   # provision, reconcile, destroy, audit
make accept-packages       # package pipeline and portal
make accept-egress         # egress enforcement
make accept-upgrade        # backups and independent upgrades
make netprobe              # network-posture probes
make redteam               # the security matrix
```

- **Suites** share one VM and daemon, so they run sequentially. `ARGS=--keep`
  leaves a suite's tenant in place.
- **Network probes:** three of them need a provisioned tenant and skip without
  one.
- **`make redteam`** is a gate: **every probe must fail to reach its goal**, and every
  probe carries a positive control, so one that could not have seen an escape fails
  instead of passing. Re-run it after any container-runtime upgrade or firewall-backend
  change. It needs a few GiB free: the backup-bomb probe stages up to twice a tenant's
  image, and refuses to run where that would be unsafe.

### Against something other than UTM

`hack/in-vm.sh` needs only ssh:

```sh
PB_VM_HOST=127.0.0.1 PB_VM_PORT=2222 make accept-controlplane
```

---

## Deploying to a running VM

You need a single Linux VM with root access. Any instance family works,
including arm64, because nested virtualisation is not required.

1. **Prepare the host.** Run the provisioning script (container runtime and
   gVisor), then the bootstrap script (user-namespace remapping, firewall
   backend pin, registry, image matrix). Enable remapping **before first
   production use**.
2. **Build the images**: the PocketBase versions to offer, the edge proxy, the
   egress proxy and the probe. Note the digests.
3. **Write the config**: set the tenant domain. The image settings default to
   the newest digests the builds recorded, so set them only to pin something else.
4. **Start the control plane** as root (see
   [Starting the control plane](#starting-the-control-plane)).
5. **Verify before traffic.** Run the network probes and the red-team matrix on
   the real host.

**Not built yet:**

- systemd units;
- firewall persistence across reboot;
- wildcard TLS automation;
- offsite backups and anchors.

See [docs/design.md §16](docs/design.md#16-what-is-next) for what comes next,
and §12 for when to quarantine versus force-upgrade.

---

## Documentation

| | |
|---|---|
| [docs/design.md](docs/design.md) | the **why**: invariants, architecture, threat model, decisions |
| [hack/vm/README.md](hack/vm/README.md) | creating and driving the development VM |

Read design §1 (invariants) and §9 (network model) before changing anything that
crosses the sandbox boundary, and §14 as well if it touches ownership, grants or
the audit record.

## License

Citadel is licensed under the [Functional Source License 1.1, Apache 2.0 Future
License](LICENSE) (FSL-1.1-ALv2). You may use, modify and redistribute it for any
purpose other than offering a competing commercial product or service. Each
release becomes available under the Apache License 2.0 two years after it is
published. Third-party components are listed in [NOTICE](NOTICE). Contributions require
signing the [CLA](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).
