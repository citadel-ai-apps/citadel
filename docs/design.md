# PocketBase Sandbox Platform — Design

Multi-tenant hosting for PocketBase applications. Each tenant gets a **separate, hardened,
independently-versioned PocketBase instance** in its own Docker container, under gVisor, on
its own internal network. Tenants ship application packages; they never touch the binary.

This document is the *why*. Read §1 and §9 before changing anything that crosses the sandbox
boundary, and §14 as well if it touches ownership, grants or the audit record. The README
covers what the platform does and how to run it.

Docker shares the host kernel, so the network model (§9) and security model (§13) carry more
weight here than they would behind a hypervisor.

---

## Table of contents

1. [Invariants — read first](#1-invariants--read-first)
2. [Where each invariant is enforced](#2-where-each-invariant-is-enforced)
3. [Architecture](#3-architecture)
4. [Runtime: Docker](#4-runtime-docker)
5. [The hardened image](#5-the-hardened-image)
6. [The tenant package](#6-the-tenant-package)
7. [Storage and on-disk layout](#7-storage-and-on-disk-layout)
8. [Control plane](#8-control-plane)
9. [Network model and egress control](#9-network-model-and-egress-control)
10. [Edge proxy](#10-edge-proxy)
11. [Backups](#11-backups)
12. [Versioning and upgrades](#12-versioning-and-upgrades)
13. [Security model](#13-security-model)
14. [Ownership, grants and audit](#14-ownership-grants-and-audit)
15. [Observability](#15-observability)
16. [What is next](#16-what-is-next)
17. [Decisions](#17-decisions)
18. [Glossary](#18-glossary)

---

## 1. Invariants — read first

These are load-bearing. If an implementation violates one, the implementation is wrong, not
the invariant.

| ID | Invariant | Why |
|----|-----------|-----|
| **INV-1** | **Tenant code is hostile.** A tenant's `pb_hooks` is arbitrary code execution inside the PocketBase process. Under Docker the boundary is namespaces, cgroups and seccomp, not a hypervisor. Tenant containers, the one-shot CLI containers that run against tenant data, and rehearsal instances all run under gVisor; `tenant_runtime` accepts nothing but `runsc`. | PocketBase's JSVM exposes `$os` (including shell execution), `$dbx` (raw SQL), `$filepath` and `$http`. It is an extension mechanism, not a sandbox. Tenant containers run under gVisor (D2). |
| **INV-2** | **The PocketBase binary is never modified and never supplied by the tenant.** The image, entrypoint and flags are platform-owned. A runtime version's digest comes only from `images/pb-hardened/digests.txt`, the platform's own build. | "Hardened PocketBase" means a hardened *environment*, not a patched binary. |
| **INV-3** | **Exactly one PocketBase process may ever have a given `pb_data` open.** The instance lock serialises every control-plane operation on a tenant; within it, the single container name, destroy-before-ensure, and one-shots that are removed before the lock is released (and swept at start-up) keep a second process off the data. | SQLite is single-writer. Two processes corrupt it. |
| **INV-4** | **PocketBase version upgrades are one-way.** Rollback is *restore from snapshot*, never *swap the image tag back*: an operator stops the tenant, pins its runtime to the snapshot's version (`pin-runtime`), restores, then starts it. A forced restore across versions leaves the instance stopped. | A newer binary migrates `pb_data` irreversibly, and the failure is **silent**: an old binary on migrated data can serve `/api/health` OK with a broken data plane. Nothing at runtime catches it, so the snapshot-only rollback and the `backup.pb_version` restore check are absolute. |
| **INV-5** | **The control plane never manages an instance through that instance's PocketBase API.** Management is process-level and filesystem-level only. The only calls to an instance are read-only verification: `/api/health`, the superuser `auth-refresh` data-plane check, and the release manifest's own smoke requests. | The tenant is superuser of their own instance and can delete any account the platform creates. |
| **INV-6** | **Two independent version axes: runtime version and app release. Never move both in one operation.** | If both change and it breaks, nobody knows which did it. Rollback paths differ (§12). |
| **INV-7** | **Egress is denied by default.** The default is an `internal: true` network with no outbound path, and no platform network has IPv6. Cloud metadata (`169.254.0.0/16`, `fd00:ec2::254`) is blocked unconditionally and never allowlistable, in `iptables` and — wherever Docker manages a v6 `DOCKER-USER` chain — `ip6tables`, where a deny that cannot be written stops the control plane. | SSRF from a hook to instance metadata is the most likely credential-leak path. |
| **INV-8** | **Routing is by subdomain, never by path prefix.** | PocketBase assumes it is at root: admin UI at `/_/`, API at `/api/`, assets at `/`. |
| **INV-9** | **No `docker exec` into a live tenant container, and no interactive shell in the production path.** The single exception is the platform's own `pbsnap` live copy (INV-20): a fixed binary whose only argument is a database name, behind `Driver.Snapshot`. There is no general exec method. | If you cannot debug without a shell, the log pipeline is missing. An exec path is also an escalation path. |
| **INV-10** | **`pb_data` never lives on a network filesystem.** It is an ext4 loop mount, and the directories holding the loop images, their rehearsal copies and backups must be local too; the control plane refuses to start when `pb_root` is on NFS, SMB, FUSE or similar. | SQLite WAL locking, and a loop device over a network filesystem is the same failure one layer down. |
| **INV-11** | **The reconciler never changes an instance's runtime version** — running, stopped or recreated. Every start path refuses when the desired digest differs from the one the instance last ran. Image changes go through `Upgrade` (which snapshots first, and covers same-version hardening-rev bumps) or the operator-only `pin-runtime` on a stopped tenant. | Prevents an unbacked-up one-way migration triggered by a stray row edit, a reboot, or a failed rollback. |
| **INV-12** | **Tenant containers publish no host ports.** Ingress happens because the edge proxy joins the tenant's network. | Every published port is a DNAT rule, a chance to bind `0.0.0.0`, and a path that bypasses host `INPUT` rules. |
| **INV-13** | **`DOCKER-USER` only filters routed traffic.** Container-to-host traffic lands in `INPUT`; host protection needs explicit `INPUT` rules. | The most commonly missed gap in "block container egress" recipes. |
| **INV-14** | **`HTTP_PROXY`/`HTTPS_PROXY` are ergonomics, not enforcement.** The netfilter DROP is the boundary. | Cooperative hooks honour them; hostile hooks open raw sockets. |
| **INV-15** | **Never, for a tenant container**: mount `/var/run/docker.sock`; `--privileged`; `--network=host` or any host namespace; `--cap-add` of anything; a device. **Never, for the daemon**: `--ip-forward-no-drop`. Platform containers add only what they document: the edge `NET_BIND_SERVICE`, the egress proxy `CHOWN SETUID SETGID DAC_OVERRIDE`. | Each one alone voids the model. A tenant container found with any of them is security drift. |
| **INV-16** | **A manifest declaration is a request, never a grant.** Proxy ACLs, relay ACLs and storage credentials are generated from the `access_grant` table only (§14.2). | The manifest is tenant-controlled input; enforcing from it lets a tenant grant itself access with no approver, expiry or record. |
| **INV-17** | **Every tenant has exactly one accountable owner principal at all times.** Never null, never inferred, and an active principal. "At most one" is a SQL index; "at least one" is enforced at the single code path that moves an owner seat, inside the same transaction, and checked fleet-wide on every accountability pass. Transfer is two-party and audited; suspending a principal cancels its open offers and never orphans a tenant; principals are never deleted. | "Who owns this instance, and who owned it in March?" must always be answerable. |
| **INV-18** | **The audit log is append-only and hash-chained. Nothing updates or deletes an audit row — including tenant deletion.** Triggers refuse `UPDATE` and `DELETE`, and recursive triggers are on so `INSERT OR REPLACE` cannot delete around them. Audit retention outlives data retention. | The record of who authorised access to data must survive the data. |
| **INV-19** | **An access attestation is derived from the host, never from the control-plane database.** Divergence is an alert and a freeze, never a silent reconcile (§14.5). | An audit that reads the table that generated the rules proves nothing. |
| **INV-20** | **The host never opens a live tenant database through SQLite's locking.** Host-side reads of `pb_data` use `immutable=1` (no locks, no `-wal`/`-shm` access, and so no WAL contents); live copies are taken from inside the sandbox by `pbsnap` (§11). A stopped instance's files are copied as plain bytes, `-wal` included, under the lock. | gVisor keeps fcntl locks inside the sandbox. A host connection that believes it is alone rebuilds `-shm` and, on close, checkpoints and unlinks `-wal`/`-shm` under the running instance, which then fails every query with `SQLITE_IOERR_SHORT_READ`. |

---

## 2. Where each invariant is enforced

Each invariant names the code that holds it and the check that would notice if it stopped
holding. A change that moves one of these moves the row with it.

| ID | Enforced by | Noticed by |
|----|-------------|------------|
| INV-1 | `config.Validate` (runsc only); `docker.buildConfigs`; one-shot and rehearsal use the tenant spec's runtime | `controlplaned` start-up host facts; red-team `escape-battery` |
| INV-2 | image ENTRYPOINT; `buildConfigs` sets no entrypoint, digest-only image refs; `addRuntimeVersion` accepts only a `digests.txt` entry | `diffSpec` image check |
| INV-3 | `hostfs.Lock`; Destroy before Ensure in every start path; one-shot removed with an uncancellable context; `Recover` sweeps one-shots | acceptance `upgrade.sh` |
| INV-4 | `ErrDowngrade`; `backup.Restore` pb_version guard; forced restore leaves the instance stopped; failed rollback stops and quarantines; `PinRuntime` | `DriftUpgradeStuck`; digest guard |
| INV-5 | no management client exists; `health` makes only read-only calls | — |
| INV-6 | process-local claim + `upgrade_job` row + instance lock; digest guard on deploy | `claim_test.go` |
| INV-7 | `internal: true` networks with IPv6 off; `DeniedRanges`/`DeniedRangesV6`; Squid `v2p_blocked_dst` | netprobe 01–04, 08, 11 |
| INV-8 | `proxyctl` host matchers only | acceptance `controlplane.sh` (every request by `Host`) |
| INV-9 | `Driver.Snapshot` is the only exec, fixed binary, validated name | red-team `escape-battery` |
| INV-10 | ext4 loop mount; `hostfs.CheckLocal` at start-up | — |
| INV-11 | `digestGuard` on every start path; `running_digest`; only `Upgrade` and `PinRuntime` move the digest | `DriftDigest` + `instance.digest_drift.detected` |
| INV-12 | `PortBindings: {}`, no `ExposedPorts`; posture diff recreates | `DriftPosture`; attestation `published_port` |
| INV-13 | `INPUT -i br-t-+ -j DROP` (v4 and v6) re-asserted every tick | netprobe 02, 14 |
| INV-14 | per-tenant DROP and proxy-only accept in `DOCKER-USER` | netprobe 11 |
| INV-15 | `CapDrop: ALL`, no `CapAdd`/`Privileged`/host modes; start-up refuses `--ip-forward-no-drop` | `DriftPosture`; netprobe 00; attestation network/mount findings |
| INV-16 | `enforceableGrants` from `access_grant` only; Tier-3 only via break-glass; Tier-2 decided by a named person within the expiry ceiling; the portal has no decision or break-glass route | red-team `grant-forge`, `tier2-probe`; portal `TestPortalDecidesNoGrantAndOpensNoBreakglass` |
| INV-17 | `one_owner_per_tenant` index; `identity.replaceOwner` | `checkOwners` → `DriftOwnerless`; red-team `orphan-owner` |
| INV-18 | `audit_event`/`audit_anchor` triggers; `recursive_triggers(ON)`; `Append` needs a transaction | `audit verify`; signed anchors; red-team `audit-tamper` |
| INV-19 | `attest.observe` reads iptables, the running proxy and `docker inspect` | attestation outcome; freeze; `egress.acl.tampered`; `egress.acl.unbacked` |
| INV-20 | `safesqlite` (`immutable=1`, single-file VFS); `pbsnap` in-sandbox | `safesqlite` and `pbauth` tests |

---

## 3. Architecture

```
                          ┌───────────────────────────────┐
     *.apps.example.com   │        Edge proxy (Caddy)     │
     ───────────────────▶ │  TLS · subdomain routing      │
                          │  SSE passthrough · rate limit │
                          └───┬────────┬────────┬─────────┘
                              │        │        │   joins each tenant network;
                              │        │        │   NO published tenant ports (INV-12)
        ┌─────────────────────┘        │        └───────────────────┐
        ▼                              ▼                            ▼
 ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
 │ net: t-a         │         │ net: t-b         │         │ net: t-c         │
 │ internal: true   │         │ internal: true   │         │ internal: true   │
 │ ┌──────────────┐ │         │ ┌──────────────┐ │         │ ┌──────────────┐ │
 │ │pb-hardened   │ │         │ │pb-hardened   │ │         │ │pb-hardened   │ │
 │ │  0.30.2-h4   │ │         │ │  0.28.6-h4   │ │         │ │  0.26.1-h3   │ │
 │ │/pb/app  (ro) │ │         │ └──────────────┘ │         │ └──────────────┘ │
 │ │/pb/pb_data rw│ │         └──────────────────┘         └──────────────────┘
 │ └──────┬───────┘ │
 └────────┼─────────┘   tenants with approved egress grants additionally join:
          │             ┌───────────────────────────────────────────┐
          └────────────▶│ net: egress   →  egress-proxy:3128        │
                        │ DOCKER-USER: only this destination allowed│
                        └───────────────────┬───────────────────────┘
                                            ▼  domain allowlist per source IP
                                        internet
 ┌───────────────────────────┐
 │      Control plane        │   Docker SDK over the unix socket (host side only)
 │  · HTTP API + portal      │   NEVER mounted into a tenant container (INV-15)
 │  · reconciler loop        │
 │  · netpolicy manager      │
 │  · release artifact store │   ┌──────────────────┐  ┌──────────────────┐
 │  · backup orchestrator    │   │  OCI registry    │  │  backup store    │
 │  · upgrade state machine  │   │  (zot, local)    │  │  (local)         │
 │  · SQLite state           │   └──────────────────┘  └──────────────────┘
 └───────────────────────────┘
```

Tenants run **different PocketBase versions**. That is the point (§12). The versions shown
here and in §5 are illustrative; the supported set is `images/pb-hardened/versions.txt`.

### Trust zones

| Zone | Contains | Trusts |
|------|----------|--------|
| **Platform** | control plane, edge proxy, registry, backup store, egress proxy | itself |
| **Tenant** | one container + its `pb_data` + its internal network | nothing; treated as fully compromised (INV-1) |

The only paths from tenant to platform are HTTP responses back through the edge proxy and,
for tenants with egress grants, CONNECT requests to the egress proxy. No shared writable
filesystem, no control-plane credentials in any container, no Docker socket near a tenant.

One boundary runs *inside* the platform zone: the **audit record**. The control plane writes
it, but an operator with database access must not be able to rewrite it undetected, so the
chain head is anchored under a signature (§14.4).

---

## 4. Runtime: Docker

Docker runs natively on laptops and any cloud VM, including arm64, with no
nested-virtualisation requirement, a mature Go SDK, and fast stop/start.

The cost is a shared kernel: under INV-1 the platform is one kernel LPE away from a
cross-tenant breach. Two mitigations:

1. **gVisor (`runsc`) for tenant containers only.** Same images and SDK, syscall
   interposition in userspace. Platform containers keep `runc`.
2. **`userns-remap`**, so container root is not host root. Tenant data dirs are chowned to
   `base+10001`, with the base read from `/etc/subuid`, never hardcoded. Enable it **before
   first production use**: it moves Docker's data root (named volumes included, so the local
   registry comes back empty), disables the containerd image store, and changes every image
   digest. The classic store pushes Docker v2 manifests, which zot accepts only with
   `http.compat: ["docker2s2"]` (set in `deploy/registry/zot-config.json`). That change is
   one-off: within a store, builds are reproducible (bases pinned by digest,
   `SOURCE_DATE_EPOCH=0`, file mtimes pinned), so a rebuild gives the same digest.

### Version and backend pinning

- **Docker ≥ 28.0**, which drops traffic to unpublished container ports by default. The
  control plane only logs the engine version; `test/netprobe/00-baseline.sh` is what fails
  below 28.
- **Never set `--ip-forward-no-drop`** (INV-15). It re-opens that hole.
- **Firewall backend pinned to `iptables`** in `daemon.json`. The control plane refuses to
  start on any other backend it is told about (an engine that reports none is accepted). Changing it counts as a hardening-rev bump with a full red-team
  re-run.
- Docker 29 groups its filter logic under `DOCKER-FORWARD`/`DOCKER-CT`/`DOCKER-BRIDGE`/
  `DOCKER-INTERNAL`. `DOCKER-USER` is still consulted first from `FORWARD`, *before* Docker's
  established-connection accept in `DOCKER-CT` (§9.5).
- After any engine upgrade, firewall-backend change or new host, re-run `test/netprobe/` and
  the red-team matrix before traffic.

### Container configuration for a tenant

```
--network              t-<slug>           # internal: true; no -p, ever (INV-12)
                                          # + the egress network, at create, only with a grant (§9.4)
--read-only
--tmpfs                /tmp:rw,noexec,nosuid,size=64m
--cap-drop             ALL
--security-opt         no-new-privileges:true
--security-opt         seccomp=<platform profile>    # runc only: runsc applies its own filter
--security-opt         apparmor=<platform profile>   # runc only, and only if the kernel has it
--pids-limit           128
--memory               256m
--memory-swap          256m               # equal to --memory => swap disabled
--cpus                 1.0
--restart              no                 # the reconciler owns restarts, not Docker
--log-opt              max-size=<log_max_bytes>,max-file=2   # stdout is a write path onto the host
--runtime              runsc
-v /srv/.../data:/pb/pb_data:rw
-v /srv/.../app:/pb/app:ro
-e PB_ENCRYPTION_KEY=<per-tenant>
-e GOMEMLIMIT=<below --memory>             # a soft GC limit under the cgroup's hard one
-e HTTP_PROXY, HTTPS_PROXY, NO_PROXY       # and lowercase; ergonomics only (INV-14)
```

`--restart no` is deliberate. Docker's restart policy has no backoff, no health semantics
and no visibility to the control plane, so restarts belong to the reconciler (§8.3).

Default sizing: **1 CPU, 256 MiB, 2 GiB disk** per tenant.

---

## 5. The hardened image

### Two version axes

```
pb-hardened:<pocketbase-version>-h<hardening-rev>

pb-hardened:0.30.2-h4
pb-hardened:0.28.6-h4      ← same hardening recipe, older PocketBase
pb-hardened:0.26.1-h3      ← older recipe, pending re-bake
```

- **Hardening rev**: base refresh, library CVE, entrypoint or profile change. Touches nothing
  in `pb_data`; rolled out fleet-wide after a red-team re-run.
- **PocketBase version**: migrates `pb_data` irreversibly. Per-tenant, gated, snapshotted
  and rehearsed (INV-4, INV-6, §12).

Every hardening rev is built for every supported PocketBase version, so the build is a matrix.

### Image contents

- `FROM scratch`: the static PocketBase binary, `pbsnap` (§11) and the CA bundle, nothing
  else. No shell and no package manager: a hook calling `$os.cmd()` can run only those two
  binaries, and every path it can write (`pb_data`, `/tmp`) is `noexec` inside the sandbox,
  so it cannot add a third. The red-team battery asserts both halves.
- PocketBase pinned to an exact upstream version, verified against a checksum **committed to
  the repository**. The network is trusted for the archive, never for the checksum.
- Non-root `USER 10001:10001`.
- CA bundle included: egress is CONNECT-without-MITM (§9.4), so hooks validate real origin
  certificates.
- No secrets, credentials, registry tokens or platform hostnames.

Runtime profiles:

- **seccomp**: the Moby default minus `ptrace`/`process_vm_*`/`kcmp`/`memfd_secret` and every
  capability-gated group. It only enforces under `runc`, because `runsc` applies its own
  filter. `smoke.sh` runs its functional suite under runc with the profile applied; nothing yet
  asserts that the dropped syscalls fail.
- **AppArmor** (`pb-hardened`): writes only to `/pb/pb_data` and `/tmp`, exec only of the
  binary, no raw sockets. It does not mediate the entry exec. On kernels without AppArmor the
  smoke checks warn rather than silently skip.

### Entrypoint and builds

The entrypoint is platform-owned (INV-2). It serves on a fixed port, with the data, hooks,
public and migrations directories at the platform's mounts. Settings are encrypted at rest
with a per-tenant key that is injected as an environment variable. Binding all interfaces
inside the container is safe, because the only network is the internal bridge (INV-12).

The build outputs a **digest**, and the digest is what the control plane schedules: never a
tag (INV-11). Provenance attestation is disabled so that identical inputs rebuild to an
identical digest.

On PocketBase 0.22.x, `admin create` against an empty `pb_data` fails **and exits 0**. Any
pre-0.23 path runs `migrate up` first and does not trust the exit code.

---

## 6. The tenant package

### Format

A zip containing **only**:

```
pb_hooks/          *.pb.js
pb_migrations/     *.js
pb_public/         static assets
pbapp.json         manifest
```

Everything else (binary, entrypoint, flags, `pb_data`, network) is platform-owned (INV-2).

### Manifest (`pbapp.json`)

```json
{
  "schemaVersion": 1,
  "name": "my-app",
  "version": "1.4.0",
  "pocketbase": { "min": "0.28.0", "max": "0.30.x" },
  "egress": ["api.stripe.com", "hooks.slack.com"],
  "healthcheck": { "path": "/api/health", "expectStatus": 200 },
  "smoke": [
    { "method": "GET", "path": "/api/collections/posts/records", "expectStatus": 200 }
  ]
}
```

- `pocketbase.min`/`max` gates scheduling **both ways**: no deploy onto an incompatible
  runtime, and no runtime upgrade the release declares incompatible.
- `egress` is a **request, not a grant** (INV-16). An empty or absent array is the default:
  no outbound path at all. Each entry raises a grant request (§14.2), and only approved
  grants reach the proxy allowlist. Tier-2 hosts deploy as `pending` rather than blocking the
  release.
- `smoke` requests are replayed after deploys and during upgrade rehearsal (§12).

### Validation rules

The upload is rejected with a specific, human-readable error naming the offending path when:

- total uncompressed size exceeds the cap (default 50 MiB), the file count exceeds the cap
  (default 2000), or the compression ratio is not sane (zip-bomb guard);
- an entry is outside `pb_hooks/`, `pb_migrations/`, `pb_public/` and `pbapp.json`;
- an entry is an absolute path, a `..` traversal, a symlink or a device node (zip has no
  hardlink entry type);
- an entry has the setuid/setgid bit, or an executable mode on a non-directory;
- `pb_hooks/` or `pb_migrations/` contains anything other than `.js`;
- `pbapp.json` does not parse or does not match the schema, or the `pocketbase` range is
  invalid;
- an `egress` entry is not a valid hostname or fails policy: IP literals (including
  shorthand forms such as `10.0.1` or `0x7f.1`), apex wildcards, wildcards over a public
  suffix (`*.co.uk`, `*.github.io`), reserved TLDs (`.internal`, `.local`, `.test` and the
  like) and platform domains are all refused. Names are not resolved here: denied ranges are
  refused by the proxy on every connection (§9.5);
- the range intersects no supported runtime version.

An `egress` entry this tenant previously had denied or revoked is never auto-granted,
whatever its tier (§14.7). Validation is a guardrail and a source of useful errors, **not** a
security boundary (INV-1).

---

## 7. Storage and on-disk layout

```
<pb_root>/                         # config `pb_root`, default /srv/citadel
  control/
    state.db                       # control-plane SQLite
    keys/                          # per-tenant encryption keys (0600, root-owned)
    audit-signing.key              # signs chain anchors + attestations (0600)
    portal-session.key             # signs portal session cookies
  audit/
    anchors/<timestamp>.json       # signed chain heads (§14.4)
    attestations/<tenant-id>/      # signed access attestations (§14.5)
    evidence/                      # e.g. a hand-edited egress allowlist, kept before regeneration
  artifacts/
    <sha256>/                      # content-addressed, immutable, unpacked releases
    <sha256>.zip                   # original upload, kept for audit
  tenants/
    <tenant-id>/
      data.img                     # loopback ext4 image, mounted at data/  (quota)
      data/                        # mountpoint; bind-mounted to /pb/pb_data
      app/
        current -> <pb_root>/artifacts/<sha256>       # bind-mounted :ro
      instance.lock                # INV-3 singleton guard
      meta.json                    # last-known-good breadcrumb for disaster recovery
  backups/
    <tenant-id>/
      <kind>/<YYYYMMDD-HHMMSS>.img.zst   # kind: routine, pre_deploy, pre_upgrade, manual;
                                         # .tar for format=files, .gz when zstd is missing
  scratch/                         # rehearsal images and live-copy staging
  egress/                          # generated squid.conf, mounted as a directory (§9.4)
  caddy/admin/                     # the edge's admin socket (§10)
  logs/
    <tenant-id>/
    _egress/                       # the proxy's access log
```

**Bind mounts, not named volumes**, because backups (§11) and the deploy symlink swap need
plain host-side filesystem access.

**Quota is a per-tenant loopback ext4 image** (D4). The quota is enforced by construction,
it is one file to snapshot, and SQLite's locks stay on a local ext4. The image itself must
still sit on a local filesystem (INV-10); the control plane refuses to start when `pb_root`
is on NFS, SMB, FUSE or similar. Filesystem overhead means
images are sized 20 % above the nominal quota (a 100 MiB ext4 image measured 82 MiB usable),
so the tenant gets the space it was sold.

`meta.json` and the container labels (`v2p.managed`, `v2p.tenant`, `v2p.role`,
`v2p.data-device`, `v2p.rehearsal`) let the host be enumerated without the database. If
`state.db` is lost, an operator re-provisions tenants by hand from `meta.json`; nothing reads
it automatically yet (§16). **Grants are never reconstructed** from it or from any manifest
(INV-16). Every tenant comes back with no outbound path.

Deploy means unpacking the release into `artifacts/<sha>/`, repointing `app/current` and
recreating the container. Rollback repoints to the previous sha. Artifacts are
content-addressed, so a sha shared by many tenants is stored once.

---

## 8. Control plane

### 8.1 Data model

**Runtime versions** carry a PocketBase version, hardening rev, image digest and lifecycle
state (§12). A **tenant** pins one, and pins the digest, which only an upgrade job changes
(INV-11). Subnets and container addresses are explicit rather than runtime-assigned, because
firewall rules and proxy ACLs are written against them.

**Ownership is a history, not a column.** Ownership rows carry a role, who granted it and
when it was revoked, and the current owner is a view over them. INV-17 is enforced by a
uniqueness constraint in the database. The platform itself is a **principal**, so automated
actions have a real actor and orphaned tenants have somewhere to land.

**Releases** are content-addressed and immutable, and keep their manifest, including the
egress hosts they *asked for*. The **instance** row holds observation (container id,
observed state, running digest, health, last request), kept separate from intent so drift is
visible.

**Upgrade jobs** record the rehearsal outcome, the report shown to the tenant and the
pre-apply snapshot. **Backups** record kind, format, retention deadline and *which runtime
version wrote the data*, which the restore path checks.

**Grants** are the only input to enforcement (INV-16): tenant, kind, direction, subject,
tier, decision, decider, justification, evidence and expiry. The difference between the
release's request and the grants answers "why can't my app reach this host?".

**Audit events** are append-only and hash-chained (INV-18): sequence, actor, on-behalf-of
principal, action, subject reference (never a payload) and previous hash. The database
itself rejects updates and deletes, and nothing cascades into the table. **Anchors** hold
signed chain heads; **attestations** hold the signed host-derived reports of §14.5.

### 8.2 Driver interface

One interface, one Docker implementation. An instance spec holds: image digest (never a tag),
the read-only app mount and writable data mount, network and static address, an optional
egress attachment, resource caps, runtime, and a platform-built environment: the encryption
key, `GOMEMLIMIT` and the proxy variables, nothing tenant-supplied. Operations: ensure
(converge), stop, destroy, status, logs, stats, rehearse and snapshot.

**There is no exec method** (INV-9). `Snapshot` runs the platform's `pbsnap` inside the
instance's sandbox for a live backup copy (INV-20, §11), with a database name as its only
argument; there is no shell to exec into. One-shot CLI containers (the owner seat, pre-0.23
`migrate up`) carry the instance's memory and pids ceilings, are labelled, are removed even
when their caller gives up, and any found at start-up is swept (INV-3).
Most container settings are immutable after create, so converging means comparing the
container against the spec and recreating it on any difference.

Rehearse boots a throwaway container on the target image against a *copy* of the tenant's
data, on an isolated network with no egress (§12). It **refuses** a spec with an egress
attachment or proxy environment rather than stripping them.

### 8.3 Reconciler

Runs every 5 seconds. For each tenant:

```
desired running,  no network         -> create network + firewall rules (§9) FIRST
desired running,  no container       -> create + start
desired running,  container stopped  -> start
desired running,  container unhealthy-> restart with backoff; after N failures mark failed
desired stopped,  container running  -> stop
desired deleted                      -> destroy container, destroy network,
                                        remove firewall rules, retain data per policy
image_digest != last-ran digest      -> DO NOT ACT. Raise a drift alert. (INV-11)
                                        "last ran" is the existing container's image,
                                        running or stopped, else instance.running_digest
container has posture it never may   -> recreate, raise SECURITY drift (INV-12, INV-15)
grant expired or revoked             -> regenerate rules and proxy ACLs without it, this tick
rule tagged with an unknown grant    -> DO NOT REPAIR, DO NOT DELETE. Alert. (INV-19, §14.5)
```

Rules:

- **Network and firewall rules exist before the container starts.** Starting first opens an
  egress window.
- **Firewall rules are re-asserted every tick**, idempotently. Daemon restarts, network
  prunes and firewall reloads can drop them, and a missing rule is logged as drift.
- **The final snapshot on delete is taken by the delete endpoint**, before it marks the
  tenant deleted (kind `manual`, skipped with `--no-backup`). A failed snapshot aborts the
  delete, which it could not do once the tick owns the teardown.
- **Grant expiry is enforced here and nowhere else.** There is no cleanup cron: an expired
  grant simply stops being an input.
- **Restart backoff** is 1s, 5s, 30s and 2m, then `failed`. No restart storms.
- **Docker resolves a bind source at create time.** The driver records the data device in a
  `v2p.data-device` label and recreates on mismatch, because a container started before its
  loopback mount serves an empty `pb_data`. For the same reason, a deploy recreates the
  container rather than converging (§8.5).
- **Convergence compares the resolved image ID**, not just the reference, so a tag rebuilt in
  place still rolls.
- **Teardown is idempotent**, and "already done" has several spellings. For example,
  `NetworkDisconnect` returning `is not connected` counts as success.
- **Reboot recovery order:** mounts → rules → containers → edge re-attachment.

### 8.4 API surface

Three audiences. The API has two subrouters, operator (`/api/v1/admin/…`) and tenant
(`/api/v1/tenants/…`); the unauthenticated audience gets only the portal's login.

**Tenant-facing** (portal session or API token): upload, release history and download,
deploy, rollback, logs, start, stop, restart, backups and restores, upgrade requests and jobs, the effective egress
allowlist with recent denials. From §14 as well: owner and ownership history, transfer
offer/accept, the tenant's grants (active, pending, expired, denied with reasons), grant
request and revoke, the latest attestation, and every platform access to its data.

**Operator-only**: provision and delete tenants, resize (memory only, applied by recreating
the container), principals and API tokens, the fleet view, runtime versions and their
lifecycle, the upgrade queue, quarantine, Tier-2 approve/deny (the denial reason is shown to
the tenant verbatim), break-glass, on-demand attestation, and audit query/export/verify.

**Unauthenticated**: nothing beyond login.

**Admin handoff.** The owner or an `admin` opens `/_/` from the portal, with nothing
but their portal session. The portal reads the owner seat's token key and the collection's
token secret from `pb_data` on the host and signs a short-lived superuser token. It audits
`tenant.instance_admin.opened` (no token in the row) and redirects to
`<slug>.apps…/_citadel/admin#<payload>`. The edge's bridge page puts the token where the
admin UI looks for its session, and the UI refreshes it into an ordinary one. The owner
seat (`admin-<id>@example.invalid`) is created by the pre-boot one-shot with a password
that is thrown away. If the owner deletes it, the next deploy re-creates it (0.23+). This
is a filesystem read, never a call to the instance's API (INV-5). The data-plane health
check mints its token the same way, but signs for *any* superuser, so nothing the owner does
to the seat can make a healthy instance look broken; it then makes one read-only
`auth-refresh` call, which is verification, not management (INV-5).

**Operator in the portal.** The platform principal opens a tenant's pages only while it holds a
real role on it (orphan custody, §14.1). It has no standing view of tenant pages, logs or
releases, which §14 routes through break-glass. Its operator pages are read-only apart from
on-demand attestation. Tier-2 decisions, break-glass and its review need a named person
(INV-16), and a shared platform login names nobody, so they live only on the socket.

Tenant auth is **separate from any tenant's PocketBase** (INV-5). Portal logins are throttled
per principal and per source address, and signing out or changing a password bumps the
principal's session epoch, which invalidates every existing cookie.

The control-plane API listens on a `0600` unix socket. A bearer-token-only copy is mounted at
`/api/` on the portal listener, which defaults to `127.0.0.1:8080` and refuses a non-loopback
address unless `portal_allow_public` is set. Neither is reachable from a tenant bridge (§9.3).

### 8.5 Deploy state machine

```
uploaded
  └─ validate (§6) ──fail──▶ rejected (specific error to user)
       │ ok
       ▼
  check manifest range vs tenant.runtime_version ──fail──▶ rejected
  classify egress requests (§14.3)
       ├─ any Tier 0 ──────────────────────────────fail──▶ rejected
       ├─ Tier 1 ──▶ auto-granted, grant row written, decided_by = platform
       └─ Tier 2 ──▶ grant row pending; deploy CONTINUES, host stays unreachable
       │ ok
       ▼
  unpack to artifacts/<sha>/                  [idempotent, content-addressed]
       ▼
  acquire instance.lock                                                  (INV-3)
       ▼
  write the grant rows classified above
       ▼
  stop ──▶ backup pb_data  (kind=pre_deploy)
       ▼
  regenerate ACLs from active grants (§9.4, INV-16)
       ──▶ repoint app/current ──▶ recreate + start
       ▼
  wait for healthcheck (timeout 60s)
       ├─ pass ──▶ replay manifest smoke requests
       │              ├─ pass ──▶ deployed; history updated; release lock
       │              └─ fail ─┐
       └─ fail ───────────────┴──▶ ROLLBACK:
                                     stop, repoint current to previous sha,
                                     restore pre_deploy backup,
                                     recreate + start, verify, release lock,
                                     surface logs to the tenant
```

- A rollback does not touch egress. Enforcement follows active grants, not the current
  release, so a grant the failed release auto-approved stays in effect. Grants end by expiry,
  by the tenant or by an operator only.
- Expect **1–3 seconds of downtime**. SQLite is single-writer, so there is no zero-downtime
  swap.
- Tenant migrations run at startup, and a migration can commit data before a later one
  throws. That is why rollback restores the data as well as the artifact.

---

## 9. Network model and egress control

> The highest-risk section. Under a shared kernel the network is where a compromised tenant
> does the most damage. Pair every rule with a probe that fails if the rule is absent.

### 9.1 Four escape routes

| # | Route | Consequence |
|---|-------|-------------|
| 1 | **The internet** | exfiltration, spam relay, SSRF, C2 |
| 2 | **The host itself** | control-plane API, SSH, anything bound on the bridge gateway IP |
| 3 | **Other tenants** | read or corrupt another customer's database |
| 4 | **Cloud metadata** | `169.254.169.254` → instance credentials → everything |

Route 2 is the one that gets missed (§9.3).

### 9.2 Default posture: per-tenant internal network, no published ports

Each tenant gets one bridge network, created **before** the container and marked
`internal: true` (no outbound routing, INV-7). It has an explicit subnet and a predictable
bridge name, `br-t-<slug>`.

Ingress works because **the edge proxy joins the tenant's network** and reaches
`pb-<slug>:8090` there. No `-p` flags and no DNAT (INV-12). This closes routes 1 and 4
declaratively. Route 3 needs one more step: the edge listens on its address on every tenant
bridge and routes by `Host`, so a tenant that can open a connection *to* the edge reaches every
other tenant. **Every tenant route refuses client addresses in the tenant and egress pools**, so
such a request falls through to the catch-all 404. That is the boundary on hosts where
same-bridge traffic never reaches iptables: Docker 29 does not load `br_netfilter`, and neither
the per-tenant accept nor any other `DOCKER-USER` rule sees it there. Where `br_netfilter` is
loaded, the per-tenant accept also admits only the edge dialling the tenant (§9.5, rule 2).
Routes published by an earlier release are re-rendered once when the control plane starts.
`test/netprobe/15-edge-hairpin.sh` asserts whichever layer the host has. The embedded resolver on an internal network does not forward external names,
so there is no DNS covert channel either. That behaviour belongs to the engine, so
`test/netprobe/03-dns-covert.sh` re-checks it on every engine upgrade.

A container on an internal network **can still reach the host's own IP on its bridge**,
which is why the `INPUT` rules in §9.3 are load-bearing (`test/netprobe/02-host-reachability.sh`).

The edge joins every tenant network (D1).

### 9.3 The `DOCKER-USER` trap (INV-13)

`DOCKER-USER` is jumped from `FORWARD`, so container-to-host traffic, which lands in `INPUT`,
never reaches it. Every tenant bridge therefore gets an `INPUT` drop by interface wildcard,
for IPv4 and IPv6 (`-I INPUT -i br-t-+ -j DROP`), re-asserted every tick.

**The drop cuts host→tenant too**: the SYN-ACK of a host-initiated connection arrives on
`br-t-+` and is dropped. The control plane cannot dial a tenant's bridge IP. Health checks
go through the edge or a probe container on the tenant's network (§12).
Container↔container traffic, including edge→tenant, goes through `FORWARD` and is unaffected.

A host service that must be reachable from a tenant bridge is a design smell. Route it
through the edge or egress proxy instead.

### 9.4 Tenants with egress grants

Netfilter cannot allowlist hostnames, and resolve-into-ipset is exploitable, so don't build
it. Instead, a forward proxy holds the domain allowlist and netfilter makes the proxy the
only reachable destination:

```
tenant container ──▶ egress-proxy:3128 ──▶ internet
       │
       └──▶ anything else: DROP
```

1. The tenant additionally joins a non-internal network containing only the proxy, at a
   static IP. The attachment is part of the **create spec**, never hot-plugged: under `runsc`,
   `docker network connect` reports success and does nothing. A first grant or last
   revocation therefore recreates the container.
2. Per-tenant `DOCKER-USER` rules: one accept from the tenant's address to the proxy port,
   tagged with the justifying grant id, above a drop for everything else from that tenant.
3. The proxy (Squid) maps **source IP → tenant → allowed domains**, generated from **active
   grants** only (INV-16). It filters TLS on the CONNECT target *and* the ClientHello SNI,
   with **no MITM** and no certificates injected into tenants.
4. Squid's `squid-internal-mgr/config` is restricted to the egress bridge gateway (the host).
   Attestation reads it to observe the allowlist **as loaded**, not as templated (§14.5).
   The manager ACL sits **first**, above `Safe_ports`. The deny for every other source sits
   above the per-tenant allows, because tenants share this network and the report names the
   whole fleet's allowlist. `test/netprobe/13-squid-mgr.sh` asserts both halves.
5. Denials are logged with tenant, destination and grant id, and surfaced at
   `GET /api/v1/tenants/:id/egress` with one of four reasons: *never requested*, *awaiting
   approval*, *denied — <reason>*, *expired on <date>*.

The proxy env vars make cooperative hooks work, but the DROP is the boundary (INV-14).
Tenants get no external DNS: they pass hostnames in CONNECT and the proxy resolves them.

A refused host gets a **TCP reset**, not a 403, because a page inside TLS would require a
certificate. A tenant with no grants sees `network is unreachable`, because it is not on the
egress network at all.

**Squid constraints** (each fails in a way that looks like something else):

- Mount the config **directory**, not the file. Atomic rewrites create a new inode that a file
  bind mount never sees.
- SNI filtering needs an `ssl-bump` port. Without one, `ssl_bump` rules are silently inert,
  and the port requires `tls-cert=` and a working `sslcrtd_program` even when nothing is
  bumped. The proxy generates a never-presented self-signed cert when it starts, and
  `test/netprobe/10-sni-mismatch.sh` proves no bumping happens.
- `ssl_bump terminate` must be qualified with `step2`. At step 1 the SNI is unknown, so it
  kills every connection.
- `deny_info TCP_RESET all`. Otherwise denials are answered by bumping. And it only covers
  a refusal that falls through to the final `http_access deny all`: a CONNECT refused by any
  other deny line is bumped to deliver an error page under a generated certificate, and a
  per-ACL `deny_info` does not prevent it (verified on the development VM). So the port rules
  and the destination deny are conditions on each tenant's allow line, never deny lines of
  their own.
- Squid must be built with OpenSSL. `images/egress-proxy` uses Alpine's package and fails the
  build otherwise. The cert is `0440 root:squid`, and the platform chowns the log
  directory's contents, not just the directory.
- Without the custom proxy image, the control plane falls back to CONNECT-only filtering and
  logs it loudly. `egress_sni_enforce: false` makes that downgrade a recorded choice.

### 9.5 Unconditional denies

Cloud metadata (IPv4 link-local, IPv6 metadata), RFC1918, CGNAT (`100.64.0.0/10`), loopback
and IPv6 unique-local/link-local space are dropped in `DOCKER-USER`, and are never
allowlistable (INV-7). On `INPUT` the `br-t-+` drop (§9.3) already covers every tenant source. The egress proxy refuses the same destinations, plus the host's
own addresses, for any name that resolves to them (`dstdomain -n`, `dst` deny). Otherwise a
granted name the tenant controls could point Squid at them. The egress bridge has its own
`INPUT` drop for everything except the proxy. Docker bridges live inside
these ranges, so accepts must sit above the denies. The `DOCKER-USER` shape, top to bottom:

```
1. -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
1a. -p tcp ! -i br-t-+ ! -s <egress_subnet> -m conntrack --ctstate DNAT
      --ctorigdstport <edge_port> -j ACCEPT                     # platform ingress
2. -i br-t-<slug> -o br-t-<slug> -s <edge_ip> -d <tenant_ip>
      -p tcp --dport 8090 -m conntrack --ctstate NEW -j ACCEPT   # per tenant, tagged
3. -s <tenant_ip> -d <proxy_ip> -p tcp --dport 3128 -j ACCEPT   # per grant, tagged
4. -s <tenant_ip> -j DROP                                       # per tenant with a grant, tagged
5. -i <egress_bridge> ! -o <egress_bridge> ! -s <proxy_ip> -j DROP
6. the unconditional denies above
```

- **Rule 1**: `DOCKER-USER` runs before Docker's own established accept, so without it the
  proxy→tenant reply is dropped.
- **Rule 1a**: ingress to the edge's published port, the only one reachable off the host
  (INV-12); the development registry publishes on loopback only.
  Tenant bridges and the egress subnet are excluded, so a tenant cannot hair-pin to the edge
  through the host's address.
- **Rule 2**: where `br_netfilter` is loaded, the edge→tenant SYN is `NEW`, crosses `FORWARD`,
  and its destination falls inside a denied range. Docker 29 does not load it, and then the
  rule is inert. Without rule 2 every request through the edge
  times out with a 502. It is scoped by interface on **both** sides: a wildcard
  `-i br-t-+ -o br-t-+` would permit tenant→tenant (route 3). It is also scoped by
  **direction**. An accept in both directions let a tenant connect to the edge and name
  another tenant's `Host`.
- **Rule 5**: the egress network is the one non-internal network, so Docker routes and
  masquerades it. Rule 4 covers only addresses the control plane allocated, so without
  rule 5 any other address on the bridge reaches the internet directly, bypassing the proxy
  (found by `test/netprobe/08` and `11`). It matches on the outbound interface, so
  tenant→proxy traffic is unaffected. A missing deny is reinserted above the first platform
  deny, never at the top of the chain, where it would precede rule 1.
- Rule **order** is asserted programmatically (`test/netprobe/05-rule-ordering.sh`), not just
  presence.

### 9.6 Rule lifecycle

- Written at provisioning, before first container start.
- Re-asserted idempotently every tick (§8.3).
- Rewritten whenever the **active grant set** changes (deploy, approval, revocation, expiry),
  before the container restarts.
- Removed with the tenant and its network.
- Every tenant rule's `--comment` carries the tenant ID, and every grant-backed accept
  carries **the grant ID** too, so it can be traced, diffed and garbage-collected. The edge
  accept is tagged `intra-network=edge`; platform rules are tagged `platform …`. Attestation reads this tag (§14.5). A tagged rule with no
  matching grant is an incident, not drift.

---

## 10. Edge proxy

Caddy, configured dynamically through its admin API and attached to every tenant network.
The route table is derived from the tenant and instance tables:
`<slug>.apps.example.com` → `pb-<slug>:8090` (INV-8, INV-12).

- **No response buffering**, for `/api/realtime` (SSE): `flush_interval -1` is set on the
  whole tenant route.
- **Per-tenant request body cap**, 32 MiB by default.
- **Per-tenant rate limits**, separately for `/api/` and `/_/`. This needs the custom
  `edge-caddy` image.
- **`/_citadel/admin` is reserved on every tenant hostname.** The edge answers it itself
  with the admin handoff page (§8.4) and never proxies it, so a tenant cannot serve a page
  there to collect tokens. The page sends no request: its payload is in the URL fragment,
  its CSP allows only its own script, and it writes only the admin UI's session key.
- **The admin API is a unix socket, not a port**: `admin unix//run/caddy-admin/admin.sock`,
  bind-mounted from `<pb_root>/caddy/admin/`. No listener exists for a tenant to reach, and
  the control plane drives it over the socket without exec. Under userns-remap the directory
  must be chowned to the remapped root uid. Asserted by `test/netprobe/07-controlplane.sh`.
- **Quarantine** makes the proxy return 503 for a tenant without touching its data. The reason
  is mandatory and shown to the tenant in the portal; the 503 itself carries none. It stops ingress only: background hooks keep running,
  so stop the instance too if the tenant's own code is the problem.

TLS is a wildcard certificate for `*.apps.example.com`. Custom domains (§16) need on-demand
TLS gated by an ask endpoint, plus a Tier-2 `custom_domain` grant with proof of control.

---

## 11. Backups

**Never use PocketBase's own backup endpoint.** It needs superuser credentials inside the
instance (INV-1, INV-5). Back up from the host.

| Format | Taken | Artifact | Used by |
|---|---|---|---|
| `image` | container stopped, image unmounted | compressed copy of `data.img` | `pre_deploy`, `pre_upgrade`, final snapshot on destroy |
| `files` | container still serving | tar of a `VACUUM INTO` of each database, from a private copy streamed out of the sandbox | `routine`, and the rehearsal copy (§12) |

`backup.format` is an explicit column. Never `cp` a live WAL database, and never open one from
the host (INV-20). The only live path is `pbsnap`, shipped in `pb-hardened` from h2 and run with
`docker exec` inside the instance's sandbox. Under one read transaction it streams every page
through `sqlite_dbpage` to stdout, so it needs no room in the tenant's quota image. The host
writes the stream to a private file, bounded by the image size, runs `integrity_check` on it and
then `VACUUM INTO`s it, so the artifact is unchanged. An image without `pbsnap` (h1) is stopped
for the copy and started again; that is logged and audited
(`backup.live_copy.stopped_instance`). Non-database files are copied as plain files, and
symlinks are refused rather than followed, because `pb_data` is tenant-writable. Everything
copied out of `pb_data` is charged against the size of the tenant's image, and a copy that
would exceed it is refused the same way. The image bounds the blocks a tenant writes, not
the size a file claims: one `truncate` in a hook makes a sparse terabyte that occupies
nothing inside the quota, and a plain copy writes every hole out as zeroes onto the host's
own disk, which the staging directory shares with every other tenant.

| Kind | When | Retention |
|---|---|---|
| `routine` | nightly | 7 days |
| `pre_deploy` | every deploy | 48 hours |
| `pre_upgrade` | every runtime upgrade | **30 days** (INV-4: the only rollback path) |
| `manual` | tenant-triggered, and on destroy | 30 days |

A sweep on the reconcile tick enforces retention; there is no separate cron. Two snapshots
always survive: a tenant's newest one, and any snapshot an in-flight upgrade job names.
Deletion removes the row first, then the file.

Every archive's sha256 is recorded at creation and checked before a restore.

**Restore refuses a snapshot written by a different `pb_version`** (INV-4). The operator-only
`--force` exists for snapshots whose recorded version is wrong; a forced restore across
versions leaves the instance stopped for an operator to `pin-runtime` before starting it.

Backups are tenant data outside the sandbox, so they are inside the audit model. Create,
restore and delete are audited. Downloading or replicating a snapshot will require a
`backup_export` grant once that path exists (§16). An operator reading `pb_data` or a
snapshot on the host does so under an `operator_data_access` break-glass grant (§14.3); root
can read it regardless, so the control is detection, not prevention (D15). The automated routine path runs as the platform principal and
is exempt, though each run is still audited.

---

## 12. Versioning and upgrades

### Why per-instance versioning

PocketBase's JSVM API changes substantially across releases, for example `daos`/`models`/
`schema` versus `core`/`router`, with renamed hooks. The platform cannot fix tenant code, so
each tenant stays on the version its hooks were written for and upgrades deliberately.

### Upgrade state machine

```
pending
  └─ compatibility gate: target version within release.pb_min..pb_max?
        no  ──▶ blocked (tell the tenant exactly which hooks/APIs are at risk)
        yes
        ▼
rehearsing            live-copy pb_data into a fresh scratch image (§11); boot a throwaway
  │                   container on the TARGET image against the copy, attached to an
  │                   isolated rehearsal network with NO egress and only a probe
  │                   container on it; run healthcheck + manifest smoke requests;
  │                   capture hook-registration errors; destroy container, network, copy
  ├─ failed ──▶ report to tenant with logs; job ends; nothing touched
  ├─ passed, --rehearse-only ──▶ rehearsed; job ends
  │ passed
  ▼
snapshotting          backup kind=pre_upgrade, retain 30 days, record snapshot_id
  ▼
applying              stop container; update image_digest; recreate + start
  ▼                   (PocketBase runs its system migrations here — irreversible)
verifying             healthcheck + smoke requests against the REAL instance
  ├─ pass ──▶ succeeded; move tenant runtime_version + image_digest; keep snapshot 30 days
  └─ fail ──▶ rolling_back: stop, restore pre_upgrade snapshot, revert image_digest,
              recreate + start, verify, alert operator
```

Verification needs all three checks:

- **The healthcheck alone is not enough.** A mismatched binary can pass it with a broken data
  plane (INV-4).
- **The smoke set alone is not enough.** PocketBase catches a hook that throws at
  registration and keeps serving, running none of the tenant's code.
- **So both rehearsal and verification also fail on hook-registration errors** in the
  instance log.

**Rehearsal isolation rules:**

- No egress at all, regardless of grants: hooks may send mail or charge cards.
- An `internal: true` network with one `DOCKER-USER` rule: new connections from the probe
  to the rehearsal instance's PocketBase port, nothing else, so the hooks under rehearsal
  cannot open connections to the probe. It is tagged `rehearsal=<job>` with **no** `tenant=`
  field, so attestation never mistakes it for tenant enforcement. The probe is platform code
  on `runc`, with the same memory and pids ceilings as anything else handling hostile input.
- Bridge `br-t-rh########` deliberately matches the `br-t-+` `INPUT` drop, because the
  rehearsal runs hostile hooks (INV-13). The control plane therefore cannot dial it, and the
  health and smoke requests come from a probe container on the same network.
- The data copy is a real ext4 image of the tenant's size, mounted `nosuid,nodev,noexec`
  like the live one.
- Teardown runs on every path in reverse order, attempting each step even after a failure:
  probe, container, rules, network, unmount, scratch. Residue is reported, never
  force-removed. A reaper on the tick cleans up after terminal or unknown jobs.

### Never move both axes at once

| | App deploy | Runtime upgrade |
|---|---|---|
| Changes | `pb_hooks`, `pb_migrations`, `pb_public` | the PocketBase binary |
| Touches `pb_data` | only via tenant migrations | via system migrations, **irreversibly** |
| Rollback | repoint symlink to previous sha | **restore snapshot** |
| Trigger | tenant, freely | tenant, gated; or platform at EOL |
| Downtime | 1–3s | seconds to a minute on large databases |

A deploy is rejected while an upgrade job is active for the tenant, and vice versa (INV-6).

### Version lifecycle

| State | Meaning |
|---|---|
| `current` | default for newly provisioned tenants |
| `supported` | patch updates auto-applied; minors offered in the portal |
| `deprecated` | still runs; portal nags; no new tenants; EOL date **required** on entry |
| `eol` | platform force-upgrades past `eol_at + eol_grace`, batched |

The platform nags once per `eol_nag_interval`. Forced upgrades go through the same
`StartUpgrade`, so they cannot skip the snapshot, rehearsal or verification. **A forced
upgrade whose rehearsal fails quarantines the tenant instead of applying**, and the tenant
and an operator are notified with the failures verbatim.

Keep roughly the last three or four minor lines. Hardening-rev bumps sit outside this
lifecycle: after a red-team re-run the registry row moves to the new rev (it never moves
back), and each tenant reaches it as a same-version upgrade — `citadel tenant upgrade <slug>
--to <its version>` — with the full rehearsal, snapshot and verification ladder.

### Security fixes in PocketBase itself (D11)

**Quarantine first; force-upgrade only for a vulnerability that is being actively exploited.**

| | Quarantine | Force-upgrade |
|---|---|---|
| Reversible | yes, instantly | no — snapshot restore only (INV-4) |
| Tenant impact | unreachable | unreachable, then possibly broken |
| Stops an exploit via HTTP ingress | yes | yes |
| Stops an exploit via a background hook | **no** — stop the instance too | yes |
| Right when | the fix is not ready, or the hooks will break | the vulnerability is exploited now |

Operator-only overrides:

- `--no-rehearse`: only when the rehearsal itself is broken.
- `--force`: marks the job forced, as the EOL path does. It overrides the release's
  `pocketbase.min/max` and the target version's lifecycle gate, and a failed rehearsal
  quarantines the tenant rather than only ending the job.

If an upgrade *succeeded* but the instance is wrong, the way back is: quarantine and stop
the tenant, `citadel tenant pin-runtime <slug> --to <old version> --justification …`, restore
the `pre_upgrade` snapshot (the versions now match, so no `--force`), then start it.
`pin-runtime` is operator-only, audited and announced to the tenant, refuses a tenant that is
meant to be running, and never starts one.

If the automatic rollback *itself* fails, or the control plane restarts mid-apply, the tenant
is set desired-stopped and quarantined: its version row and its `pb_data` may now disagree,
and only an operator can tell which binary last migrated it.

---

## 13. Security model

### 13.1 Container hardening

The full flag set is in §4. In short:

- a `FROM scratch` image;
- non-root, with userns-remap;
- a read-only rootfs, with only `pb_data` and a `noexec` tmpfs writable;
- `/pb/app` mounted read-only, so a hook cannot rewrite its own release;
- `--cap-drop=ALL` and `no-new-privileges`;
- explicit seccomp and AppArmor profiles;
- `runsc`;
- pids, memory (no swap) and CPU limits;
- reconciler-owned restarts;
- a capped runtime log, because stdout is a write path onto the host outside the quota;
- a per-tenant encryption key;
- the loopback disk quota (the 90 % alert is not built yet, §16).

### 13.2 Network posture

The full design is in §9:

- a per-tenant internal network, created before the container;
- no published ports;
- the `br-t-+` `INPUT` drop;
- unconditional denies below the conntrack, intra-bridge and grant accepts;
- egress only via the proxy;
- no external DNS;
- the Caddy admin API on a unix socket;
- the control-plane API on loopback or a management interface;
- Docker ≥ 28 with the backend pinned.

### 13.3 Red-team suite (`test/redteam/` + `test/netprobe/`)

Adversarial tenant packages and network probes, run against real containers. **Every probe
must fail to reach its goal** while the platform stays healthy, and `make redteam` exits
non-zero otherwise. The suite covers:

- shell exec;
- metadata SSRF;
- open internet;
- allowed and denied egress;
- host and neighbour scans;
- DNS exfiltration;
- proxy bypass;
- the Docker socket;
- disk fill, fork bomb, memory hog and infinite hooks;
- writes to `/pb/app`;
- key theft;
- rule tampering;
- zip-bomb, traversal and Tier-0 egress packages;
- raw dials that ignore `HTTP_PROXY` (PocketBase's SMTP mailer dials the host itself), from
  both a tenant with no grant and one on the egress network: metadata, the internet, the
  host's addresses, the neighbour, DNS;
- the proxy as a pivot: granted names re-pointed at metadata, the host, the edge and other
  tenants, and granted hosts on non-web ports, each judged by the proxy's own access log
  (a refusal is `TCP_DENIED` with no upstream hop), because from inside the hook a cut TLS
  session and a dialled destination look the same;
- dropped binaries in `pb_data` and `/tmp`, unexpected mounts, rootfs writes;
- the container posture itself (runtime, capabilities, limits, binds, mount flags, log cap);
- log floods, sparse-file backup bombs, crash loops against the restart ladder, and the CPU cap;
- `symlink-swap`: tenant code re-pointing `pb_data` while a live backup reads it;
- `tier2-kinds`: Tier-2 kinds land pending, and no kind but `egress_host` opens egress;
- the accountability probes: `grant-forge` (INV-16), `grant-revive` (§14.7),
  `expired-grant`, `unbacked-rule` and `unbacked-acl` (INV-19), `audit-tamper` (INV-18), `breakglass-silent`
  and `orphan-owner` (INV-17).

Every probe carries a positive control: a probe that could not have seen an escape (a route
that 404'd, a hook that threw first, a target unreachable for an unrelated reason) fails
rather than reading as contained. The audit-tamper cases (an edit in place, a wholesale
rewrite, a truncation) tamper with the shared state database, so they run last against a
snapshot that is restored afterwards.

It gates every hardening rev. Re-run it after any Docker upgrade or firewall-backend change.

### 13.4 Tenant-facing policy limits

Tenant-configurable SMTP and S3 settings would turn the platform into a spam relay and an
exfiltration channel, and the egress proxy covers only HTTP(S). Whatever D5 decides, both are
Tier-2 grant kinds (`smtp_relay`, `object_storage`).

---

## 14. Ownership, grants and audit

> §9 and §13 cover what a tenant **cannot** reach. This section covers what it **can**: who
> decided that, when it expires, and who at the platform has looked at the tenant's data.

For any instance, at any point in time including the past, the platform must answer:

1. **Who owns it?** Who transferred it, and who accepted?
2. **What can it reach outside its sandbox?** Who authorised each item, on what evidence,
   and when does it lapse?
3. **Who at the platform has read its data?** When, for how long, and why?

**Audit is not observability.** §15 is operational telemetry: rotated, and trusted because
nobody has a motive to forge it. §14 is the accountability record: written once, kept beyond
the tenant's data, and designed assuming someone wants it changed. Keep the two pipelines
separate.

### 14.1 Principals and ownership

A **principal** is a person, a service account (CI tokens) or the platform itself.
Ownership is a history (§8.1), so "who owned this in March" is a query.

| Role | Deploy | Request grants | Download a backup | Transfer ownership | Open `/_/` as superuser |
|---|---|---|---|---|---|
| `owner` | yes | yes | yes | yes | yes |
| `admin` | yes | yes | yes | no | yes |
| `deployer` | yes | yes (Tier 2 still needs an approver) | no | no | no |
| `viewer` | no | no | no | no | no |

- Exactly one `owner` per tenant (INV-17); other roles are unbounded.
- **Transfer is two-party**: the owner offers, the target accepts, both are recorded, and
  unaccepted offers expire.
- **Operator-forced transfer** (for a departed owner) requires a reason and appears in the
  tenant's feed.
- **Orphan reclamation**: when a principal is suspended (principals are suspended, not
  deleted), its tenants are
  transferred, or the platform principal takes custody and the tenant is flagged
  `owner_orphaned` in the fleet view. Open transfer offers to or from it are cancelled.
- A tenant is only ever provisioned to, or transferred to, an **active** principal.

### 14.2 The grant model

A **grant** authorises one capability crossing the sandbox boundary, in either direction.

**Outbound: what the tenant's code may reach**

| Kind | Subject | Notes |
|---|---|---|
| `egress_host` | an FQDN | the §9.4 proxy allowlist entry |
| `smtp_relay` | relay + from-addresses | outside the HTTP proxy's coverage (§13.4) |
| `object_storage` | bucket + prefix | platform-provisioned, scoped credentials |
| `custom_domain` | a hostname | needs proof of control (§10) |
| `oauth_provider` | an external IdP | the login flow needs egress to it |

**Inbound: what the outside may reach of the tenant's data**

| Kind | Subject | Notes |
|---|---|---|
| `operator_data_access` | `pb_data` or a snapshot | host-side read by a named operator |
| `backup_export` | a snapshot destination | data leaving the platform's control |
| `log_access` | collected host-side logs | beyond the tenant's own portal view |
| `support_impersonation` | a portal session | an operator acting *as* the tenant |

**Every grant expires.** Expiry is the mechanism, not hygiene:

| Kind | Default TTL |
|---|---|
| `egress_host`, `oauth_provider` | 365 days; a deploy re-requests one that has lapsed |
| `smtp_relay`, `object_storage`, `custom_domain` | 180 days, re-affirmed by the owner |
| `log_access`, `backup_export` | 7 days |
| `operator_data_access`, `support_impersonation` | 60 minutes, hard |

The reconciler enforces expiry on its normal tick (§8.3): an expired grant stops being an
input, so it never needs removing.

### 14.3 Tiered approval

Classification is a pure function of `(kind, subject, tenant history, policy version)`, and
every decision records the policy version.

- **Tier 0: never grantable.** Metadata, RFC1918, platform domains and infrastructure, and
  other tenants' hostnames. Rejects the release.
- **Tier 1: auto-granted, recorded.** A concrete FQDN `egress_host` that passes validation.
  The row is still written, with `decided_by` set to the platform principal. A name is not
  resolved at classification time: what it resolves to then says nothing about what it
  resolves to after a rebind. The proxy refuses denied ranges on every connection instead
  (§9.5), so `169.254.169.254.nip.io` can be granted and still reach nothing. The
  portal's Approvals page lists recent Tier-1 grants under the Tier-2 queue, so what
  the platform granted on its own is visible in one place.
- **Tier 2: named human approver.** The decision is made by a `person` principal — never
  the platform or a service account — and may shorten a grant's §14.2 expiry, never extend
  it. Wildcard hosts, `smtp_relay`, `object_storage`,
  `custom_domain`, `oauth_provider`, `log_access` and `backup_export`. Approval records approver, justification and
  expiry. An approved `*.example.com` reaches the proxy as `.example.com`, Squid's form for
  the domain and everything under it, so it also admits the apex. A host that a granted
  wildcard already covers is not listed again, because Squid drops one of two overlapping
  entries. The attestation counts a host covered by a wildcard as in effect.

> **A deploy never blocks on a Tier-2 grant.** The Tier-1 subset is enforced, Tier-2
> requests are `pending`, and calls to those hosts fail with "awaiting approval", visible in
> the portal and at `GET /egress`.

- **Tier 3: break-glass.** `operator_data_access` and `support_impersonation`, always.
  An operator needs a tenant's data now. A root operator can read
  the bind mount regardless (D15), so the design makes access loud rather than impossible:
  - self-approved, hard time-boxed (60 minutes by default, not extendable);
  - a mandatory reason, shown to the tenant verbatim;
  - **the tenant and a second operator are notified at grant time**;
  - reviewed within 24 hours by someone else, with the review recorded;
  - opened only through the break-glass endpoint: a Tier-3 kind is refused as an ordinary
    grant request, and a Tier-3 row is never approved through the ordinary decision path;
  - a break-glass left unreviewed past its 24-hour window blocks further break-glass by the
    same principal.

### 14.4 The audit event log

A hash chain: each row commits to the previous one, so an edit or deletion breaks
verification from that point on.

```
v2: hash = H("citadel-audit-v2\0" ‖ sequence ‖ time ‖ id ‖ actor ‖ actor kind ‖ on behalf of ‖
             tenant ‖ action ‖ subject ref ‖ detail ‖ request id ‖ source ip ‖ previous hash)
v1: hash = H(sequence ‖ time ‖ actor ‖ action ‖ subject ref ‖ detail ‖ previous hash)
```

The sequence is a fixed 8-byte big-endian integer; every other field is length-prefixed. v1 left `tenant_id` and `on_behalf_of` outside the hash, so a
platform read could be moved out of a tenant's access log (§14.6), or an impersonation erased,
without breaking the chain. Rows carry `hash_version`. Rows written before migration 006 stay
v1 and still verify, but a v1 row after the first v2 row fails verification as a downgrade.

- **Exactly one component writes audit rows**, in the **same transaction** as the state change.
- **One global chain**. Tenant exports ship the surrounding segment and the signed head (D14).
- **Anchoring**: hourly, the control plane signs `(seq, head_hash)` and writes it out.
  `citadel audit verify` recomputes the chain against the anchors, both the `audit_anchor`
  rows and the files under `audit/anchors/`, so a rewritten table contradicts an anchor it
  cannot reach. An anchor file with no row is a failure, because rows are append-only
  (triggers, like `audit_event`'s) and are written after their file. An anchor with no
  public key to check it against is a failure too. Anchors currently live on the same host (§16), so
  this protects only against tampering that does not also rewrite the anchors. With the
  signing key on the host, root can sign going forward; replicated anchors are what fix
  history.
- **`audit-signing.key` is never rotated.** Every anchor and attestation verifies against it.
- A fresh control plane's first anchor is seq 0 with the genesis hash, and verification seeds
  genesis explicitly.

**What is audited:**

- tenant lifecycle;
- ownership and transfers;
- grants (request, decide, expire, revoke);
- deploys and rollbacks;
- upgrades;
- backup create, restore, download and delete;
- host-side reads of `pb_data`;
- log access;
- impersonation;
- quarantine;
- netpolicy writes and drift repairs;
- control-plane authentication;
- audit configuration changes.

**Subject refs, never payloads.** Audit rows outlive tenant data (INV-18), so a payload in
the detail would make deletion requests impossible to honour (D10).

### 14.5 Access attestation (INV-19)

The platform builds a tenant's effective external access **by inspecting the host**, then
diffs it against `access_grant`. It observes:

- the networks the container is attached to;
- every `DOCKER-USER` and `INPUT` rule carrying the tenant's tag (§9.6);
- the egress ACL **as loaded in the running proxy** (§9.4);
- bind mounts, published ports (must be none) and the running image digest.

SMTP relay and storage grants have nothing to observe yet (D5); the report lists them as
recorded but not enforced.

| Outcome | Meaning | Response |
|---|---|---|
| `match` | host and grants agree | sign and store the report |
| `grant_without_enforcement` | approved, not in effect | a functional bug: repair next tick, log, show the tenant |
| `enforcement_without_grant` | access with nothing behind it | **a security incident**: alert, freeze, quarantine-eligible, **never silently repaired** |

**Freeze** means the tenant's configuration stops moving while it is investigated: deploys,
upgrades, grant requests and grant decisions are refused until an operator runs `citadel
unfreeze <slug> --reason …`, which is audited. Enforcement keeps failing closed — expired
and revoked grants still lapse — and nothing that was found is removed.

Beyond the per-tenant diff, the platform also reports allowlist blocks in the running proxy
that belong to no tenant with an active egress grant (`egress.acl.unbacked`), and the
reference copy the `squid.conf` tamper check compares against survives a restart, so an
edit made while the control plane was down is reported like any other.

Auto-removing an extra rule would destroy the evidence. The proxy allowlist is the one
exception, because a proxy cannot be left admitting a host nobody granted: a hand-edited
`squid.conf` is regenerated from grants on the next tick, but the edited copy is first kept
under `audit/evidence/` and the regeneration is audited as `egress.acl.tampered`. An operator removes it by hand only
after recording the chain, the audit segment, the grant rows and the signed reports, and only
once its origin is understood. Otherwise it is a host-compromise investigation.

Example report:

```
Tenant  acme  ·  attested 2026-03-04T11:02:17Z  ·  outcome: match

Can reach outside its sandbox:
  api.stripe.com      grant g-4f21  approved by dana@  2026-01-12  expires 2027-01-12
  smtp relay (100/h)  grant g-51aa  approved by dana@  2026-02-01  expires 2026-08-01
  nothing else

Platform principals with standing access to its data:  none
Break-glass sessions, last 90 days:                    1 (g-6b03, 42 min, reviewed)
Backup exports, last 90 days:                          0
```

**Fleet attestation** shows operators every tenant with egress and who approved it, grants
expiring within 30 days, and the aggregate set of external destinations.

### 14.6 Tenant-facing transparency

Without asking, a tenant sees:

- its ownership history;
- its grants: active, pending, expired, and denied with the reason verbatim;
- **every platform access to its data**, notified at grant time.

Tenants get a **summarised** attestation and operators the full one (D17). The summary drops
bridge names, chain positions, subnets, bind mounts, the running digest and finding
locations, but keeps the findings themselves.

### 14.7 Restore, transfer and deletion

- **A restore never reinstates a revoked grant.** Grants are not in `pb_data`, but the
  restored release re-declares its hosts, which re-enter as fresh requests. A previously
  denied or revoked subject needs human approval regardless of tier.
- **A transfer does not silently carry grants.** The inherited set is recorded, and Tier-2
  grants must be re-affirmed by the new owner within 30 days or they expire.
- **Deletion** removes the tenant's grant and ownership rows, whose history survives in the
  audit log (every grant, transfer and owner change is an audit event), and retains the
  data until an operator purges it (D10). A final attestation is taken from the host as
  teardown starts.
  Audit events are retained (INV-18), and so is the final attestation, which
  deliberately has no foreign key to `tenant`.

---

## 15. Observability

Logs never leave through tenant-controlled channels. The host collects stdout/stderr via
the driver into `/srv/citadel/logs/<tenant>/`, rotates them and exposes them read-only in
the portal.

Per-tenant metrics: CPU, memory, disk vs quota, request rate and p95 latency (from the
proxy), health, uptime, last request, **egress denials**.

The **fleet view** (`GET /admin/fleet`, rendered at `/fleet`, operators only) leads with:

- tenants per runtime version, and who blocks the next EOL date;
- upgrade jobs that failed rehearsal, and upgrade rollbacks;
- instances `failed` or `unhealthy`;
- **backup age per tenant**;
- drift (digest mismatch, missing firewall rules);
- top egress denials;
- pending Tier-2 grants, oldest first, and grants expiring within 30 days;
- open or unreviewed break-glass sessions;
- attestation mismatches, `enforcement_without_grant` first;
- the audit chain head and anchor age;
- tenants flagged `owner_orphaned`.

**Alerts** are entries in the fleet view's drift list today, with no paging (§16): a digest
mismatch, a missing or misordered rule, a backup failure, an upgrade rollback or stuck job,
rehearsal residue, a missing route, and the security findings below, which are never
auto-remediated:

- `enforcement_without_grant` (an unbacked rule or egress entry).

An egress allowlist edited outside the control plane (`egress.acl.tampered`) is flagged too. It
is the one security finding that is remediated, because the proxy cannot keep admitting a
host nobody granted. The edited copy is kept as evidence first (§14.5).

---

## 16. What is next

Not yet built. Each item gets a goal, a task list and done-when criteria when it starts. The
acceptance suites under `test/acceptance/` must still pass before anything starts.

- **Snapshot download and offsite replication.** One question: a copy of tenant data leaving
  the host. `backup_export` grants exist but enforce nothing, and snapshots share a disk with
  the data they protect. Likewise `operator_data_access` is granted through break-glass, but
  no host-side read path checks it.
- **Alerting.** Paging for the drift list's security findings, disk above 90 % (and disk vs
  quota in the fleet view), an audit anchor stale beyond two intervals, and a periodic
  `citadel audit verify`.
- **Disaster recovery from `meta.json`.** It is written at provision, but
  rebuilding from it is a manual procedure.
- **Offsite audit anchors.** Anchors are signed but written to the host that writes the chain,
  so root can rewrite both together. They need replicating under credentials the host does
  not hold.
- **Scale to zero.** Idle detection from `instance.last_request_at` and a graceful idle-stop
  that takes a `routine` backup. Wake-on-request at the edge would hold the request, start the
  instance, serve a "starting" page past ~2s, and allow one start per tenant under concurrent
  wakes. Stopped tenants keep their network and rules.
- **Cloud deployment.** The same stack, unattended, on a single VM: systemd units with the
  boot order (mounts → rules → containers), firewall persistence, wildcard TLS, offsite
  backups with a tested restore, and offsite anchors. It is done when a full host rebuild from
  backups restores every tenant with netprobes passing and the chain verifying against
  pre-rebuild anchors.
- **Custom domains and multi-host.** On-demand TLS gated by an ask endpoint, plus a
  `custom_domain` grant. Multi-host is a different scheduling problem and splits the audit
  chain (D14a).

The `smtp_relay`, `object_storage`, `custom_domain` and `oauth_provider` grants are
requested, decided, expiring and attested, but nothing yet enforces them (D5). The
attestation says so explicitly.

---

## 17. Decisions

### Decided

| # | Decision |
|---|---|
| D1 | The edge proxy joins every tenant network (rather than sidecars or a shared ingress network). |
| D2 | Tenant containers run under gVisor (`runsc`); platform containers stay on `runc`. |
| D3 | `userns-remap` is on, enabled before first production use; data dirs are chowned to `base+10001`. |
| D4 | Quota is a loopback ext4 image per tenant, not XFS project quotas. |
| D6 | Control-plane identity is the control plane's own store (argon2id portal passwords, sha256-hashed API tokens, signed session cookies), not a dedicated PocketBase and never a tenant's (INV-5). |
| D7 | Tenants get their PocketBase admin UI at `/_/`, rate-limited separately from `/api/` (§10). The owner, or anyone holding `admin`, opens it from the portal with their portal login (§8.4): no PocketBase password is handed out or stored. |
| D9 | Resource defaults are 1 CPU / 256 MiB / 2 GiB, configurable (`default_cpus`, `default_mem_mib`, `default_disk_mib`) and overridable per tenant at create. |
| D10 | Deleting a tenant retains its data image, keys and a final snapshot until an operator explicitly purges (`--purge`). Audit events always outlive the data (INV-18). |
| D11 | Security fixes: quarantine first; force-upgrade only for actively exploited vulnerabilities (§12). |
| D12 | arm64 and amd64 are both supported: checksums are pinned for both, and images are built natively for the host's architecture (no multi-arch manifests). |
| D14 | One global audit chain (§14.4). Tenant-scoped export and verification are operator-only. |
| D15 | Break-glass is detect-and-attribute (§14.3, Tier 3), not technical prevention. |
| D16 | Principals use local accounts. `principal.external_id` is reserved so SSO/OIDC can replace the credential source without changing anything downstream. |
| D17 | Attestations are summarised for tenants and full for operators (§14.6). |

### Open

| # | Decision | Notes |
|---|---|---|
| D5 | Tenant SMTP / S3: disabled, or a platform relay with rate limits? | Leaning toward a relay. Either way both are Tier-2 grant kinds, already requested and attested but not enforced. |
| D8 | Supported version window | `versions.txt` is maintained by hand today; no rule fixes how many minor lines are kept. |
| D9a | Plan tiers | Only the platform-wide defaults exist. |
| D10a | Automatic purge of retained tenant data | Nothing expires retained data today. |
| D13 | Audit event retention period | Nothing deletes audit rows today. Any period must exceed D10. |
| D14a | Per-tenant chains or inclusion proofs | Needed for independently verifiable tenant exports, and once multi-host splits the chain. |

---

## 18. Glossary

| Term | Meaning |
|---|---|
| **Tenant** | One project. One container, one internal network, one `pb_data`, one pinned runtime version. |
| **Package** | The zip a tenant uploads: `pb_hooks` + `pb_migrations` + `pb_public` + `pbapp.json`. |
| **Release** | A validated, content-addressed, immutable unpacked package. Identified by sha256. |
| **Runtime version** | The PocketBase version a tenant's instance runs. Per-tenant. Changed only by upgrade jobs. |
| **Hardening rev** | The platform's image + profile generation. Fleet-wide, rolled after a red-team run. |
| **Instance** | The running container for a tenant. |
| **Internal network** | A Docker bridge with `internal: true`: intra-network traffic works, no outbound routing. The default tenant posture. |
| **Egress network** | The non-internal network joined only by tenants with egress grants, containing only the forward proxy. |
| **Rehearsal** | Booting a throwaway container on a copy of a tenant's data, on the target runtime, with no egress, to test an upgrade. |
| **Quarantine** | The edge returns 503 for a tenant; data untouched. The alternative to a forced upgrade. |
| **Drift** | Running digest ≠ desired digest, or a netpolicy rule missing from the host. An alert; for digests, never an automatic action (INV-11). |
| **Principal** | Anything that can act: a person, a service account, or the platform itself. |
| **Grant** | One authorisation for one capability crossing the sandbox boundary, with a decider, justification and expiry. The only input to enforcement (INV-16). |
| **Tier** | A grant's approval class: 0 never, 1 auto-granted and recorded, 2 named approver, 3 break-glass (§14.3). |
| **Attestation** | A signed report of a tenant's effective external access, derived from the host and diffed against grants (INV-19). |
| **Break-glass** | Time-boxed, self-approved operator access to tenant data during an incident; notified at grant time, reviewed within 24h. |
| **Anchor** | A signed copy of the audit chain head, to be replicated offsite. |
| **Audit event** | One append-only, hash-chained row recording who did what to which subject. Never contains payloads. |
