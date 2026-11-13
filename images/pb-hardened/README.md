# pb-hardened — the platform-owned PocketBase image

`pb-hardened:<pocketbase-version>-h<hardening-rev>` (design §5). The PocketBase version
migrates `pb_data` irreversibly. The hardening rev changes only the environment and rolls out
fleet-wide.

Build and verify from the repo root (Docker work runs in the development VM):

```
./hack/in-vm.sh make registry                                # local zot on 127.0.0.1:5000
./hack/in-vm.sh make image PB_VERSION=0.42.2 HARDENING_REV=2 # one image → digest
./hack/in-vm.sh make image-matrix HARDENING_REV=2            # every version in versions.txt
./hack/in-vm.sh make smoke                                   # image self-checks by digest
```

The control plane schedules **digests, never tags**. `make image` appends to `digests.txt`,
which the control plane reads.

## Adding a PocketBase version

1. `./fetch-checksum.sh <version>` pins the upstream sha256 into `checksums/`. Commit it.
2. Add the version to `versions.txt`.
3. `make image PB_VERSION=<version> HARDENING_REV=<current>`, then run smoke.

Builds verify only against the **committed** checksum.

Builds are reproducible: rebuilding a `(version, rev, arch)` gives the same digest and adds no
line to `digests.txt`. The Alpine base is pinned by digest (`ALPINE_IMAGE` in the
Containerfile) because it supplies the CA bundle. Bumping it changes every digest, so it
counts as a `HARDENING_REV` bump.

## Profiles

- **`seccomp.json`** is Moby's default profile minus `ptrace`, `process_vm_readv/writev`,
  `kcmp`, `memfd_secret` and every capability-gated group. It only enforces under `runc`,
  because `runsc` ignores per-container seccomp, so `smoke.sh` checks it under runc.
- **`apparmor/pb-hardened`** allows writes only under `/pb/pb_data` and `/tmp`, and denies
  capabilities, ptrace and raw sockets. `smoke.sh` warns and skips when the kernel lacks
  AppArmor; re-run it on the production host.
