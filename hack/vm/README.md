# The development VM

Everything that touches Docker (image builds, acceptance suites, red-team matrix, network
probes) runs on Linux. In development that is a [UTM](https://mac.getutm.app) guest on a
stock Ubuntu kernel, because the guarantees under test are kernel guarantees.

## From nothing

```sh
brew install --cask utm     # once

make vm-create              # download, seed, register the VM in UTM
make vm-up                  # boot it and wait for cloud-init
make vm-provision           # Docker, gVisor, and the suites' dependencies
make vm-bootstrap           # user-namespace remapping, registry, image matrix
```

`vm-create` needs no preparation. It generates `~/.ssh/citadel_vm` if missing, downloads
and checksums the pinned Ubuntu image, grows it, builds the cloud-init seed and registers
the VM. `vm-bootstrap` enables `userns-remap`, which rebuilds the image store; that must
happen before first use. `make vm-create ARGS=--recreate` deletes the VM and starts over.

## Day to day

```sh
make vm-status      # is it up, is ssh answering, is Docker healthy
make vm-ssh         # a shell in the guest
make vm-down        # stop it

hack/in-vm.sh bin/citadel fleet
hack/in-vm.sh bash test/netprobe/01-internal-isolation.sh
```

Each `in-vm.sh` call rsyncs the tree in first and copies `images/*/digests.txt` back
afterwards. `PB_VM_NO_SYNC=1` skips both.

## Duplicate VM entries

UTM allows two VMs with the same name, and `utmctl` then resolves `citadel` to whichever
one it finds first. So the scripts address UTM by UUID (`hack/vm/resolve.sh`) and stop with
an error when the name is ambiguous. Two states cause duplicates, and `utmctl` shows
neither:

- **Ghost registry entry**: an entry for `citadel.utm` that outlived its VM. While no bundle
  exists at that path UTM hides it. When a new VM is created there, the entry resolves to the
  new bundle and a second `citadel` appears.
- **Orphan QEMU**: a VM whose bundle was deleted while it was running. QEMU keeps the
  unlinked disk open and stays on the network, but UTM stops listing it.

`make vm-create` clears both before it creates anything: it refuses if it finds orphans, or
kills them under `--recreate`, and it purges ghost entries. To check or repair an existing
VM:

```sh
make vm-doctor              # report ghosts, orphans, stray bundles (also part of vm-status)
make vm-doctor ARGS=--fix   # kill orphans, edit ghosts out of UTM's registry
```

`--fix` has to quit UTM to edit its registry, so it stops `citadel` first and starts it
again afterwards. It refuses if any other VM is running. A backup of the preferences file is
left at `com.utmapp.UTM.plist.bak-<timestamp>`.

**Never delete a ghost from UTM's GUI**: it shares the real VM's bundle, so the delete
removes the real VM's disk. That is how the orphans arise. For the same reason, don't delete
a running VM's entry.

## How it is put together

| | |
|---|---|
| Backend | UTM's **QEMU** backend, hardware-accelerated, native guest architecture |
| Disk | the Ubuntu cloud image, grown to 64 GiB |
| Seed | a second disk holding a `cidata` ISO for cloud-init |
| Network | UTM **Shared** mode — the guest is reachable from the Mac, no port forwarding |

UTM quirks the scripts work around:

- **No `qemu-img`**: UTM does not ship one, so `qcow2-resize.py` grows the image by editing
  its header.
- **The seed is a plain disk, not a CD**: UTM's scripting ignores a removable drive's
  source. `create.sh` checks that every drive actually got its image.
- **No port forwards**: they cannot be set over AppleScript, and Shared mode makes them
  unnecessary anyway.
- **DNS from containers**: containers cannot reach the guest's own resolver.
  `provision.sh` tests candidate resolvers from inside a container and configures the
  first that answers. Override with `PB_VM_DNS`.

## Using something other than UTM

`hack/in-vm.sh` only needs ssh. With `PB_VM_HOST` set it never calls `utmctl`:

```sh
PB_VM_HOST=10.0.0.5 make accept-controlplane
```

Only the `vm-create`, `vm-up`, `vm-down`, `vm-status`, `vm-doctor` and `vm-ssh` targets are
UTM-specific.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PB_VM` | `citadel` | UTM VM name |
| `PB_VM_HOST` | from `utmctl ip-address` | ssh host |
| `PB_VM_PORT` | `22` | ssh port |
| `PB_VM_USER` | `ubuntu` | ssh user; needs passwordless sudo |
| `PB_VM_KEY` | `~/.ssh/citadel_vm` | ssh identity |
| `PB_VM_DIR` | `/opt/citadel` | repo path inside the guest |
| `PB_VM_NO_SYNC` | unset | skip the rsync |
| `PB_VM_CPUS` | `4` | cores, at creation |
| `PB_VM_MEM_MIB` | `8192` | RAM, at creation |
| `PB_VM_DISK_GIB` | `64` | disk, at creation |
| `PB_VM_DNS` | detected | resolver for the daemon |

The base image is pinned in `ubuntu-image.conf` by dated serial and checksum. Run
`make check` before committing a newer one.
