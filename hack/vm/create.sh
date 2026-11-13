#!/usr/bin/env bash
# Create the development VM in UTM, from nothing. Run on the Mac.
#
#   hack/vm/create.sh [--recreate]
#
# It downloads a pinned Ubuntu cloud image, generates an ssh key if you have
# none, builds a cloud-init seed, and registers a UTM virtual machine with the
# three drives the rest of the tooling expects. It does not start the VM:
# `make vm-up` does that.
#
# Two things it does NOT do, both because UTM's own tooling cannot:
#
#   * Convert the cloud image. UTM ships qemu-img as a library rather than a
#     binary, so there is no way to convert qcow2 from a script. That is why
#     this uses UTM's QEMU backend, which reads qcow2 directly, rather than the
#     Apple Virtualization backend, which needs raw. Growing the image — the
#     cloud image is 3.5 GiB, which Docker fills before it finishes installing
#     — is done by qcow2-resize.py for the same reason.
#   * Attach the cloud-init seed as a CD. UTM's scripting layer accepts a
#     removable drive but silently ignores its source file (checked against UTM
#     build 118), so the seed is attached as a plain disk instead — cloud-init
#     finds the cidata label on any block device.
#
# Everything else goes through UTM's documented scripting interface.
set -euo pipefail

VM_NAME="${PB_VM:-citadel}"
VM_CPUS="${PB_VM_CPUS:-4}"
VM_MEM_MIB="${PB_VM_MEM_MIB:-8192}"
VM_DISK_GIB="${PB_VM_DISK_GIB:-64}"
SSH_KEY="${PB_VM_KEY:-$HOME/.ssh/citadel_vm}"
RECREATE=0
[ "${1:-}" = "--recreate" ] && RECREATE=1

HERE="$(cd "$(dirname "$0")" && pwd)"
SEED_DIR="$HERE/cloud-init"
CACHE="${PB_VM_CACHE:-$HOME/Library/Caches/citadel}"

die() { echo "create-vm: $*" >&2; exit 1; }
log() { printf '\033[1m==> %s\033[0m\n' "$*"; }

# ── Preflight ────────────────────────────────────────────────────────────────
[ "$(uname -s)" = Darwin ] || die "UTM is macOS-only; on Linux run the suites directly"
[ -d /Applications/UTM.app ] || die "UTM not found — brew install --cask utm"
command -v utmctl >/dev/null || die "utmctl not on PATH (brew install --cask utm links it)"
for t in curl shasum hdiutil osascript ssh-keygen plutil; do
    command -v "$t" >/dev/null || die "$t not found"
done

# The guest architecture matches the host: the whole point of the VM is a real
# kernel under a real hypervisor, and emulating a foreign architecture would
# give neither.
case "$(uname -m)" in
    arm64)  GUEST_ARCH=aarch64; IMG_ARCH=arm64 ;;
    x86_64) GUEST_ARCH=x86_64;  IMG_ARCH=amd64 ;;
    *) die "unsupported host architecture $(uname -m)" ;;
esac

# By UUID, never by name: see resolve.sh. Deleting by name right after a
# non-blocking `utmctl stop` is what once left a stale second 'citadel' in
# UTM's registry, pointing at the same bundle as the new VM.
. "$HERE/resolve.sh"
rc=0
OLD_UUID="$(utm_vm_uuid "$VM_NAME" 2>/dev/null)" || rc=$?
case "$rc" in
    0)
        [ "$RECREATE" = 1 ] || die "a VM named '$VM_NAME' already exists — pass --recreate to replace it (ALL ITS DATA IS DELETED)"
        log "deleting the existing '$VM_NAME' ($OLD_UUID)"
        if [ "$(utmctl status "$OLD_UUID")" != stopped ]; then
            utmctl stop "$OLD_UUID"
            for _ in $(seq 1 60); do
                [ "$(utmctl status "$OLD_UUID" 2>/dev/null)" = stopped ] && break
                sleep 1
            done
            [ "$(utmctl status "$OLD_UUID" 2>/dev/null)" = stopped ] ||
                die "'$VM_NAME' did not stop within 60s; stop it in UTM and retry"
        fi
        osascript -e "tell application \"UTM\" to delete virtual machine id \"$OLD_UUID\"" >/dev/null ||
            die "UTM refused to delete $OLD_UUID"
        [ -z "$(utm_vm_matches "$VM_NAME")" ] ||
            die "'$VM_NAME' is still registered in UTM after the delete; remove it by hand and retry"
        ;;
    1) ;;
    *) utm_vm_uuid "$VM_NAME" >/dev/null || true
       die "will not create or delete anything while the name is ambiguous — 'make vm-doctor ARGS=--fix' clears a ghost" ;;
esac

# Nothing named $VM_NAME is registered now, as far as utmctl can tell. What it
# cannot tell is the cause of every duplicate so far (see resolve.sh): a QEMU
# still running off a deleted bundle, and a hidden registry entry for this
# bundle path that a new bundle would bring back to life.
BUNDLE="$(utm_bundle_path "$VM_NAME")"
if [ -e "$BUNDLE" ]; then
    [ "$RECREATE" = 1 ] ||
        die "$BUNDLE exists but no VM is registered for it — pass --recreate to delete it (ALL ITS DATA IS DELETED)"
    log "removing the unregistered bundle $BUNDLE"
    rm -rf "$BUNDLE"
fi
orphans="$(utm_qemu_for_bundle "$VM_NAME")"
if [ -n "$orphans" ]; then
    if [ "$RECREATE" = 1 ]; then
        while read -r pid uuid; do
            log "killing orphan QEMU $pid ($uuid), whose bundle is gone"
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
            kill -9 "$pid" 2>/dev/null || true
        done <<< "$orphans"
    else
        echo "$orphans" | sed 's/^/    pid uuid: /' >&2
        die "QEMU is still running a deleted '$VM_NAME' — 'make vm-doctor ARGS=--fix' kills it, or pass --recreate"
    fi
fi
ghosts="$(utm_registry_for_bundle "$VM_NAME")"
if [ -n "$ghosts" ]; then
    # shellcheck disable=SC2086
    log "purging stale registry entries for $BUNDLE:" $ghosts
    # shellcheck disable=SC2086
    utm_registry_purge $ghosts || die "could not purge the stale entries; see 'Duplicate VM entries' in hack/vm/README.md"
    [ -z "$(utm_registry_for_bundle "$VM_NAME")" ] ||
        die "stale registry entries for $BUNDLE survived the purge"
fi

# ── The ssh key ──────────────────────────────────────────────────────────────
if [ ! -f "$SSH_KEY" ]; then
    log "generating an ssh key at $SSH_KEY"
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -t ed25519 -f "$SSH_KEY" -C "$VM_NAME-dev" -N '' >/dev/null
fi
[ -f "$SSH_KEY.pub" ] || die "$SSH_KEY exists but $SSH_KEY.pub does not"

# ── The cloud image ──────────────────────────────────────────────────────────
# Pinned to a dated release with a committed checksum, for the same reason the
# PocketBase image pins its binary: a base image that changes underneath you
# makes every result before the change unreproducible.
. "$HERE/ubuntu-image.conf"
IMG_FILE="ubuntu-$UBUNTU_RELEASE-server-cloudimg-$IMG_ARCH.img"
IMG_URL="https://cloud-images.ubuntu.com/releases/$UBUNTU_RELEASE/$UBUNTU_SERIAL/$IMG_FILE"
eval "WANT_SHA=\$UBUNTU_SHA256_$IMG_ARCH"
[ -n "${WANT_SHA:-}" ] || die "no pinned checksum for $IMG_ARCH in hack/vm/ubuntu-image.conf"

mkdir -p "$CACHE"
IMG_PATH="$CACHE/$UBUNTU_SERIAL-$IMG_FILE"
if [ -f "$IMG_PATH" ] && [ "$(shasum -a 256 "$IMG_PATH" | cut -d' ' -f1)" = "$WANT_SHA" ]; then
    log "cloud image already cached and verified"
else
    log "downloading $IMG_FILE ($UBUNTU_SERIAL)"
    curl -fL --progress-bar -o "$IMG_PATH.part" "$IMG_URL" || die "download failed"
    got="$(shasum -a 256 "$IMG_PATH.part" | cut -d' ' -f1)"
    [ "$got" = "$WANT_SHA" ] || {
        rm -f "$IMG_PATH.part"
        die "checksum mismatch for $IMG_FILE: got $got, pinned $WANT_SHA"
    }
    mv "$IMG_PATH.part" "$IMG_PATH"
    log "checksum verified"
fi

# ── The cloud-init seed ──────────────────────────────────────────────────────
# NoCloud reads user-data and meta-data off any attached volume labelled
# cidata, so a tiny ISO is enough. It is attached as a plain disk rather than a
# CD: UTM's scripting interface silently ignores the source file of a removable
# drive, leaving an empty CD and a VM that never runs cloud-init at all.
log "building the cloud-init seed"
PUBKEY="$(cat "$SSH_KEY.pub")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
awk -v k="$PUBKEY" '{gsub(/@SSH_PUBKEY@/, k); print}' \
    "$SEED_DIR/user-data.tmpl" > "$STAGE/user-data"
printf 'instance-id: %s-1\nlocal-hostname: %s\n' "$VM_NAME" "$VM_NAME" > "$STAGE/meta-data"
# Kept beside the template so you can read what was actually handed to the VM.
cp "$STAGE/user-data" "$SEED_DIR/user-data"
cp "$STAGE/meta-data" "$SEED_DIR/meta-data"
SEED_ISO="$SEED_DIR/seed.iso"
rm -f "$SEED_ISO"
hdiutil makehybrid -iso -joliet -joliet-volume-name cidata \
    -default-volume-name cidata -o "$SEED_ISO" "$STAGE" >/dev/null ||
    die "could not build the seed image"

# ── The boot disk ────────────────────────────────────────────────────────────
# Grown from a throwaway copy so the cache stays byte-identical to what the
# checksum covers. cloud-init's growpart extends the root partition and
# filesystem to fill it on first boot.
log "growing the boot disk to $VM_DISK_GIB GiB"
BOOT_IMG="$STAGE/boot.qcow2"
cp "$IMG_PATH" "$BOOT_IMG"
python3 "$HERE/qcow2-resize.py" "$BOOT_IMG" "$VM_DISK_GIB" ||
    die "could not grow the boot disk"

# ── Create the VM ────────────────────────────────────────────────────────────
# UTM copies each source file into the VM bundle, so the cache and the seed can
# both be thrown away afterwards.
log "creating the UTM virtual machine '$VM_NAME'"
open -ga UTM
for _ in $(seq 1 30); do
    osascript -e 'tell application "UTM" to count virtual machines' >/dev/null 2>&1 && break
    sleep 1
done

VM_ID="$(osascript <<AS
tell application "UTM"
  set v to make new virtual machine with properties {backend:qemu, configuration:{ ¬
    name:"$VM_NAME", architecture:"$GUEST_ARCH", machine:"virt", ¬
    memory:$VM_MEM_MIB, cpu cores:$VM_CPUS, hypervisor:true, uefi:true, ¬
    drives:{ ¬
      {removable:false, interface:VirtIO, source:POSIX file "$BOOT_IMG"}, ¬
      {removable:false, interface:VirtIO, source:POSIX file "$SEED_ISO"} }, ¬
    network interfaces:{{mode:shared}} }}
  return id of v
end tell
AS
)" || die "UTM refused the configuration"
log "created $VM_ID"
[ "$(utm_vm_uuid "$VM_NAME")" = "$VM_ID" ] ||
    die "UTM does not resolve '$VM_NAME' to exactly the VM just created ($VM_ID)"
# The registry is the copy UTM reloads on its next launch, which is when a
# ghost used to reappear, so check that too. UTM writes it asynchronously.
for _ in $(seq 1 10); do
    [ "$(utm_registry_for_bundle "$VM_NAME")" = "$VM_ID" ] && break
    sleep 0.5
done
[ "$(utm_registry_for_bundle "$VM_NAME")" = "$VM_ID" ] ||
    die "UTM's registry does not hold exactly $VM_ID for $BUNDLE: $(utm_registry_for_bundle "$VM_NAME" | tr '\n' ' ')"

# ── Check what UTM actually built ────────────────────────────────────────────
# UTM reports success while silently dropping a drive source it did not like,
# and an empty seed drive means a VM that boots, never runs cloud-init, and has
# no way in — a failure that otherwise only surfaces as an ssh timeout minutes
# later.
PLIST="$BUNDLE/config.plist"
[ -f "$PLIST" ] || die "expected $PLIST after creation"
python3 - "$PLIST" <<'PY'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    cfg = plistlib.load(f)

drives = cfg.get("Drive") or []
if len(drives) != 2:
    sys.exit("expected 2 drives (boot, seed), found %d" % len(drives))
empty = [i for i, d in enumerate(drives) if not d.get("ImageName")]
if empty:
    sys.exit("UTM created drive(s) %s without an image"
             % ", ".join(str(i) for i in empty))

# Shared mode is vmnet: the guest gets its own address on a host interface,
# which is what `utmctl ip-address` reports and hack/in-vm.sh dials. Any other
# mode leaves the guest unreachable from the Mac.
nets = cfg.get("Network") or []
if not nets or nets[0].get("Mode") != "Shared":
    sys.exit("expected one network device in Shared mode, found %r" % (nets,))
PY

cat <<EOF

$VM_NAME is created. It has not been started yet.

  make vm-up          # boot it and wait for cloud-init to finish with ssh
  make vm-provision   # Docker, gVisor, and the suites' dependencies
  make vm-bootstrap   # user-namespace remapping, registry, image matrix

ssh:   as ubuntu with $SSH_KEY, at whatever address UTM hands the guest
       (\`utmctl ip-address $VM_NAME\`, which hack/in-vm.sh resolves for you)
disk:  $UBUNTU_RELEASE cloud image grown to ${VM_DISK_GIB} GiB

The first boot runs cloud-init, which installs packages and grows the root
filesystem, so it takes a few minutes longer than later ones.
EOF
