#!/usr/bin/env bash
# Run a command inside the development VM, as root, from the repo root.
#
# It exists because the Docker daemon the control plane manages lives in the VM,
# not on the Mac — the binaries and scripts themselves are plain Linux and run
# unchanged on a production host.
#
# The development VM is a UTM guest. Unlike a filesystem-sharing VM manager, the
# repo is NOT visible inside the guest by itself: this script rsyncs the working
# tree (including bin/, which `make build` cross-compiles on the Mac) into
# $PB_VM_DIR and then runs the command there over ssh. The guest path is
# $PB_VM_DIR, not the Mac path — nothing in the tree depends on the Mac path,
# every script derives its own root from $0.
#
# UTM's shared network is vmnet, so the guest has its own address on a host
# interface and needs no port forwarding. The address is not stable across
# rebuilds, so it is resolved from UTM each time rather than configured.
#
#   PB_VM        UTM VM name                         (default: citadel)
#   PB_VM_HOST   ssh host                            (default: the VM's address)
#   PB_VM_PORT   ssh port                            (default: 22)
#   PB_VM_USER   ssh user, must have passwordless sudo (default: ubuntu)
#   PB_VM_KEY    ssh identity file                   (default: ~/.ssh/citadel_vm)
#   PB_VM_DIR    repo path inside the guest          (default: /opt/citadel)
#   PB_VM_NO_SYNC  set to 1 to skip the rsync (repeated probe runs)
#
# Usage: hack/in-vm.sh bin/citadel tenant list
set -eu

VM_NAME="${PB_VM:-citadel}"
VM_PORT="${PB_VM_PORT:-22}"
VM_USER="${PB_VM_USER:-ubuntu}"
VM_KEY="${PB_VM_KEY:-$HOME/.ssh/citadel_vm}"
VM_DIR="${PB_VM_DIR:-/opt/citadel}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() { echo "in-vm: $*" >&2; exit 1; }

# Setting PB_VM_HOST means another hypervisor or a remote Linux box, and utmctl
# has nothing to say about either — so it is only consulted for the default.
VM_HOST="${PB_VM_HOST:-}"
if [ -z "$VM_HOST" ]; then
    command -v utmctl >/dev/null ||
        die "utmctl not found and PB_VM_HOST is unset; install UTM (brew install --cask utm) or set PB_VM_HOST"
    # By UUID, never by name: see hack/vm/resolve.sh.
    . "$REPO_ROOT/hack/vm/resolve.sh"
    rc=0
    VM_UUID="$(utm_vm_uuid "$VM_NAME")" || rc=$?
    case "$rc" in
        0) ;;
        1) die "no UTM VM named '$VM_NAME' — run 'make vm-create'" ;;
        *) die "cannot pick a VM to talk to (see above)" ;;
    esac
    status="$(utmctl status "$VM_UUID" 2>/dev/null || true)"
    [ "$status" = started ] ||
        die "UTM VM '$VM_NAME' is ${status:-in an unknown state} — run 'make vm-up'"
    # The guest agent answers this, and cloud-init installs it on first boot,
    # so an empty answer during the very first boot is expected — `make vm-up`
    # retries.
    # Not simply the first IPv4: the guest agent lists EVERY interface, in no
    # stable order, and once Docker and the platform are up that includes the
    # docker0 gateway, the egress bridge and every tenant bridge's gateway —
    # none of which the Mac can reach. Skip the private ranges Docker and the
    # platform hand out (172.16/12, and 10.213/16 and 10.214/16 by default).
    VM_HOST="$(utmctl ip-address "$VM_UUID" 2>/dev/null |
        grep -E '^[0-9]+(\.[0-9]+){3}$' |
        grep -vE '^(172\.(1[6-9]|2[0-9]|3[01])\.|10\.21[34]\.)' | head -1 || true)"
    [ -n "$VM_HOST" ] ||
        die "UTM reports no address for '$VM_NAME' yet; give it a moment to finish booting, or set PB_VM_HOST"
fi

[ -f "$VM_KEY" ] || die "ssh key $VM_KEY not found; run 'make vm-create', or set PB_VM_KEY"

SSH_OPTS="-p $VM_PORT -i $VM_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts_citadel -o ConnectTimeout=10"
# shellcheck disable=SC2086,SC2029  # SSH_OPTS splits; the command is built (and %q-escaped) here on purpose
ssh $SSH_OPTS "$VM_USER@$VM_HOST" true 2>/dev/null ||
    die "cannot ssh to $VM_USER@$VM_HOST:$VM_PORT — is the VM booted? ('make vm-up', then 'make vm-provision')"

if [ -z "${PB_VM_NO_SYNC:-}" ]; then
    # --delete so a file removed on the Mac is removed in the guest: the suites
    # assert on what is NOT there as much as on what is.
    rsync -a --delete \
        --exclude '.git/' --exclude '.DS_Store' \
        --exclude 'test/netprobe/out/' \
        -e "ssh $SSH_OPTS" \
        "$REPO_ROOT/" "$VM_USER@$VM_HOST:$VM_DIR/" ||
        die "rsync to $VM_DIR failed"
fi

# A tty is requested only when there is one to forward: the suites colour their
# output, but `make accept | tee` must still work.
TTY_FLAG=""
[ -t 1 ] && TTY_FLAG="-t"

set +e
# shellcheck disable=SC2086,SC2029  # SSH_OPTS splits; the command is built (and %q-escaped) here on purpose
ssh $SSH_OPTS $TTY_FLAG "$VM_USER@$VM_HOST" \
    "sudo bash -c $(printf '%q' "cd '$VM_DIR' && $(printf '%q ' "$@")")"
rc=$?
set -e

# Pull the digests back. `make image` and the `make *-image` targets record the
# pushed digest by appending to images/*/digests.txt IN THE GUEST, and that file
# is the committed hand-off to the control plane — without this the next
# --delete sync would throw the build away. Harmless when nothing wrote them.
if [ -z "${PB_VM_NO_SYNC:-}" ]; then
    for d in pb-hardened edge-caddy rehearse-probe egress-proxy; do
        [ -f "$REPO_ROOT/images/$d/digests.txt" ] || continue
        rsync -a -e "ssh $SSH_OPTS" \
            "$VM_USER@$VM_HOST:$VM_DIR/images/$d/digests.txt" \
            "$REPO_ROOT/images/$d/digests.txt" 2>/dev/null || true
    done
fi

exit $rc
