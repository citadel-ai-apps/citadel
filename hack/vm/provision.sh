#!/usr/bin/env bash
# Install everything the platform needs on a fresh Ubuntu guest. Run ON the
# guest, as root — `make vm-provision` does that for you.
#
# This is the step before hack/bootstrap-vm.sh, which assumes Docker and runsc
# are already there and only dies if they are not. In particular D2 requires
# gVisor, and nothing else in the tree installs it.
#
# Idempotent: re-running it on a provisioned guest is a no-op that re-verifies.
#
# Usage: hack/vm/provision.sh
set -euo pipefail

die() { echo "provision: $*" >&2; exit 1; }
log() { printf '%s %s\n' "[$(date +%H:%M:%S)]" "$*"; }

[ "$(id -u)" = 0 ] || die "must run as root"
# shellcheck source=/dev/null  # the target host's, not present where lint runs
. /etc/os-release
[ "${ID:-}" = ubuntu ] || [ "${ID:-}" = debian ] || [ "${ID_LIKE:-}" = debian ] ||
    die "this script targets Ubuntu/Debian; adapt it for $ID"

export DEBIAN_FRONTEND=noninteractive
ARCH_DEB="$(dpkg --print-architecture)"

log "base packages"
apt-get update -qq
apt-get install -y -qq \
    ca-certificates curl gnupg rsync jq sqlite3 python3 make bzip2 \
    iptables iproute2 netcat-openbsd dnsutils shellcheck

# ── Room to work ─────────────────────────────────────────────────────────────
# Checked before Docker rather than after: the image store, the local registry
# and every tenant's data all land on this filesystem, and running out partway
# through `make image-matrix` wastes a long build. If cloud-init's growpart did
# not run, the root filesystem is still the cloud image's 2.5 GiB.
avail_gib=$(( $(df --output=avail -k / | tail -1) / 1024 / 1024 ))
if [ "$avail_gib" -lt 20 ]; then
    die "only ${avail_gib} GiB free on / — the disk did not grow on first boot.
     Check 'cloud-init status --long' in the guest, or recreate the VM with
     'make vm-create ARGS=--recreate'."
fi
log "${avail_gib} GiB free on /"

# ── Docker CE ────────────────────────────────────────────────────────────────
# From Docker's own repository, not Ubuntu's: §4 requires Docker >= 28 and the
# distro package lags. The firewall backend is pinned to iptables by
# hack/bootstrap-vm.sh, not here.
if ! command -v docker >/dev/null; then
    log "installing Docker CE"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$ID/gpg" |
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$ARCH_DEB signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin
    systemctl enable --now docker
fi
docker_major="$(docker version --format '{{.Server.Version}}' | cut -d. -f1)"
[ "$docker_major" -ge 28 ] || die "Docker $docker_major is older than the required 28"
log "docker $(docker version --format '{{.Server.Version}}')"

# ── gVisor ───────────────────────────────────────────────────────────────────
# D2: tenant containers run under runsc. Platform containers stay on runc, so
# runsc is registered as an additional runtime, never as the default.
if ! command -v runsc >/dev/null; then
    log "installing gVisor (runsc)"
    case "$ARCH_DEB" in
        arm64) gv_arch=aarch64 ;;
        amd64) gv_arch=x86_64 ;;
        *) die "no gVisor build for $ARCH_DEB" ;;
    esac
    gv_base="https://storage.googleapis.com/gvisor/releases/release/latest/$gv_arch"
    gv_tmp="$(mktemp -d)"
    curl -fsSL "$gv_base/gvisor.tar.bz2" -o "$gv_tmp/gvisor.tar.bz2" ||
        die "could not download gVisor"
    curl -fsSL "$gv_base/gvisor.tar.bz2.sha512" -o "$gv_tmp/gvisor.tar.bz2.sha512" ||
        die "could not download the gVisor checksum"
    # The checksum file names the bare tarball, so verify from its directory.
    ( cd "$gv_tmp" && sha512sum -c gvisor.tar.bz2.sha512 >/dev/null ) ||
        die "gVisor checksum mismatch"
    # runsc and its shim go on PATH; gvisor-bin/ holds helpers runsc resolves
    # relative to itself, so the layout has to be kept.
    tar -xjf "$gv_tmp/gvisor.tar.bz2" -C /usr/local/bin
    chmod 0755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
    rm -rf "$gv_tmp"
fi

# ── Daemon configuration ─────────────────────────────────────────────────────
# Two things, written together so the daemon restarts once.
#
# runsc, per D2: tenant containers run under gVisor. Platform containers stay
# on runc, so it is registered as an additional runtime, never as the default.
#
# DNS, because of how this VM is networked. Ubuntu's /etc/resolv.conf points at
# systemd-resolved's stub on 127.0.0.53, and the real upstream list underneath
# it includes a link-local IPv6 address with a scope id. Neither survives the
# trip into a container: Docker substitutes a public resolver for the stub, and
# BuildKit passes the scoped address straight through, where it fails as
# "Network unreachable" — which apk and apt both report as a transient DNS
# error. It is not transient.
#
# Under UTM's shared networking the host's own resolver is the vmnet gateway,
# on 192.168.64.1. So rather than assume any of them, each candidate is TESTED
# from inside a container and the first one that answers is the one configured.
# Override with PB_VM_DNS.
#
# But the probe alone is not enough, and getting this wrong is expensive to
# diagnose. The control plane's unconditional deny list (netpolicy.DeniedRanges)
# puts `-d 192.168.0.0/16 -j DROP` in DOCKER-USER, so the vmnet gateway stops
# answering container queries the moment the platform first reconciles — long
# after provisioning, where it probes fine and gets pinned into daemon.json.
# Every name lookup in every container then fails, which surfaces as the egress
# proxy returning 503/HIER_NONE and the §9.4 netprobes failing on the ALLOW path
# while the deny checks stay green. So denied ranges are filtered out here,
# before the probe, and hack/bootstrap-vm.sh re-checks once the rules are real.
denied_ranges='169.254.0.0/16 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12'

# in_denied_range <ipv4> — the same four ranges as netpolicy.DeniedRanges.
in_denied_range() {
    case "$1" in
        169.254.*)                                       return 0 ;;
        10.*)                                            return 0 ;;
        192.168.*)                                       return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)          return 0 ;;
        *)                                               return 1 ;;
    esac
}

dns_candidates="${PB_VM_DNS:-}"
if [ -n "$dns_candidates" ]; then
    for cand in $dns_candidates; do
        in_denied_range "$cand" &&
            die "PB_VM_DNS=$cand is inside the platform deny list ($denied_ranges);
     containers can reach it now but not once the control plane reconciles."
    done
else
    dns_candidates="$(resolvectl status 2>/dev/null |
        awk '/DNS Servers:|Current DNS Server:/ { for (i = 1; i <= NF; i++)
                 if ($i ~ /^[0-9]+(\.[0-9]+){3}$/) print $i }' | sort -u || true)"
    # Public fallbacks, for when the host's resolver is only reachable from the
    # host. A development VM, not a production host: it resolves what it must
    # to build images, and egress from tenants is governed separately.
    dns_candidates="$dns_candidates
1.1.1.1
8.8.8.8"

    kept=""
    for cand in $dns_candidates; do
        if in_denied_range "$cand"; then
            log "  skipping $cand — inside the platform deny list"
        else
            kept="$kept $cand"
        fi
    done
    dns_candidates="$kept"
fi

DNS_UPSTREAM=""
for cand in $dns_candidates; do
    if docker run --rm --dns "$cand" alpine:3 \
         getent hosts dl-cdn.alpinelinux.org >/dev/null 2>&1; then
        DNS_UPSTREAM="$cand"
        break
    fi
    log "  $cand does not resolve from a container"
done
[ -n "$DNS_UPSTREAM" ] ||
    die "no candidate resolver works from inside a container (tried: ${dns_candidates//$'\n'/ }).
     Set PB_VM_DNS to one that does, outside $denied_ranges."

log "configuring the daemon (runsc, dns $DNS_UPSTREAM)"
python3 - "$DNS_UPSTREAM" <<'PY'
import json, os, sys
path = "/etc/docker/daemon.json"
cfg = json.load(open(path)) if os.path.exists(path) else {}
cfg.setdefault("runtimes", {})["runsc"] = {
    "path": "/usr/local/bin/runsc",
    # systrap is the platform the runtime contract measured (~36 % API write
    # penalty). ptrace is far slower; KVM needs nested virtualisation.
    "runtimeArgs": ["--platform=systrap"],
}
cfg["dns"] = sys.argv[1:]
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PY
systemctl restart docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done

docker info --format '{{json .Runtimes}}' | grep -q runsc || die "runsc did not register (D2)"
log "runsc $(runsc --version | head -1)"

# Prove it, rather than assuming: a build that cannot resolve anything fails
# several minutes into `make image-matrix` instead of here.
log "checking name resolution inside a build"
build_dir="$(mktemp -d)"
printf 'FROM alpine:3\nRUN getent hosts dl-cdn.alpinelinux.org\n' > "$build_dir/Dockerfile"
docker build -q -t v2p-dns-check "$build_dir" >/dev/null 2>&1 ||
    die "a build container cannot resolve names even after setting dns=$(echo "$DNS_UPSTREAM" | tr '\n' ' ')"
docker rmi -f v2p-dns-check >/dev/null 2>&1 || true
rm -rf "$build_dir"

log "guest is provisioned — next: make vm-bootstrap"
