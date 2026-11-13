#!/usr/bin/env bash
# Prepare the Docker host for the control plane. Run ON the host, as root.
#
# The one thing that cannot be done later is `userns-remap: default` in
# daemon.json (D3). It must be enabled BEFORE first production use, never as a
# later migration: the image store is per-remap-namespace, so flipping it
# re-pulls everything (design.md §4). Here that is three images
# from the local zot registry, which is cheap — on a populated host it is not.
#
# Usage: hack/bootstrap-vm.sh
set -euo pipefail

DAEMON_JSON=/etc/docker/daemon.json
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() { echo "bootstrap: $*" >&2; exit 1; }
log() { printf '%s %s\n' "[$(date +%H:%M:%S)]" "$*"; }

[ "$(id -u)" = 0 ] || die "must run as root"
command -v docker >/dev/null || die "docker not found"
command -v python3 >/dev/null || die "python3 is needed to edit daemon.json safely"

if docker info --format '{{json .SecurityOptions}}' | grep -q userns; then
    log "userns-remap is already enabled"
else
    log "enabling userns-remap in $DAEMON_JSON (this re-pulls the image store)"
    python3 - "$DAEMON_JSON" <<'PY'
import json, os, sys
path = sys.argv[1]
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        cfg = json.load(f)
cfg["userns-remap"] = "default"
# Pinned explicitly: Docker 29's nftables backend changes the rule layout and
# would require migrating DOCKER-USER rules (design §4). The control plane
# refuses to start if this is anything else.
cfg.setdefault("firewall-backend", "iptables")
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PY
    log "restarting docker"
    systemctl restart docker
    for _ in $(seq 1 30); do
        docker info >/dev/null 2>&1 && break
        sleep 1
    done
    docker info --format '{{json .SecurityOptions}}' | grep -q userns || \
        die "docker restarted but userns-remap is not active"
fi

grep -q '^dockremap:' /etc/subuid || die "userns-remap is on but /etc/subuid has no dockremap entry"
log "subuid base: $(awk -F: '/^dockremap:/{print $2}' /etc/subuid)"

# Container DNS, checked HERE rather than in hack/vm/provision.sh, because this
# is the first point at which the platform's rules can already exist.
# provision.sh picks the resolver by probing it from a container, on a host where
# DOCKER-USER is still Docker's own — so a resolver inside netpolicy.DeniedRanges
# (the vmnet gateway on 192.168.64.1, under UTM) probes fine and gets pinned,
# then starts being dropped the moment the control plane first reconciles. The
# symptom is remote from the cause: the egress proxy answers 503/HIER_NONE and
# the §9.4 netprobes fail on the ALLOW path only. One lookup is cheap insurance.
log "checking name resolution from a container"
docker run --rm alpine:3 getent hosts dl-cdn.alpinelinux.org >/dev/null 2>&1 || \
    die "a container cannot resolve names. daemon.json has dns=$(python3 -c \
'import json;print(",".join(json.load(open("'"$DAEMON_JSON"'")).get("dns",[])) or "unset")' 2>/dev/null).
     If that address is inside 169.254.0.0/16, 10.0.0.0/8, 192.168.0.0/16 or
     172.16.0.0/12 the platform's own deny list is dropping the query — re-run
     'make vm-provision', or set PB_VM_DNS to a resolver outside those ranges."

log "ensuring the local registry is up"
make -C "$REPO_ROOT" registry

# Enabling userns-remap moves Docker's ENTIRE data root to
# /var/lib/docker/<uid>.<gid>/ — not just the image store but named volumes too.
# So the registry comes back with an empty volume and the images pushed before
# the flip are gone from both the store and the registry. This is the operational
# cost D3 warns about, and the reason it must be enabled before first production
# use rather than migrated into later.
#
# Rebuilding reproduces the same digests: `make image` pins the PocketBase zip
# by a committed checksum, the Alpine base by digest, and every timestamp
# (SOURCE_DATE_EPOCH=0, file mtimes in the Containerfile), and passes
# --provenance=false, so identical inputs give identical digests (design §5).
# The Makefile owns the defaults; reading them here keeps a provisioned VM in
# step with `make images-all`.
mkvar() { make -s --no-print-directory -C "$REPO_ROOT" "print-$1"; }
REV="${HARDENING_REV:-$(mkvar HARDENING_REV)}"
need_rebuild=0
while read -r _ _ _ ref; do
    [ -n "${ref:-}" ] || continue
    docker pull "$ref" >/dev/null 2>&1 || { need_rebuild=1; break; }
done < <(grep -Ev '^\s*(#|$)' "$REPO_ROOT/images/pb-hardened/digests.txt")

if [ "$need_rebuild" = 1 ]; then
    log "image digests are not in the remapped store or the registry; rebuilding the matrix"
    make -C "$REPO_ROOT" image-matrix HARDENING_REV="$REV" || die "image-matrix failed"
    # The upgrade suite's version pair is built by name, not from versions.txt
    # (see images-all in the Makefile).
    for v in "$(mkvar PB_FROM)" "$(mkvar PB_TO)"; do
        make -C "$REPO_ROOT" image PB_VERSION="$v" HARDENING_REV="$REV" || die "image $v failed"
    done
fi

# Only the SELECTED digest per (version, rev, arch) has to be pullable — the
# last matching line, which is what the control plane resolves. Earlier lines
# are history: a superseded build is a record, not something that must still
# exist in the registry.
log "verifying the selected digest for each version is pullable"
ARCH_NAME="$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')"
while read -r ver; do
    ref="$(grep "^$ver h$REV $ARCH_NAME " "$REPO_ROOT/images/pb-hardened/digests.txt" |
           tail -1 | awk '{print $4}')"
    [ -n "$ref" ] || die "no digest recorded for $ver h$REV $ARCH_NAME"
    docker pull "$ref" >/dev/null || \
        die "cannot pull the selected digest for $ver h$REV: $ref"
    log "  ok $ver h$REV $ARCH_NAME"
done < <(grep -Ev '^\s*(#|$)' "$REPO_ROOT/images/pb-hardened/versions.txt")

docker info --format 'runtimes: {{json .Runtimes}}' | grep -q runsc || \
    die "runsc is not registered as a Docker runtime (D2)"

log "host is ready for the control plane"
