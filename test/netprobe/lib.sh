# shellcheck shell=bash
# Shared helpers for the netprobe suite. Source from every probe script.
#
# Every probe runs ON the Docker host (root). In development the host is the UTM
# VM (hack/vm/README.md); invoke a probe from the Mac with:
#
#   hack/in-vm.sh bash test/netprobe/01-internal-isolation.sh
#
# or the whole suite with `make netprobe`, which runs run-all.sh: it provisions
# the two tenants 08 and 09 need and passes them in as SLUG/SLUG_A/SLUG_B. A
# probe run on its own takes those from the environment.
#
# A probe exits 0 when the security posture holds and non-zero when an escape
# or misconfiguration is detected. Probes clean up everything they create.

set -u

NP_PREFIX="npr"                  # every network/container we create is ${NP_PREFIX}-*
NP_FAILS=0
NP_SUBNET="${NP_SUBNET:-10.213.0.0/29}"
NP_BRIDGE="${NP_BRIDGE:-br-t-npr}"

log()  { printf '%s %s\n' "[$(date +%H:%M:%S)]" "$*"; }
note() { printf '    NOTE: %s\n' "$*"; }

# np_skip <reason> — a probe whose preconditions are absent has found no hole,
# so it exits 0 with the reason stated. The alternative, exiting non-zero,
# makes "we did not run this" indistinguishable from "the posture failed", and
# the whole point of this suite is that the two never look alike.
np_skip() { printf '    \033[33mSKIP\033[0m %s\n' "$*"; exit 0; }

pass() { printf '    PASS: %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*"; NP_FAILS=$((NP_FAILS + 1)); }

# expect_ok  <description> <cmd...>   — posture holds when the command succeeds
# expect_err <description> <cmd...>   — posture holds when the command fails
expect_ok()  { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
expect_err() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }

# run_in <container> <cmd...> — exec in a probe container
run_in() { local c="$1"; shift; docker exec "$c" "$@"; }

require_root()   { [ "$(id -u)" = 0 ] || { echo "must run as root on the Docker host" >&2; exit 2; }; }
require_docker() { docker info >/dev/null 2>&1 || { echo "docker daemon unreachable" >&2; exit 2; }; }

# Create the standard probe network: internal, fixed subnet, predictable bridge
# name so INPUT rules can match br-t-+ (§9.2).
np_net_create() {
    docker network create \
        --driver bridge \
        --internal \
        --subnet "$NP_SUBNET" \
        -o com.docker.network.bridge.name="$NP_BRIDGE" \
        "${NP_PREFIX}-net" >/dev/null

    # Reproduce the platform's intra-network accept for THIS bridge.
    #
    # The control plane's DOCKER-USER chain denies the RFC1918 ranges
    # unconditionally (§9.5), and a probe network's own subnet is inside
    # one of them. Same-bridge container traffic traverses FORWARD, so without
    # this rule the deny swallows container-to-container traffic on the probe
    # network — and probes that assert the sanctioned ingress path works would
    # fail for a reason that has nothing to do with what they are testing.
    #
    # Pinned to both ends of one bridge, exactly as netpolicy.IntraNetworkRule
    # does, and tagged `netprobe` so np_cleanup removes this copy and never the
    # control plane's.
    iptables -C DOCKER-USER -i "$NP_BRIDGE" -o "$NP_BRIDGE" \
        -m comment --comment "netprobe intra-network" -j ACCEPT 2>/dev/null ||
    iptables -I DOCKER-USER 1 -i "$NP_BRIDGE" -o "$NP_BRIDGE" \
        -m comment --comment "netprobe intra-network" -j ACCEPT
}

# np_run <name-suffix> [docker run args...] — alpine container on the probe
# network with the tools the probes need (nc, nslookup via busybox).
np_run() {
    local name="${NP_PREFIX}-$1"; shift
    docker run -d --rm --name "$name" --network "${NP_PREFIX}-net" "$@" \
        alpine:3.20 sleep 600 >/dev/null
}

np_cleanup() {
    docker ps -aq --filter "name=^/${NP_PREFIX}-" | xargs -r docker rm -f >/dev/null 2>&1
    docker network ls -q --filter "name=^${NP_PREFIX}-" | xargs -r docker network rm >/dev/null 2>&1

    # Remove ONLY rules this suite tagged, matched by comment.
    #
    # This used to delete `INPUT -i br-t-+ -j DROP` unconditionally, which is
    # the platform's own host-protection rule shared by every live
    # tenant — so running any probe's teardown stripped host protection from
    # the whole fleet. The control plane now tags its rules `v2p platform
    # host-protect` and this suite tags its own `netprobe …`, so the two are
    # distinguishable. Never delete an untagged rule from a shared chain.
    for chain in INPUT DOCKER-USER; do
        for ipt in iptables ip6tables; do
            while read -r n; do
                "$ipt" -D "$chain" "$n" 2>/dev/null || true
            done < <("$ipt" -L "$chain" --line-numbers -n 2>/dev/null |
                     grep -F "netprobe" | awk '{print $1}' | sort -rn)
        done
    done
}

np_summary() {
    echo
    if [ "$NP_FAILS" -eq 0 ]; then
        log "RESULT: all checks passed"
        exit 0
    else
        log "RESULT: $NP_FAILS check(s) FAILED"
        exit 1
    fi
}
