#!/usr/bin/env bash
# Task 3, route 2 (§9.1, §9.3): can a container on an internal network
# reach the HOST — the bridge gateway IP and services bound on it?
#
# `internal: true` governs traffic routed off the subnet; the gateway address
# is inside the subnet, so assume reachable until proven otherwise. The fix is
# an INPUT rule (DOCKER-USER never sees container→host traffic).
#
# This probe records the BEFORE state as a finding (not a failure), applies
# `iptables -I INPUT -i br-t-+ -j DROP`, and asserts the AFTER state is closed.
. "$(dirname "$0")/lib.sh"
require_root; require_docker
trap 'np_cleanup; kill "$SRV_PID" 2>/dev/null' EXIT
np_cleanup

np_net_create
np_run a
GW=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "${NP_PREFIX}-net")
log "bridge gateway: $GW on $NP_BRIDGE"

# A stand-in for a host service that must never be tenant-reachable
# (control-plane API, SSH, Caddy admin...). Bind on all interfaces, which is
# the common accidental configuration.
python3 -m http.server 18099 --bind 0.0.0.0 >/dev/null 2>&1 &
SRV_PID=$!
sleep 1

log "BEFORE any INPUT rule (finding, recorded either way):"
if run_in "${NP_PREFIX}-a" nc -w 2 -z "$GW" 18099 >/dev/null 2>&1; then
    note "container CAN reach a host service on the gateway IP — INPUT rules are mandatory"
    BEFORE=open
else
    note "container cannot reach the host service even without INPUT rules"
    BEFORE=closed
fi

# Tagged `netprobe`, so np_cleanup removes THIS rule and never the control
# plane's own `v2p platform host-protect` rule, which is shared by every live
# tenant. The two are otherwise byte-identical.
log "applying INPUT drop for tenant bridges (br-t-+)"
iptables  -I INPUT -i br-t-+ -m comment --comment "netprobe host-protect" -j DROP
ip6tables -I INPUT -i br-t-+ -m comment --comment "netprobe host-protect" -j DROP 2>/dev/null || true

expect_err "host service on gateway IP unreachable after INPUT drop" \
    run_in "${NP_PREFIX}-a" nc -w 2 -z "$GW" 18099
expect_err "gateway IP fully closed after INPUT drop (port 22)" \
    run_in "${NP_PREFIX}-a" nc -w 2 -z "$GW" 22

echo
log "finding: before-rule state was: $BEFORE"
np_summary
