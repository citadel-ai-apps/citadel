#!/usr/bin/env bash
# INV-13 on the egress bridge: a granted tenant must not reach the host.
#
# The br-t-+ INPUT drop covers tenant bridges. The egress bridge is
# deliberately outside that wildcard, and its gateway is the host, so a tenant
# holding a grant has an interface one hop from every host service. The
# control plane writes an INPUT drop of its own for that bridge, admitting only
# the proxy; this probe asserts it exists and that it works, from a sidecar on
# the egress network standing in for a granted tenant.
#
#   hack/in-vm.sh bash test/netprobe/14-egress-bridge-input.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_NET="${EGRESS_NET:-v2p-egress}"
EGRESS_BRIDGE="${EGRESS_BRIDGE:-br-v2p-egr}"
EDGE_PORT="${EDGE_PORT:-80}"
SRV_PID=""
trap 'np_cleanup; [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null' EXIT

docker network inspect "$EGRESS_NET" >/dev/null 2>&1 ||
    np_skip "no $EGRESS_NET network; nothing has been granted egress yet"

GW="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$EGRESS_NET")"
log "egress bridge $EGRESS_BRIDGE, host at $GW"

input_has() { iptables -S INPUT | grep -q -- "-i $EGRESS_BRIDGE .*v2p platform host-protect=egress"; }
expect_ok "the control plane's INPUT drop for the egress bridge is present" input_has

# A stand-in for a host service bound on every interface.
python3 -m http.server 18098 --bind 0.0.0.0 >/dev/null 2>&1 &
SRV_PID=$!
sleep 1

docker run -d --rm --name "${NP_PREFIX}-granted" --network "$EGRESS_NET" \
    alpine:3.20 sleep 300 >/dev/null

expect_err "a granted tenant cannot reach a host service on the egress gateway" \
    run_in "${NP_PREFIX}-granted" nc -w 3 -z "$GW" 18098
expect_err "a granted tenant cannot reach sshd on the egress gateway" \
    run_in "${NP_PREFIX}-granted" nc -w 3 -z "$GW" 22
# The hair-pin: the host's edge port, DNATed to the edge, from the egress
# bridge. That would reach every tenant by Host header.
expect_err "a granted tenant cannot hair-pin to the edge through the host address" \
    run_in "${NP_PREFIX}-granted" nc -w 3 -z "$GW" "$EDGE_PORT"

np_summary
