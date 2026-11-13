#!/usr/bin/env bash
# §9.1 route 3, through the edge: tenant A must not reach tenant B by asking
# the edge for B's hostname.
#
# The edge joins every tenant network and routes by Host header. 09 proves A
# cannot reach B's container directly; this proves A cannot reach it through
# the edge either — nor anything else the edge serves, A's own route included.
#
# Two layers, and which one holds depends on the host:
#
#   - With br_netfilter loaded, same-bridge traffic crosses FORWARD and the
#     tenant's intra-network accept admits only the edge dialling the tenant,
#     so A cannot even open a connection to the edge.
#   - Without it (Docker 29 does not load it), same-bridge traffic never meets
#     iptables at all, and A CAN connect. The edge's tenant routes then refuse
#     every client address in the tenant pool, and the request falls through to
#     the catch-all 404. That answer is asserted positively below: a request
#     that merely failed would prove nothing.
#
#   SLUG_A=demo SLUG_B=other hack/in-vm.sh bash test/netprobe/15-edge-hairpin.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

SLUG_A="${SLUG_A:-demo}"
SLUG_B="${SLUG_B:-other}"
EDGE="${EDGE:-citadel-caddy}"
PB_ROOT="${PB_ROOT:-/srv/citadel}"
STATE_DB="$PB_ROOT/control/state.db"

trap np_cleanup EXIT

for s in "$SLUG_A" "$SLUG_B"; do

    docker inspect "pb-$s" >/dev/null 2>&1 ||
        np_skip "tenant pb-$s is not running; this probe needs two tenants (SLUG_A, SLUG_B)"
done
docker inspect "$EDGE" >/dev/null 2>&1 || np_skip "no edge container $EDGE"
command -v sqlite3 >/dev/null || np_skip "sqlite3 is needed to read the tenants' hostnames"

hostname_of() { sqlite3 "$STATE_DB" "SELECT hostname FROM tenant WHERE slug='$1'"; }
HOST_A="$(hostname_of "$SLUG_A")"
HOST_B="$(hostname_of "$SLUG_B")"
EDGE_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"t-$SLUG_A\").IPAddress}}" "$EDGE")"
[ -n "$EDGE_IP" ] || np_skip "the edge is not attached to t-$SLUG_A"
log "edge at $EDGE_IP on t-$SLUG_A"

# curl rather than busybox wget: the refusal is asserted by the catch-all's
# body, and wget prints no body for a 404.
docker run -d --rm --name "${NP_PREFIX}-in-a" --network "t-$SLUG_A" \
    --entrypoint sleep "${CURL_IMAGE:-curlimages/curl:8.11.1}" 300 >/dev/null

if [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] &&
   [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 1 ]; then

    expect_err "tenant A cannot open a connection to the edge on its own bridge" \
        run_in "${NP_PREFIX}-in-a" curl -s -o /dev/null -m 3 "http://$EDGE_IP/"

else

    note "br_netfilter is not loaded: same-bridge traffic is not filtered on this host,"
    note "so the edge's refusal of tenant client addresses is the boundary"
fi

# edge_refuses <host> — the edge either took no connection from tenant A, or
# answered it with the catch-all ("no such app"), never with a tenant.
edge_refuses() {
    local out code
    out="$(run_in "${NP_PREFIX}-in-a" curl -s -m 5 -w '\n%{http_code}' -H "Host: $1" "http://$EDGE_IP/")"
    code="$(printf '%s' "$out" | tail -1)"
    [ "$code" = 000 ] && return 0                     # no connection at all
    [ "$code" = 404 ] && printf '%s' "$out" | grep -q 'no such app'
}

expect_ok "the edge refuses tenant A a route to tenant B ($HOST_B)" edge_refuses "$HOST_B"
expect_ok "the edge refuses tenant A even its own route ($HOST_A)" edge_refuses "$HOST_A"

# The sanctioned path still works: a client off the tenant networks.
expect_ok "ingress through the edge still reaches tenant A" \
    curl -sf -o /dev/null -m 5 -H "Host: $HOST_A" http://127.0.0.1/api/health

np_summary
