#!/usr/bin/env bash
# §9.1 route 3, §9.5: one tenant must not reach another.
#
# This is the escape route the intra-network accept could most easily reopen.
# That rule is pinned to ONE bridge on both sides precisely so it cannot become
# cross-tenant; a wildcard `-i br-t-+ -o br-t-+` would look almost identical and
# would permit exactly what this probe forbids.
#
# Needs two provisioned tenants:
#
#   SLUG_A=demo SLUG_B=other hack/in-vm.sh bash test/netprobe/09-neighbour-scan.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

SLUG_A="${SLUG_A:-demo}"
SLUG_B="${SLUG_B:-other}"
EGRESS_NET="${EGRESS_NET:-v2p-egress}"

trap np_cleanup EXIT

net_of()  { echo "t-$1"; }
ip_of()   { docker inspect -f "{{(index .NetworkSettings.Networks \"$(net_of "$1")\").IPAddress}}" "pb-$1"; }

for s in "$SLUG_A" "$SLUG_B"; do

    docker inspect "pb-$s" >/dev/null 2>&1 ||
        np_skip "tenant pb-$s is not running; this probe needs two tenants (SLUG_A, SLUG_B)"
done

IP_B="$(ip_of "$SLUG_B")"
log "tenant $SLUG_B is at $IP_B on $(net_of "$SLUG_B")"

# A sidecar on A's network stands in for hostile code inside A. The tenant
# image has no shell, so there is nothing to exec into — and the platform forbids
# execing into a live tenant container in any case.
docker run -d --rm --name "${NP_PREFIX}-in-a" --network "$(net_of "$SLUG_A")" \
    alpine:3.20 sleep 300 >/dev/null

expect_err "tenant A cannot reach tenant B's PocketBase port (route 3)" \
    run_in "${NP_PREFIX}-in-a" nc -w 3 -z "$IP_B" 8090
expect_err "tenant A cannot resolve tenant B's container name" \
    run_in "${NP_PREFIX}-in-a" nslookup "pb-$SLUG_B"
expect_err "tenant A cannot reach tenant B's bridge gateway" \
    run_in "${NP_PREFIX}-in-a" nc -w 3 -z "$(docker network inspect -f \
        '{{(index .IPAM.Config 0).Gateway}}' "$(net_of "$SLUG_B")")" 22

# Same question from the shared egress network, which is the one place two
# tenants have addresses on the same bridge. The per-grant accept names the
# PROXY as its only destination, so tenant-to-tenant there must still fail.
if docker network inspect "$EGRESS_NET" >/dev/null 2>&1; then

    EG_B="$(docker inspect -f \
      "{{with index .NetworkSettings.Networks \"$EGRESS_NET\"}}{{.IPAddress}}{{end}}" "pb-$SLUG_B")"
    if [ -n "$EG_B" ]; then

        docker run -d --rm --name "${NP_PREFIX}-in-egress" --network "$EGRESS_NET" \
            alpine:3.20 sleep 300 >/dev/null
        expect_err "a neighbour on the egress network cannot reach tenant B there either" \
            run_in "${NP_PREFIX}-in-egress" nc -w 3 -z "$EG_B" 8090
        note "tenant $SLUG_B holds $EG_B on $EGRESS_NET"

    else

        note "tenant $SLUG_B is not on $EGRESS_NET (no active grant), so there is nothing to scan there"
    fi
fi

np_summary
