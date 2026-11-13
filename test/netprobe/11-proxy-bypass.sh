#!/usr/bin/env bash
# HTTP_PROXY is ergonomics, not enforcement; the netfilter DROP is the
# boundary.
#
# Every tenant container gets HTTP_PROXY/HTTPS_PROXY pointing at the egress
# proxy, because PocketBase's $http.send goes through Go's http.Client and
# honours ProxyFromEnvironment — a cooperating hook then works with no code
# change. A hostile hook opens a raw socket and ignores the variable entirely.
#
# This probe is the one that keeps those two facts from being conflated in
# review: it ignores the environment completely and asserts that the packets
# still do not leave.
#
#   SLUG=demo hack/in-vm.sh bash test/netprobe/11-proxy-bypass.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

SLUG="${SLUG:-demo}"
EGRESS_NET="${EGRESS_NET:-v2p-egress}"
CONTAINER="pb-$SLUG"

trap np_cleanup EXIT

docker inspect "$CONTAINER" >/dev/null 2>&1 ||
    np_skip "tenant $CONTAINER is not running; provision one first"

# The variables ARE set, and that is fine — the point is that they are not what
# is doing the work.
env_has_proxy() { docker inspect -f '{{json .Config.Env}}' "$CONTAINER" | grep -q HTTP_PROXY; }
expect_ok "the tenant has HTTP_PROXY set (ergonomics for a cooperating hook)" env_has_proxy

EG_IP="$(docker inspect -f \
  "{{with index .NetworkSettings.Networks \"$EGRESS_NET\"}}{{.IPAddress}}{{end}}" "$CONTAINER")"
if [ -z "$EG_IP" ]; then

    note "$SLUG holds no active grant, so it is not on $EGRESS_NET at all"
    note "the default posture is an internal:true network with no outbound path"
    docker run -d --rm --name "${NP_PREFIX}-bypass" --network "t-$SLUG" \
        alpine:3.20 sleep 300 >/dev/null
    expect_err "a raw socket to a public IP from the tenant network is dropped" \
        run_in "${NP_PREFIX}-bypass" nc -w 3 -z 1.1.1.1 443
    expect_err "a raw socket to cloud metadata is dropped" \
        run_in "${NP_PREFIX}-bypass" nc -w 3 -z 169.254.169.254 80
    np_summary
fi

# On the egress network, with a grant, and STILL only the proxy port is
# reachable. The accept names one destination and one port; everything else
# from this source address hits the tenant's own default deny.
PROXY_PORT="${PROXY_PORT:-3128}"
PROXY_IP="$(docker inspect -f \
  "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" citadel-squid)"

docker run -d --rm --name "${NP_PREFIX}-bypass" --network "$EGRESS_NET" \
    alpine:3.20 sleep 300 >/dev/null

expect_err "a raw socket to a public IP is dropped despite HTTP_PROXY being set" \
    run_in "${NP_PREFIX}-bypass" nc -w 3 -z 1.1.1.1 443
expect_err "a raw socket to a public IP on port 80 is dropped" \
    run_in "${NP_PREFIX}-bypass" nc -w 3 -z 1.1.1.1 80
expect_err "cloud metadata is unreachable from the egress network" \
    run_in "${NP_PREFIX}-bypass" nc -w 3 -z 169.254.169.254 80
expect_err "an SMTP port is unreachable, so the platform is not a spam relay" \
    run_in "${NP_PREFIX}-bypass" nc -w 3 -z 1.1.1.1 25
expect_err "the proxy's non-proxy ports are unreachable" \
    run_in "${NP_PREFIX}-bypass" nc -w 3 -z "$PROXY_IP" 22

note "tenant egress address $EG_IP, proxy $PROXY_IP:$PROXY_PORT"
np_summary
