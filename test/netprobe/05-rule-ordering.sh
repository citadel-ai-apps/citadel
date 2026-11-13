#!/usr/bin/env bash
# Task 8 (§9.5): the RFC1918/metadata denies interact with the tenant→proxy
# ACCEPT. The egress subnet lives inside a denied private range, so ordering is
# load-bearing: denies ABOVE the accept silently break egress; the accept must
# come first. This probe deliberately applies the wrong order once, records the
# failure mode, then asserts the correct order works.
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_SUBNET="10.213.1.0/29"
PROXY_IP="10.213.1.3"
TENANT_IP="10.213.1.4"
ALLOWED_DOMAIN="${ALLOWED_DOMAIN:-example.com}"

wipe_rules() {
    while read -r n; do iptables -D DOCKER-USER "$n" 2>/dev/null || true; done < <(
        iptables -L DOCKER-USER --line-numbers -n 2>/dev/null |
        grep "netprobe" | awk '{print $1}' | sort -rn)
}
cleanup() { wipe_rules; np_cleanup; rm -rf /tmp/npr-squid.conf; }
trap cleanup EXIT
cleanup

np_net_create
docker network create --driver bridge --subnet "$EGRESS_SUBNET" \
    -o com.docker.network.bridge.name="br-npr-egress" "${NP_PREFIX}-egress" >/dev/null
# Written here rather than rendered from internal/egressctl/squid.conf.tmpl.
#
# This probe is about RULE ORDER, not about the proxy: it needs a proxy that
# answers, and nothing more. Keeping its own minimal config means it runs
# against a bare daemon with no control plane present, and a change to the
# platform's allowlist template can never make an ordering probe fail for a
# reason that has nothing to do with ordering.
cat >/tmp/npr-squid.conf <<EOF
http_port 3128
acl SSL_ports port 443
acl Safe_ports port 80 443
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
acl tenant_npr_src src $TENANT_IP
acl tenant_npr_dst dstdomain .$ALLOWED_DOMAIN
http_access allow tenant_npr_src tenant_npr_dst
http_access deny all
access_log stdio:/var/log/squid/access.log
cache deny all
# STEP 2 makes Squid's OWN dns lookups fail (see there). Squid caches that, and
# the default 60s would still be in force when STEP 3 asserts the opposite.
negative_dns_ttl 1 seconds
EOF
start_squid() {
    docker rm -f "${NP_PREFIX}-squid" >/dev/null 2>&1 || true
    docker run -d --rm --name "${NP_PREFIX}-squid" \
        --network "${NP_PREFIX}-egress" --ip "$PROXY_IP" \
        -v /tmp/npr-squid.conf:/etc/squid/squid.conf:ro \
        "${EGRESS_PROXY_IMAGE:-v2p-squid:6-r2}" \
        -f /etc/squid/squid.conf >/dev/null
    for _ in $(seq 1 20); do
        docker logs "${NP_PREFIX}-squid" 2>&1 | grep -q "Accepting HTTP Socket" && return 0
        sleep 0.5
    done
    return 0
}
start_squid
np_run tenant
docker network connect --ip "$TENANT_IP" "${NP_PREFIX}-egress" "${NP_PREFIX}-tenant"
sleep 2

connect_via_proxy() {
    run_in "${NP_PREFIX}-tenant" sh -c \
        "printf 'CONNECT $1:443 HTTP/1.1\r\nHost: $1:443\r\n\r\n' | nc -w 5 $PROXY_IP 3128 | head -1 | grep -q ' 200 '"
}

add_denies_at_top() {
    # §9.5 unconditional denies, inserted at position 1 (top).
    for cidr in 172.16.0.0/12 192.168.0.0/16 10.0.0.0/8 169.254.0.0/16; do
        iptables -I DOCKER-USER 1 -d "$cidr" -m comment --comment "netprobe deny" -j DROP
    done
}
add_accept_at_top() {
    iptables -I DOCKER-USER 1 -s "$TENANT_IP" -d "$PROXY_IP" -p tcp --dport 3128 \
        -m comment --comment "netprobe accept" -j ACCEPT
}

log "STEP 1 — deliberately wrong order: denies above the accept"
add_denies_at_top
iptables -A DOCKER-USER -s "$TENANT_IP" -d "$PROXY_IP" -p tcp --dport 3128 \
    -m comment --comment "netprobe accept" -j ACCEPT   # append: lands BELOW denies
if connect_via_proxy "$ALLOWED_DOMAIN"; then
    fail "egress still works with denies above the accept — probe assumption broken"
else
    pass "wrong order observed: 10.0.0.0/8 deny swallows tenant→proxy (silent egress break)"
fi

log "STEP 2 — accept above the denies, but NO conntrack rule"
# Finding from this probe: the outbound accept alone is NOT enough. The §9.5
# denies match the REPLY direction too (proxy→tenant has dst inside 10/8), and
# DOCKER-USER runs before Docker's own established-connection accepts.
#
# Second finding, from this probe failing on a host whose proxy resolves names
# over the network: the reply path the conntrack rule rescues is not only
# proxy→tenant. The PROXY'S OWN DNS replies come back to an address inside
# 10/8 too, so without the conntrack accept Squid cannot resolve anything
# either, and answers 503 ERR_DNS_FAIL rather than timing out on the origin.
# One missing rule breaks the path in two places, not one.
wipe_rules
add_denies_at_top
add_accept_at_top
if connect_via_proxy "$ALLOWED_DOMAIN"; then
    fail "egress worked without a conntrack rule — reply-path assumption broken"
else
    pass "reply path is swallowed by the denies without a conntrack accept (finding)"
fi

log "STEP 3 — verified-correct shape: established accept, then tenant accept, then denies"
wipe_rules
add_denies_at_top
add_accept_at_top
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "netprobe conntrack" -j ACCEPT
# The rules are right from here on, but Squid is still carrying the DNS failure
# STEP 2 caused it. Restart it so this step measures the ruleset and not the
# previous step's wreckage — a fresh proxy has an empty cache, which no TTL
# makes this deterministic.
start_squid
expect_ok  "egress works with conntrack accept above accept above denies" \
    connect_via_proxy "$ALLOWED_DOMAIN"
expect_err "RFC1918 addresses beyond the proxy are still denied (192.168.1.1:80)" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z 192.168.1.1 80
expect_err "metadata endpoint is still denied" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z 169.254.169.254 80

log "finding: assert rule ORDER programmatically (accept line number < first deny), not just presence"
np_summary
