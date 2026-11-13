#!/usr/bin/env bash
# §9.4: the egress path. A tenant that has an approved
# egress grant joins a second, non-internal network containing only the forward
# proxy. DOCKER-USER rules make the proxy the ONLY reachable destination.
#
# Asserts: allowed domain works via CONNECT; denied domain is refused by the
# proxy; a raw socket that ignores HTTP_PROXY is dropped by netfilter.
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_SUBNET="10.213.1.0/29"
PROXY_IP="10.213.1.3"
TENANT_IP="10.213.1.4"
ALLOWED_DOMAIN="${ALLOWED_DOMAIN:-example.com}"
DENIED_DOMAIN="${DENIED_DOMAIN:-www.google.com}"

cleanup() {
    np_cleanup
    rm -rf /tmp/npr-squid.conf
}
trap cleanup EXIT
cleanup

# Tenant's own internal network, plus the shared egress network (non-internal:
# the proxy needs an outbound path). Bridge name deliberately NOT br-t-* — the
# egress bridge is platform infra, not a tenant bridge.
np_net_create
docker network create --driver bridge --subnet "$EGRESS_SUBNET" \
    -o com.docker.network.bridge.name="br-npr-egress" "${NP_PREFIX}-egress" >/dev/null

# Written here rather than rendered from internal/egressctl/squid.conf.tmpl.
#
# That template is a Go template embedded in the control plane, and this probe
# has to run standalone against a bare daemon with no control plane present —
# that independence is the point: a probe that asked the platform to generate
# its own test input would only prove the platform agrees with itself.
# 10-sni-mismatch.sh covers the SNI half of the real configuration.
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
EOF

docker run -d --rm --name "${NP_PREFIX}-squid" \
    --network "${NP_PREFIX}-egress" --ip "$PROXY_IP" \
    -v /tmp/npr-squid.conf:/etc/squid/squid.conf:ro \
    "${EGRESS_PROXY_IMAGE:-v2p-squid:6-r2}" -f /etc/squid/squid.conf >/dev/null

np_run tenant
docker network connect --ip "$TENANT_IP" "${NP_PREFIX}-egress" "${NP_PREFIX}-tenant"

# §9.4 rules: ACCEPT to the proxy port, then DROP everything else from the
# tenant's egress-network address. Comment-tagged (§9.6) — in production the
# tag carries the grant ID.
iptables -I DOCKER-USER 1 -s "$TENANT_IP" -d "$PROXY_IP" -p tcp --dport 3128 \
    -m comment --comment "netprobe tenant=npr grant=test" -j ACCEPT
iptables -I DOCKER-USER 2 -s "$TENANT_IP" \
    -m comment --comment "netprobe tenant=npr" -j DROP

sleep 2   # squid start

# connect_via_proxy <host> — speak raw CONNECT; succeed only on "200".
connect_via_proxy() {
    run_in "${NP_PREFIX}-tenant" sh -c \
        "printf 'CONNECT $1:443 HTTP/1.1\r\nHost: $1:443\r\n\r\n' | nc -w 5 $PROXY_IP 3128 | head -1 | grep -q ' 200 '"
}

expect_ok  "allowed domain ($ALLOWED_DOMAIN) connects through the proxy" \
    connect_via_proxy "$ALLOWED_DOMAIN"
expect_err "denied domain ($DENIED_DOMAIN) is refused by the proxy" \
    connect_via_proxy "$DENIED_DOMAIN"

# a raw socket that ignores HTTP_PROXY must be dropped by netfilter,
# not merely inconvenienced.
expect_err "raw socket to 1.1.1.1:443 is dropped" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z 1.1.1.1 443
expect_err "raw socket to another egress-net port on the proxy is dropped" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z "$PROXY_IP" 22
expect_err "cloud metadata unreachable from the egress network" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z 169.254.169.254 80

np_summary
