#!/usr/bin/env bash
# §9.4: the proxy filters the ClientHello SNI as well as the CONNECT
# target, and never substitutes a certificate.
#
# Why this probe exists. Filtering the CONNECT target alone is a filter on what
# the client SAYS it wants. A hook can CONNECT to an allowlisted host and then
# negotiate TLS for a different one — the proxy has already spliced the tunnel
# and never looks again. That is domain fronting, and it turns a one-host
# allowlist into "any host reachable from the proxy".
#
# `ssl_bump peek step1` reads the ClientHello; `terminate` at step 2 kills a
# session whose SNI is not on the allowlist; `splice` hands everything else
# through untouched.
#
# The proxy image does carry a certificate and a certgen helper, because Squid
# will not start a port with the `ssl-bump` option without them even when every
# rule is peek/splice/terminate. It is never presented, and the last assertion
# here is what proves that rather than asserting it: the spliced connection has
# to validate against the public roots AND name the real host.
#
# Self-contained — it builds its own proxy rather than asking the control plane
# for one, so it can run against a bare daemon.
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_SUBNET="10.213.2.0/29"
PROXY_IP="10.213.2.3"
CLIENT_IP="10.213.2.4"
SNI_BRIDGE="br-npr-sni"
ALLOWED_DOMAIN="${ALLOWED_DOMAIN:-example.com}"
OTHER_DOMAIN="${OTHER_DOMAIN:-www.google.com}"
# The SAME image the platform runs. Verified that the easily pulled
# distro images ship Squid without --with-openssl and reject `at_step`, so a
# probe with its own default would answer a question about a different binary
# than the one in production. `make egress-image` builds this one.
IMAGE="${EGRESS_PROXY_IMAGE:-v2p-squid:6-r3}"
# The capabilities the platform gives the real proxy. Squid needs them to drop
# privileges and to read the port's certificate; a parse or a run with fewer
# answers a question about a different environment.
CAPS=(--cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE)

cleanup() {
    np_cleanup
    docker rm -f "${NP_PREFIX}-sni-proxy" "${NP_PREFIX}-sni-client" >/dev/null 2>&1
    docker network rm "${NP_PREFIX}-sni-net" >/dev/null 2>&1
    # -rf, not -f: a `docker run -v <path>:...` whose container fails to start
    # leaves <path> behind as a DIRECTORY, and every later run then fails with
    # "not a directory" from the mount rather than anything about squid.
    rm -rf /tmp/npr-sni.conf
}
trap cleanup EXIT
cleanup

cat >/tmp/npr-sni.conf <<EOF
# ssl-bump on the port is what makes Squid consult ssl_bump for a CONNECT at
# all; without it these rules parse and are silently inert. The certificate and
# the helper are startup preconditions of that option, not evidence of bumping.
http_port 3128 ssl-bump tls-cert=/etc/squid/bump.pem
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
acl SSL_ports port 443
acl Safe_ports port 80 443
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

acl step1 at_step SslBump1
# The SNI is not known until step 2. An unqualified terminate-on-not-SNI is
# evaluated at step 1 as well, where the name is unknown, so the negation is
# true and every connection dies - including the allowed ones.
acl step2 at_step SslBump2
ssl_bump peek step1

# Exact host only. Squid rejects a dstdomain list holding both a domain and its
# own wildcard as redundant, and an exact host is what a grant subject is: a
# grant for example.com does not silently cover its subdomains.
acl allowed_dst dstdomain $ALLOWED_DOMAIN
acl allowed_sni ssl::server_name $ALLOWED_DOMAIN
ssl_bump terminate step2 !allowed_sni
ssl_bump splice all

http_access allow allowed_dst
http_access deny all
# Reset a denied request rather than answering it: an error page on an ssl-bump
# port would have to be delivered inside TLS, which means generating a
# certificate for the host just refused.
deny_info TCP_RESET all
access_log stdio:/var/log/squid/access.log
cache deny all
EOF

docker network create --driver bridge --subnet "$EGRESS_SUBNET" \
    -o com.docker.network.bridge.name="$SNI_BRIDGE" "${NP_PREFIX}-sni-net" >/dev/null

# The platform's DOCKER-USER chain denies the RFC1918 ranges unconditionally
# (§9.5), and this probe's own subnet is inside 10.0.0.0/8. Without an
# intra-network accept for THIS bridge the client cannot even reach the proxy,
# and every negative assertion below would pass for the wrong reason — the
# connection failing because netfilter dropped it, not because the SNI filter
# worked.
#
# Pinned to both ends of one bridge, exactly as netpolicy.IntraNetworkRule does,
# and tagged `netprobe` so np_cleanup removes this copy and never the control
# plane's.
iptables -C DOCKER-USER -i "$SNI_BRIDGE" -o "$SNI_BRIDGE" \
    -m comment --comment "netprobe sni-net" -j ACCEPT 2>/dev/null ||
iptables -I DOCKER-USER 1 -i "$SNI_BRIDGE" -o "$SNI_BRIDGE" \
    -m comment --comment "netprobe sni-net" -j ACCEPT

# ── does this build understand ssl_bump at all? ──────────────────────────────
# A squid without --with-openssl parses every other line here and rejects only
# these. Saying so is the point: the platform downgrades to CONNECT-target
# filtering and records the gap rather than pretending the SNI check is on.
#
# The image's own entrypoint, not --entrypoint squid: it generates the
# certificate the ssl-bump port needs to start, then execs squid -N -d 1.
if ! docker run --rm --network none "${CAPS[@]}" \
        -v /tmp/npr-sni.conf:/etc/squid/squid.conf:ro \
        "$IMAGE" -k parse -f /etc/squid/squid.conf >/tmp/npr-sni-parse.log 2>&1; then

    fail "the proxy image $IMAGE does not accept ssl_bump; SNI filtering is NOT in effect"
    note "the platform falls back to CONNECT-target filtering only, and a hook can then"
    note "CONNECT to an allowed host and negotiate TLS for another one"
    grep -iE 'error|fatal' /tmp/npr-sni-parse.log | head -3 | sed 's/^/        /'
    np_summary
fi
pass "the proxy build accepts ssl_bump (peek at step 1; nothing is bumped)"

docker run -d --rm --name "${NP_PREFIX}-sni-proxy" \
    --network "${NP_PREFIX}-sni-net" --ip "$PROXY_IP" "${CAPS[@]}" \
    -v /tmp/npr-sni.conf:/etc/squid/squid.conf:ro \
    "$IMAGE" -f /etc/squid/squid.conf >/dev/null

# openssl s_client is the only way to send a CONNECT for one host and a
# ClientHello for another, which is exactly the attack being tested.
# ca-certificates matters as much as openssl: without a trust store the no-MITM
# assertion below fails for want of roots and says nothing about the proxy.
docker run -d --rm --name "${NP_PREFIX}-sni-client" \
    --network "${NP_PREFIX}-sni-net" --ip "$CLIENT_IP" \
    alpine:3.20 sh -c 'apk add --no-cache openssl ca-certificates >/dev/null 2>&1; sleep 300' >/dev/null

# Long enough for squid to open its port and for apk to finish. A short wait
# here makes every assertion below fail for a reason that is not the proxy's.
sleep 15

# tls_out <connect-host> <sni-host> — one session, as the client saw it.
tls_out() {
    run_in "${NP_PREFIX}-sni-client" sh -c \
        "openssl s_client -connect $1:443 -servername $2 -proxy $PROXY_IP:3128 \
           -verify_return_error -brief </dev/null 2>&1"
}

honest="$(tls_out "$ALLOWED_DOMAIN" "$ALLOWED_DOMAIN")"
fronted="$(tls_out "$ALLOWED_DOMAIN" "$OTHER_DOMAIN")"
denied="$(tls_out "$OTHER_DOMAIN" "$OTHER_DOMAIN")"

# Captured once and asserted on, rather than re-run per assertion: three TLS
# handshakes instead of six, and every assertion then talks about the same
# session it prints on failure.
completed() { printf '%s' "$1" | grep -qi 'protocol version'; }

if completed "$honest"; then

    pass "an honest TLS session to the allowlisted host succeeds"

else

    fail "the allowlisted host is not reachable, so nothing below means anything"
    printf '%s\n' "$honest" | sed 's/^/        /'
fi

# The fronted session is the attack: the CONNECT names an allowed host and the
# ClientHello names another. Squid must kill it at step 2.
if completed "$fronted"; then

    fail "a CONNECT to $ALLOWED_DOMAIN with a ClientHello for $OTHER_DOMAIN COMPLETED"
    printf '%s\n' "$fronted" | sed 's/^/        /'

else

    pass "a CONNECT to the allowlisted host with a ClientHello for $OTHER_DOMAIN is terminated"
fi

if completed "$denied"; then

    fail "a CONNECT to a host with no grant COMPLETED"
    printf '%s\n' "$denied" | sed 's/^/        /'

else

    pass "a CONNECT to a non-allowlisted host is refused outright"
fi

# ── no MITM ─────────────────────────────────────────────────────────────────
# The strongest claim this design makes about the egress path, so it is
# asserted on the certificate the client actually ends up holding, and the
# output is printed on failure: a bare red line would not say whether the proxy
# substituted a certificate or the client merely had no trust store.
if printf '%s' "$honest" | grep -qi 'verification: ok' &&
   printf '%s' "$honest" | grep -qi "peer certificate: CN=$ALLOWED_DOMAIN"; then

    pass "the origin certificate validates and names the real host: nothing was substituted"

else

    fail "the certificate the client received is not the origin's"
    printf '%s\n' "$honest" | sed 's/^/        /'
fi

np_summary
