#!/usr/bin/env bash
# Task 2: an `internal: true` network must allow intra-network traffic and
# nothing else — no internet, no external name resolution (§9.2).
. "$(dirname "$0")/lib.sh"
require_root; require_docker
trap np_cleanup EXIT
np_cleanup

np_net_create
np_run a
np_run b
IP_B=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${NP_PREFIX}-b")

# Intra-network traffic must work (this is how the edge proxy reaches tenants).
run_in "${NP_PREFIX}-b" nc -l -p 8090 -e /bin/true >/dev/null 2>&1 &
sleep 1
expect_ok  "peer container reachable on the internal network" \
    run_in "${NP_PREFIX}-a" nc -w 2 -z "$IP_B" 8090

# No outbound path: TCP to a public IP must fail (route 1).
expect_err "internet by IP is unreachable (1.1.1.1:443)" \
    run_in "${NP_PREFIX}-a" nc -w 3 -z 1.1.1.1 443
expect_err "internet by IP is unreachable (8.8.8.8:53/tcp)" \
    run_in "${NP_PREFIX}-a" nc -w 3 -z 8.8.8.8 53

# No external name resolution (also covered in depth by 03-dns-covert.sh).
expect_err "external DNS name does not resolve" \
    run_in "${NP_PREFIX}-a" nslookup -timeout=3 example.com

# Cloud metadata endpoint (route 4) — must be unreachable even here.
expect_err "cloud metadata 169.254.169.254 is unreachable" \
    run_in "${NP_PREFIX}-a" nc -w 3 -z 169.254.169.254 80

np_summary
