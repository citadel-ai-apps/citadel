#!/usr/bin/env bash
# Task 6 (§10): once Caddy joins a tenant network, its admin API must NOT be
# reachable from that network. Caddy binds admin to localhost:2019 by default;
# this probe proves that holds on the tenant-facing interface, and that the
# data plane (port 80) IS reachable — so an "unreachable admin" result cannot
# be explained by broken connectivity.
. "$(dirname "$0")/lib.sh"
require_root; require_docker
trap np_cleanup EXIT
np_cleanup

np_net_create
# The stock caddy image serves a static page on :80 with the admin API on
# localhost:2019 — the same defaults the platform will rely on.
docker run -d --rm --name "${NP_PREFIX}-caddy" --network "${NP_PREFIX}-net" \
    caddy:2 >/dev/null
np_run tenant
sleep 3

CADDY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${NP_PREFIX}-caddy")
log "caddy at $CADDY_IP on the tenant network"

expect_ok  "caddy data plane (:80) reachable from the tenant container" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z "$CADDY_IP" 80
expect_err "caddy admin API (:2019) NOT reachable from the tenant container" \
    run_in "${NP_PREFIX}-tenant" nc -w 3 -z "$CADDY_IP" 2019

# Belt and braces: the admin socket answers on localhost inside the caddy
# container, proving the API is up and the block above is real.
expect_ok  "admin API is alive on localhost inside the caddy container" \
    docker exec "${NP_PREFIX}-caddy" wget -q -T 3 -O /dev/null http://127.0.0.1:2019/config/

np_summary
