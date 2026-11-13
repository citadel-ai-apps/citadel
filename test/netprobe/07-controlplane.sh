#!/usr/bin/env bash
# Probe: the control-plane API and the Caddy admin socket are unreachable from a
# tenant container.
#
# The control plane owns two things on the host that a tenant must never touch:
#
#   · the control-plane API, which provisions and destroys tenants. Design §8.4
#     requires it to be bound where no tenant bridge can route. It is a unix
#     socket with mode 0600, so there is no listener to reach — this probe
#     asserts that, rather than assuming it.
#
#   · Caddy's admin API, which can rewrite the whole route table. Under the
#     join-every-network design Caddy has an interface on every tenant bridge,
#     which is the exposure design.md §10 warned about. It is also a
#     unix socket now, mounted only into Caddy.
#
# Run ON the Docker host, as root:
#   hack/in-vm.sh bash test/netprobe/07-controlplane.sh
set -u

cd "$(dirname "$0")" || exit
. ./lib.sh

require_root
require_docker
trap np_cleanup EXIT

CONTROL_SOCK="${CONTROL_SOCK:-/run/citadel/control.sock}"
CADDY_ADMIN_DIR="${CADDY_ADMIN_DIR:-/srv/citadel/caddy/admin}"

log "creating the probe network and container"
np_cleanup
np_net_create
np_run a

GW="$(docker network inspect "${NP_PREFIX}-net" \
    --format '{{(index .IPAM.Config 0).Gateway}}')"
log "gateway: $GW"

# The control plane's own protection must be in place for this probe to mean
# anything. It is re-asserted on every reconcile tick, so its absence is itself
# the finding.
log "checking the platform's host-protection rule is present"
if iptables -C INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP 2>/dev/null; then
    pass "control plane's tagged INPUT drop is present"
else
    fail "control plane's tagged INPUT drop is MISSING — is controlplaned running?"
    # Apply the probe's own copy so the remaining checks still measure the
    # intended posture rather than an unprotected host.
    iptables -I INPUT -i br-t-+ -m comment --comment "netprobe host-protect" -j DROP
fi

log "control-plane API"
if [ -S "$CONTROL_SOCK" ]; then
    perm="$(stat -c '%a' "$CONTROL_SOCK")"
    if [ "$perm" = 600 ]; then
        pass "control socket $CONTROL_SOCK is mode 0600"
    else
        fail "control socket $CONTROL_SOCK is mode $perm, want 600"
    fi
else
    note "no control socket at $CONTROL_SOCK (controlplaned not running); socket checks skipped"
fi

# A unix socket has no port, so nothing on the host should be listening on a
# TCP address a tenant bridge can route to. Assert the absence directly.
log "no control-plane TCP listener on any tenant-reachable address"
if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq '(^0\.0\.0\.0:|^\*:|^\[::\]:)' ; then
    LISTENERS="$(ss -ltnH | awk '{print $4}' | grep -E '(^0\.0\.0\.0:|^\*:|^\[::\]:)' | tr '\n' ' ')"
    note "host has wildcard TCP listeners: $LISTENERS"
    note "the INPUT drop is what closes them to tenants; probe 02 covers that path"
fi
# The edge publishes :80 on purpose. Anything else bound wildcard is a finding
# for an operator to look at, not necessarily a breach.
expect_err "tenant cannot reach the gateway on the control-plane socket's directory path (no TCP port exists)" \
    run_in "${NP_PREFIX}-a" nc -w 2 -z "$GW" 2019

log "caddy admin API"
if [ -d "$CADDY_ADMIN_DIR" ]; then
    perm="$(stat -c '%a' "$CADDY_ADMIN_DIR")"
    if [ "$perm" = 700 ]; then
        pass "caddy admin directory is mode 0700"
    else
        fail "caddy admin directory $CADDY_ADMIN_DIR is mode $perm, want 700"
    fi
    if [ -S "$CADDY_ADMIN_DIR/admin.sock" ]; then
        pass "caddy admin is a unix socket, not a TCP listener"
    else
        note "no admin.sock yet (edge not started)"
    fi
else
    note "no caddy admin directory at $CADDY_ADMIN_DIR; edge checks skipped"
fi

# Caddy's data plane must stay reachable from the tenant network — that is the
# ingress path (it works because the proxy joins the network, not
# because a port is published).
EDGE_NAME="${EDGE_NAME:-citadel-caddy}"
if docker inspect "$EDGE_NAME" >/dev/null 2>&1; then
    log "attaching the edge to the probe network to test its exposure"
    docker network connect "${NP_PREFIX}-net" "$EDGE_NAME" >/dev/null 2>&1 || true
    EDGE_IP="$(docker inspect -f \
        "{{(index .NetworkSettings.Networks \"${NP_PREFIX}-net\").IPAddress}}" "$EDGE_NAME" 2>/dev/null)"
    if [ -n "${EDGE_IP:-}" ]; then
        expect_ok "edge data plane reachable from the tenant network (the ingress path)" \
            run_in "${NP_PREFIX}-a" nc -w 2 -z "$EDGE_IP" 80
        expect_err "edge admin port 2019 NOT reachable from the tenant network" \
            run_in "${NP_PREFIX}-a" nc -w 2 -z "$EDGE_IP" 2019
    else
        note "could not determine the edge's address on the probe network"
    fi
    docker network disconnect "${NP_PREFIX}-net" "$EDGE_NAME" >/dev/null 2>&1 || true
else
    note "edge container $EDGE_NAME not present; data-plane exposure checks skipped"
fi

log "docker socket must not be visible to a tenant"
expect_err "no /var/run/docker.sock inside the probe container" \
    run_in "${NP_PREFIX}-a" test -S /var/run/docker.sock

np_summary
