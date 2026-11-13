#!/usr/bin/env bash
# §9.4, §9.5, §9.6: the per-grant rule set as
# the control plane writes it, asserted against a LIVE tenant.
#
# 04-egress-proxy.sh builds the datapath by hand to prove the shape works at
# all. This one asserts the shape the control plane actually produced: that the
# accepts carry grant ids, that they sit above every deny, that the tenant's
# default-deny is below every accept, and that nothing else on the egress
# network is reachable.
#
# Run it against a host with a provisioned tenant that holds an active
# egress_host grant:
#
#   SLUG=demo hack/in-vm.sh bash test/netprobe/08-egress-acl.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

SLUG="${SLUG:-demo}"
PB_ROOT="${PB_ROOT:-/srv/citadel}"
STATE_DB="$PB_ROOT/control/state.db"
CONTAINER="pb-$SLUG"
EGRESS_NET="${EGRESS_NET:-v2p-egress}"

# np_cleanup removes only what this suite created and only rules it tagged
# `netprobe` — never the control plane's, which every live tenant shares.
trap np_cleanup EXIT

command -v sqlite3 >/dev/null || np_skip "sqlite3 is needed to read the grant set"
[ -f "$STATE_DB" ] || np_skip "no control-plane database at $STATE_DB"

TENANT_ID="$(sqlite3 "$STATE_DB" "SELECT id FROM tenant WHERE slug='$SLUG'")"
EGRESS_IP="$(sqlite3 "$STATE_DB" "SELECT COALESCE(egress_ip,'') FROM tenant WHERE slug='$SLUG'")"
[ -n "$TENANT_ID" ] || np_skip "no tenant with slug $SLUG; provision one first"
docker inspect "$CONTAINER" >/dev/null 2>&1 || np_skip "$CONTAINER is not running"

log "tenant $TENANT_ID ($SLUG), egress address '${EGRESS_IP:-none}'"

CHAIN="$(iptables -L DOCKER-USER -n --line-numbers)"

# Helpers rather than `bash -c "...$CHAIN..."`: expect_ok runs its argv
# directly, so a function keeps the quoting out of the assertions.
chain_has()   { printf '%s\n' "$CHAIN" | grep -q "$1"; }
inspect_is()  { [ "$(docker inspect -f "$2" "$1")" = "$3" ]; }
attached_to_egress() {
    docker inspect -f '{{json .NetworkSettings.Networks}}' "$CONTAINER" 2>/dev/null |
        grep -q "$EGRESS_NET"
}
binds_docker_sock() {
    docker inspect -f '{{json .HostConfig.Binds}}' "$CONTAINER" | grep -q docker.sock
}
# Memory > 0 first: with no limit at all both fields are 0, and "equal" — so a
# bare equality check passes a container whose memory is unbounded.
swap_disabled() {
    local mem
    mem="$(docker inspect -f '{{.HostConfig.Memory}}' "$CONTAINER")"
    [ "${mem:-0}" -gt 0 ] &&
        [ "$mem" = "$(docker inspect -f '{{.HostConfig.MemorySwap}}' "$CONTAINER")" ]
}

# ── the accepts carry the decision that authorised them (§9.6) ───────────────
GRANTS="$(sqlite3 "$STATE_DB" "
  SELECT id FROM access_grant
   WHERE tenant_id='$TENANT_ID' AND kind='egress_host'
     AND decision IN ('approved','auto_approved') AND revoked_at IS NULL
     AND expires_at > datetime('now')")"

if [ -z "$GRANTS" ]; then

    note "no active egress grant for $SLUG; asserting the default posture instead"
    expect_err "no per-grant accept exists for a tenant with no grant" \
        chain_has "tenant=$TENANT_ID grant="
    expect_err "the tenant is not attached to the egress network" attached_to_egress
    np_summary
fi

for gid in $GRANTS; do

    expect_ok "an accept exists tagged with grant $gid" \
        chain_has "tenant=$TENANT_ID grant=$gid"
done

# ── ordering: every accept above every deny (§9.5, asserted, not read) ───────
first_deny="$(printf '%s' "$CHAIN" | awk '$2=="DROP" {print $1; exit}')"
last_accept="$(printf '%s' "$CHAIN" | awk '$2=="ACCEPT" {n=$1} END {print n}')"
if [ -n "$first_deny" ] && [ -n "$last_accept" ]; then

    if [ "$last_accept" -lt "$first_deny" ]; then

        pass "every ACCEPT sits above the first DROP (line $last_accept < $first_deny)"

    else

        fail "an ACCEPT at line $last_accept sits below the first DROP at $first_deny; it can never match"
    fi
fi

expect_ok "the conntrack accept is present (without it the proxy's replies half-open and die)" \
    chain_has "v2p platform conntrack"

# ── the tenant's own default deny exists and is below the accepts ────────────
if [ -n "$EGRESS_IP" ]; then

    expect_ok "a default-deny exists for the tenant's egress address" \
        chain_has "tenant=$TENANT_ID egress-default-deny"
fi

# ── what the container can actually reach ────────────────────────────────────
# The hardened image has no shell, so reachability is probed from a sidecar on
# the SAME networks rather than from inside the tenant (no exec into a
# live tenant container, ever).
PROXY_IP="$(docker inspect -f \
  "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" citadel-squid 2>/dev/null || true)"

if [ -n "$EGRESS_IP" ] && [ -n "$PROXY_IP" ]; then

    docker run -d --rm --name "${NP_PREFIX}-sidecar" --network "$EGRESS_NET" \
        alpine:3.20 sleep 300 >/dev/null
    SIDE_IP="$(docker inspect -f \
      "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" "${NP_PREFIX}-sidecar")"

    # The sidecar holds no grant, so the platform's unconditional denies are
    # all that stand between it and the world. If THAT is open, every tenant's
    # is too.
    expect_err "an ungranted address on the egress network cannot reach the internet" \
        run_in "${NP_PREFIX}-sidecar" nc -w 3 -z 1.1.1.1 443
    expect_err "cloud metadata is unreachable from the egress network" \
        run_in "${NP_PREFIX}-sidecar" nc -w 3 -z 169.254.169.254 80
    expect_err "the proxy's other ports are unreachable" \
        run_in "${NP_PREFIX}-sidecar" nc -w 3 -z "$PROXY_IP" 22
    note "sidecar at $SIDE_IP, proxy at $PROXY_IP"
fi

# ── published ports and capabilities on the live tenant container ────────────
expect_ok "the tenant publishes no host ports" \
    inspect_is "$CONTAINER" '{{len .HostConfig.PortBindings}}' 0
expect_ok "the tenant has no added capabilities" \
    inspect_is "$CONTAINER" '{{len .HostConfig.CapAdd}}' 0
expect_err "the Docker socket is not mounted into the tenant" binds_docker_sock
expect_ok "the tenant rootfs is read-only" \
    inspect_is "$CONTAINER" '{{.HostConfig.ReadonlyRootfs}}' true
# The configured value, not merely "some": a limit of a million is a limit in
# name only.
expect_ok "the tenant's pids limit is the configured ${PIDS_LIMIT:-128} (a fork bomb is contained, not fatal)" \
    inspect_is "$CONTAINER" '{{.HostConfig.PidsLimit}}' "${PIDS_LIMIT:-128}"
expect_ok "a memory limit is set and swap is disabled (memory-swap equals memory)" swap_disabled

np_summary
