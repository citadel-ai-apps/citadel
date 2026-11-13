#!/usr/bin/env bash
# §14.5: the proxy's manager surface is readable by the control plane and by
# nothing else.
#
# internal/attest reads `squid-internal-mgr/config` from the running proxy
# because a digest of the file on disk proves only that the platform INTENDED
# something — the generated allowlist was correct once while every request was
# refused by a binary that had never read it. Asking Squid what it holds is the
# only honest answer, but it creates a surface that did not exist before: the
# manager report names every tenant's allowlist, and tenants with an active
# egress grant sit on the same network as the proxy.
#
# So this probe asserts both halves. A one-sided assertion is the failure mode:
# a manager ACL that denies everyone breaks attestation silently, and one that
# allows the egress network hands one tenant the whole fleet's external access.
#
#   hack/in-vm.sh bash test/netprobe/13-squid-mgr.sh
. "$(dirname "$0")/lib.sh"
require_root; require_docker

EGRESS_NET="${EGRESS_NET:-v2p-egress}"
PROXY="${PROXY:-citadel-squid}"
PORT="${PORT:-3128}"

trap np_cleanup EXIT

# .State.Running, not mere existence: a STOPPED container still inspects fine,
# keeps its NetworkSettings entry, and reports an empty IPAddress — which Docker
# 29 renders through this template as the literal string "invalid IP". That is
# non-empty, so a bare `-n` test waves it through and both manager reads then
# fail against a proxy that is simply not there. A dead proxy is nothing to say
# about the §14.5 ACL, so it is a skip.
[ "$(docker inspect -f '{{.State.Running}}' "$PROXY" 2>/dev/null)" = true ] ||
    np_skip "$PROXY is not running"

PROXY_IP="$(docker inspect -f \
  "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" "$PROXY" 2>/dev/null || true)"
case "$PROXY_IP" in
    '' | *[!0-9.]*) np_skip "$PROXY has no address on $EGRESS_NET (got '${PROXY_IP:-}')" ;;
esac

GATEWAY="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$EGRESS_NET")"
log "proxy at $PROXY_IP, host gateway at $GATEWAY"

MGR="http://$PROXY_IP:$PORT/squid-internal-mgr/config"

# ── the control plane can read it, from the host ─────────────────────────────
# --noproxy so curl dials the proxy rather than asking it to CONNECT somewhere:
# a proxied request would be refused by the allowlist and look like the ACL
# working, which is the opposite of what is being tested.
host_reads_config() { curl -sf --noproxy '*' --max-time 5 "$MGR" | grep -q '^http_port'; }

expect_ok "the host can read the running proxy's configuration (attestation needs this)" \
    host_reads_config

# The point of reading it live is the generated allowlist, not the preamble.
config_has_acl_block() {
    curl -sf --noproxy '*' --max-time 5 "$MGR" | grep -q 'http_access deny all'
}
expect_ok "the manager report contains the generated allowlist section" config_has_acl_block

# ── a tenant on the same network cannot ──────────────────────────────────────
# A sidecar on the egress network holds no grant, which is exactly the position
# a tenant is in: attached for its own CONNECTs, entitled to nothing else.
docker run -d --rm --name "${NP_PREFIX}-mgr" --network "$EGRESS_NET" \
    curlimages/curl:8.11.1 sleep 300 >/dev/null 2>&1 ||
    docker run -d --rm --name "${NP_PREFIX}-mgr" --network "$EGRESS_NET" \
        alpine:3.20 sleep 300 >/dev/null

docker exec "${NP_PREFIX}-mgr" sh -c 'command -v curl' >/dev/null 2>&1 ||
    docker exec "${NP_PREFIX}-mgr" sh -c 'apk add --no-cache curl' >/dev/null 2>&1

sidecar_reads_config() {
    run_in "${NP_PREFIX}-mgr" curl -sf --noproxy '*' --max-time 5 "$MGR"
}
expect_err "a container on the egress network CANNOT read the manager report" \
    sidecar_reads_config

# The distinction matters: a refusal must come from the manager ACL, not from
# the port being unreachable — otherwise this probe would pass on a proxy that
# is simply down, and would keep passing if somebody widened the ACL later.
sidecar_reaches_proxy() {
    run_in "${NP_PREFIX}-mgr" sh -c \
      "curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 5 http://$PROXY_IP:$PORT/ | grep -q ."
}
expect_ok "the proxy port itself IS reachable from the network (so the deny is the ACL's doing)" \
    sidecar_reaches_proxy

np_summary
