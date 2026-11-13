#!/usr/bin/env bash
# Record Docker version (must be >= 28), firewall backend, and capture
# the full ruleset baseline. Output lands in $OUT_DIR (default test/netprobe/out).
. "$(dirname "$0")/lib.sh"
require_root; require_docker

OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")" && pwd)/out}"
mkdir -p "$OUT_DIR"

log "docker / host versions"
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
uname -srm

MAJOR=$(docker version --format '{{.Server.Version}}' | cut -d. -f1)
expect_ok "Docker engine >= 28 (version pinning)" test "$MAJOR" -ge 28

BACKEND=$(docker info --format '{{.FirewallBackend.Driver}}' 2>/dev/null)
log "firewall backend: ${BACKEND:-unknown}"
expect_ok "firewall backend is pinned to iptables" test "$BACKEND" = "iptables"

log "capturing ruleset baseline into $OUT_DIR"
iptables-save  > "$OUT_DIR/iptables-baseline.txt"  2>/dev/null
ip6tables-save > "$OUT_DIR/ip6tables-baseline.txt" 2>/dev/null
nft list ruleset > "$OUT_DIR/nft-baseline.txt" 2>/dev/null || true
docker info > "$OUT_DIR/docker-info.txt" 2>/dev/null

expect_ok "DOCKER-USER chain exists" iptables -L DOCKER-USER -n

# INV-15: --ip-forward-no-drop leaves FORWARD's policy at ACCEPT, so anything
# DOCKER-USER does not match is forwarded. Checked in daemon.json, on the
# running dockerd's command line, and by its effect.
no_forward_drop_flag() {
    ! grep -qE '"ip-forward-no-drop"[[:space:]]*:[[:space:]]*true' /etc/docker/daemon.json 2>/dev/null &&
        ! tr '\0' ' ' </proc/"$(pidof dockerd | cut -d' ' -f1)"/cmdline 2>/dev/null | grep -q -- '--ip-forward-no-drop'
}
expect_ok "dockerd is not run with --ip-forward-no-drop (INV-15)" no_forward_drop_flag
expect_ok "FORWARD's default policy is DROP" bash -c "iptables -S FORWARD | grep -qx -- '-P FORWARD DROP'"
expect_ok "baseline captured" test -s "$OUT_DIR/iptables-baseline.txt"

np_summary
