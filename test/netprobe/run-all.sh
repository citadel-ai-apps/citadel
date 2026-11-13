#!/usr/bin/env bash
# The whole netprobe suite against live tenants. Run ON the Docker host, as root.
#
# Most probes build their own networks, but 08-egress-acl and 09-neighbour-scan
# assert what the control plane produced for REAL tenants — and with none
# provisioned they could only skip. A skipped probe has found no hole, which is
# not the same as having looked, so this runner provisions two throwaway tenants
# first:
#
#   SLUG_EGRESS  deploys test/redteam/egress-probe, whose manifest host is
#                Tier-1 auto-granted — so 08 checks the per-grant rules, not
#                the no-grant fallback
#   SLUG_PLAIN   deploys test/fixtures/pkg-basic — the neighbour 09 scans for
#
# A control plane already listening on $SOCK is reused and left running;
# otherwise one is started for the run and stopped afterwards.
#
# Usage: test/netprobe/run-all.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG_EGRESS="${SLUG_EGRESS:-npegr}"
SLUG_PLAIN="${SLUG_PLAIN:-npplain}"
PB_VERSION="${PB_VERSION:-0.42.2}"
OWNER="${OWNER:-person:netprobe}"
PB_ROOT="${PB_ROOT:-/srv/citadel}"
STATE_DB="$PB_ROOT/control/state.db"
SOCK="${SOCK:-/run/citadel/control.sock}"
# Tenants are served as <slug>.$APPS_DOMAIN. nip.io resolves any name that
# embeds an IP to that IP, so a browser on the Mac reaches the VM directly. The
# suite itself never relies on DNS: it sends a Host header to 127.0.0.1.
VM_IP="${VM_IP:-$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)}"
APPS_DOMAIN="${APPS_DOMAIN:-apps.$VM_IP.nip.io}"
DAEMON=bin/controlplaned
CITADEL=bin/citadel
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

DAEMON_PID=""
LOG=/tmp/netprobe-controlplaned.log
CONF=/tmp/netprobe-config.json
WORK="$(mktemp -d /tmp/netprobe-pkgs.XXXXXX)"

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[31mabort: %s\033[0m\n' "$*" >&2; exit 2; }

[ "$(id -u)" = 0 ] || die "must run as root on the Docker host"
[ -x "$DAEMON" ] || die "$DAEMON not built; run 'make build' on the Mac first"
[ -x "$CITADEL" ]  || die "$CITADEL not built; run 'make build' on the Mac first"
command -v sqlite3 >/dev/null || die "sqlite3 is needed to read the state database"
command -v python3 >/dev/null || die "python3 is needed to build the package zips"

citadel() { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }
pack()  { python3 hack/pack.py "$1" "$WORK/$2.zip"; }

start_daemon() {
    cat >"$CONF" <<EOF
{
  "pb_root": "$PB_ROOT",
  "socket_path": "$SOCK",
  "apps_domain": "$APPS_DOMAIN",
  "portal_addr": ""
}
EOF
    "$DAEMON" --config "$CONF" --seed-digests images/pb-hardened/digests.txt >"$LOG" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 60); do
        [ -S "$SOCK" ] && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$LOG"; die "controlplaned exited at start-up"; }
        sleep 0.5
    done
    cat "$LOG"; die "controlplaned did not open $SOCK"
}

stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    DAEMON_PID=""
}

cleanup() {
    if [ "$KEEP" = 1 ]; then
        note "--keep: leaving $SLUG_EGRESS, $SLUG_PLAIN and the daemon (pid ${DAEMON_PID:-reused}) running"
        return
    fi
    for s in "$SLUG_EGRESS" "$SLUG_PLAIN"; do
        citadel tenant destroy "$s" --no-backup --purge >/dev/null 2>&1
    done
    # Teardown happens on the reconcile tick; stopping the daemon before the
    # rows go leaves them behind, and the next run cannot provision the same
    # slugs. Only OUR rows are waited for: a reused daemon may host others.
    for _ in $(seq 1 40); do
        [ "$(sqlite3 "$STATE_DB" \
              "SELECT COUNT(*) FROM tenant WHERE slug IN ('$SLUG_EGRESS','$SLUG_PLAIN')" \
              2>/dev/null)" = 0 ] && break
        sleep 1
    done
    stop_daemon
    rm -rf "$WORK"
}
trap cleanup EXIT

running() { [ "$(docker inspect -f '{{.State.Running}}' "pb-$1" 2>/dev/null)" = true ]; }
egress_ip() { sqlite3 "$STATE_DB" "SELECT COALESCE(egress_ip,'') FROM tenant WHERE slug='$1'"; }

# ── the platform and two tenants ─────────────────────────────────────────────
log "provisioning $SLUG_EGRESS and $SLUG_PLAIN"
if [ -S "$SOCK" ] && citadel tenant list >/dev/null 2>&1; then
    note "reusing the control plane already listening on $SOCK"
else
    start_daemon
fi
citadel principal create "$OWNER" --name "Netprobe" >/dev/null 2>&1

pack test/redteam/egress-probe egress-probe
pack test/fixtures/pkg-basic pkg-basic

citadel tenant create --slug "$SLUG_EGRESS" --pb-version "$PB_VERSION" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG_EGRESS"
citadel release upload "$SLUG_EGRESS" --file "$WORK/egress-probe.zip" --deploy >/dev/null ||
    die "the egress-probe package did not deploy to $SLUG_EGRESS"
citadel tenant create --slug "$SLUG_PLAIN" --pb-version "$PB_VERSION" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG_PLAIN"
citadel release upload "$SLUG_PLAIN" --file "$WORK/pkg-basic.zip" --deploy >/dev/null ||
    die "the baseline package did not deploy to $SLUG_PLAIN"

# The grant's rules and the egress attachment land on a reconcile tick, not
# with the deploy; probing before then would assert the no-grant posture.
ready=0
for _ in $(seq 1 60); do
    if running "$SLUG_EGRESS" && running "$SLUG_PLAIN" && [ -n "$(egress_ip "$SLUG_EGRESS")" ]; then
        ready=1; break
    fi
    sleep 1
done
[ "$ready" = 1 ] || die "the tenants did not come up with an egress address for $SLUG_EGRESS"
note "$SLUG_EGRESS holds $(egress_ip "$SLUG_EGRESS") on the egress network"

# ── the probes ───────────────────────────────────────────────────────────────
# Each probe runs even after one fails — a partial picture of the network
# posture is the least useful kind — and the failures are named again at the end
# so they are not lost in the scrollback.
failed=""
for p in test/netprobe/[0-9]*.sh; do
    printf '\n=== %s ===\n' "$p"
    SLUG="$SLUG_EGRESS" SLUG_A="$SLUG_EGRESS" SLUG_B="$SLUG_PLAIN" bash "$p" ||
        failed="$failed $p"
done

if [ -n "$failed" ]; then
    printf '\nnetprobe: FAILED:%s\n' "$failed"
    exit 1
fi
printf '\nnetprobe: every probe passed\n'
