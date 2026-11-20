#!/usr/bin/env bash
# Control-plane acceptance suite. Run ON the Docker host, as root.
#
# Provision, reconcile, destroy, audit — the core loop:
#
#   1  citadel tenant create yields a REACHABLE instance
#   2  ... with CORRECT RULES
#   3  the netprobe suite still fails to escape
#   4  a manual image_digest edit produces a drift ALERT, not a restart
#   5  deleting a rule by hand gets it re-asserted within one tick, loudly
#   6  killing the control plane at any point is recoverable, with no state
#      change left without its audit event
#   7  UPDATE/DELETE on an audit row is refused by the database
#   8  every state change has a matching audit event with a real actor
#   9  destroy leaves no orphaned network or rule
#
# Usage: test/acceptance/controlplane.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG="${SLUG:-demo}"
PB_VERSION="${PB_VERSION:-0.42.3}"
OWNER="${OWNER:-person:acceptance-cp}"
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

FAILS=0
DAEMON_PID=""
LOG=/tmp/acceptance-controlplaned.log
CONF=/tmp/acceptance-cp-config.json

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
ok()   { printf '    \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '    \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
die()  { printf '\n\033[31mabort: %s\033[0m\n' "$*" >&2; exit 2; }

check()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
check_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

[ "$(id -u)" = 0 ] || die "must run as root on the Docker host"
[ -x "$DAEMON" ] || die "$DAEMON not built; run 'make build' on the Mac first"
[ -x "$CITADEL" ]  || die "$CITADEL not built; run 'make build' on the Mac first"
command -v sqlite3 >/dev/null || die "sqlite3 is needed to simulate out-of-band edits"

citadel() { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }

cat >"$CONF" <<EOF
{
  "apps_domain": "$APPS_DOMAIN"
}
EOF

start_daemon() {
    "$DAEMON" -config "$CONF" -log-level "${CP_LOG_LEVEL:-info}" >>"$LOG" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 60); do
        [ -S "$SOCK" ] && "$CITADEL" --socket "$SOCK" fleet >/dev/null 2>&1 && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || { tail -20 "$LOG"; die "control plane exited at start-up"; }
        sleep 0.5
    done
    tail -20 "$LOG"
    die "control plane did not come up"
}

stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill -TERM "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    DAEMON_PID=""
}

# kill_daemon is SIGKILL: no shutdown hook runs, which is the point of the
# crash-recovery checks.
kill_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill -KILL "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    DAEMON_PID=""
}

cleanup() {
    kill_daemon
    if [ "$KEEP" = 0 ]; then
        log "cleanup"
        start_daemon 2>/dev/null || true
        citadel tenant destroy "$SLUG" --no-backup --purge >/dev/null 2>&1 || true
        sleep 10
        stop_daemon
        umount "$PB_ROOT/tenants/$SLUG/data" 2>/dev/null || true
        rm -rf "$PB_ROOT/tenants/$SLUG" "$PB_ROOT/control/keys/$SLUG".*
    fi
}
trap cleanup EXIT

tenant_get() {
    local path="$1"; shift
    curl -fsS -m 10 -H "Host: $SLUG.$APPS_DOMAIN" "$@" "http://127.0.0.1$path"
}

: >"$LOG"
log "starting the control plane (log: $LOG)"
start_daemon
note "pid $DAEMON_PID"

# ── 0. bootstrap ─────────────────────────────────────────────────────────────
log "0. bootstrap: principal and runtime version"
"$CITADEL" --socket "$SOCK" principal create "$OWNER" --name "Acceptance operator" >/dev/null 2>&1 || true
check "principal $OWNER exists" bash -c \
    "'$CITADEL' --socket '$SOCK' --json principal list | grep -q '\"$OWNER\"'"

citadel runtime-version add "$PB_VERSION" || die "cannot register $PB_VERSION"
check "runtime version $PB_VERSION is registered by digest" bash -c \
    "'$CITADEL' --socket '$SOCK' --json runtime-version list | grep -q '@sha256:'"

# ── 1. create, and it is reachable ───────────────────────────────────────────
log "1. tenant create -> a reachable instance"
citadel tenant create --slug "$SLUG" --pb-version "$PB_VERSION" --owner "$OWNER" \
    --app-dir test/fixtures/basic-hook --disk-mib 256 || die "tenant create failed"

check "/api/health answers through the edge" tenant_get /api/health
# /api/health is not enough: a version-mismatched binary serves it 200 with a
# broken data plane (design.md INV-4). The real check is a superuser token
# refresh, signed by the control plane from pb_data: create only returns once
# it passed, and the reconciler keeps repeating it.
check "the reconciler's data-plane check reports the tenant healthy" bash -c \
    "for i in \$(seq 1 30); do '$CITADEL' --socket '$SOCK' --json tenant status '$SLUG' \
       | grep -q '\"observed_state\": *\"healthy\"' && exit 0; sleep 1; done; exit 1"
check_not "no superuser password is stored for the tenant" test -e "$PB_ROOT/control/keys/$SLUG.su"
check "the edge itself serves the PocketBase admin handoff page" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/_citadel/admin | grep -q 'Opening PocketBase admin'"
check "the fixture hook runs from the read-only app mount" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q 'basic-hook'"
check_not "a hook cannot write to its own release" \
    test -e "$PB_ROOT/artifacts/$(readlink "$PB_ROOT/tenants/$SLUG/app/current" | xargs basename)/pb_hooks/ESCAPE_MARKER"

# ── 2. correct rules and container configuration ─────────────────────────────
log "2. correct rules and container configuration"
check "tagged INPUT drop for br-t-+ is present" \
    iptables -C INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP

DU="$(iptables -L DOCKER-USER -n -v --line-numbers)"
FIRST="$(echo "$DU" | awk 'NR>2 {print $4; exit}')"
if [ "$FIRST" = "ACCEPT" ] && echo "$DU" | grep -q "v2p platform conntrack"; then
    ok "DOCKER-USER rule 1 is the conntrack accept"
else
    bad "DOCKER-USER rule 1 is not the conntrack accept; reply traffic would be dropped"
    echo "$DU" | sed 's/^/        /'
fi
for cidr in 169.254.0.0/16 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12; do
    check "unconditional deny for $cidr" \
        iptables -C DOCKER-USER -d "$cidr" -m comment --comment "v2p platform deny=$cidr" -j DROP
done
INGRESS_LINE="$(echo "$DU" | awk '/v2p platform ingress/ {print $1; exit}')"
FIRST_DENY="$(echo "$DU" | awk '/v2p platform deny=/ {print $1; exit}')"
if [ -n "$INGRESS_LINE" ] && [ -n "$FIRST_DENY" ] && [ "$INGRESS_LINE" -lt "$FIRST_DENY" ]; then
    ok "the edge ingress accept sits above the RFC1918 denies"
else
    bad "the edge ingress accept is missing or below a deny; off-host ingress times out"
    echo "$DU" | sed 's/^/        /'
fi
# A curl from the guest itself proves nothing here: locally-originated traffic
# is DNATed in OUTPUT and never reaches FORWARD, so it passes with or without
# the ingress accept. A network namespace on a veth is an off-host client as far
# as netfilter is concerned — its request arrives on an interface, is DNATed in
# PREROUTING and crosses DOCKER-USER exactly like one from the Mac.
HOST_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)"
ip netns del v2p-ingress 2>/dev/null || true
ip link del v2p-ing-h 2>/dev/null || true
ip netns add v2p-ingress
ip link add v2p-ing-h type veth peer name v2p-ing-n
ip link set v2p-ing-n netns v2p-ingress
ip addr add 198.18.0.1/30 dev v2p-ing-h
ip link set v2p-ing-h up
ip -n v2p-ingress addr add 198.18.0.2/30 dev v2p-ing-n
ip -n v2p-ingress link set v2p-ing-n up
ip -n v2p-ingress route add default via 198.18.0.1
check "an off-host client reaches the tenant through the edge on $HOST_IP" \
    ip netns exec v2p-ingress curl -fsS -m 10 -H "Host: $SLUG.$APPS_DOMAIN" "http://$HOST_IP/api/health"
ip netns del v2p-ingress
ip link del v2p-ing-h 2>/dev/null || true

PORTS="$(docker inspect -f '{{json .HostConfig.PortBindings}}{{json .NetworkSettings.Ports}}' "pb-$SLUG")"
if echo "$PORTS" | grep -q HostPort; then
    bad "the tenant container publishes a port: $PORTS"
else
    ok "no published ports on the tenant container"
fi
check "tenant container runs under runsc (D2)" bash -c \
    "docker inspect -f '{{.HostConfig.Runtime}}' pb-$SLUG | grep -qx runsc"
check "tenant container is read-only with swap disabled" bash -c \
    "docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}' pb-$SLUG \
     | awk '{exit !(\$1==\"true\" && \$2==\$3)}'"
check_not "no docker socket is mounted into the tenant" bash -c \
    "docker inspect -f '{{json .Mounts}}' pb-$SLUG | grep -q docker.sock"
check "data dir is chowned for the remapped container uid (D3)" bash -c \
    "base=\$(awk -F: '/^dockremap:/{print \$2}' /etc/subuid); \
     [ \"\$(stat -c %u '$PB_ROOT/tenants/$SLUG/data')\" = \$((base + 10001)) ]"

# ── 3. netprobe suite ────────────────────────────────────────────────────────
log "3. netprobe suite against the control-plane-provisioned tenant"
for probe in test/netprobe/0*.sh; do
    case "$probe" in */00-baseline.sh) continue ;; esac
    if bash "$probe" >/tmp/"$(basename "$probe")".out 2>&1; then
        ok "$(basename "$probe")"
    else
        bad "$(basename "$probe") — see /tmp/$(basename "$probe").out"
        tail -15 /tmp/"$(basename "$probe")".out | sed 's/^/        /'
    fi
done

# ── 4. digest drift is an alert, never an action ────────────────────
log "4. a manual image_digest edit produces a drift ALERT, not a restart"
CID_BEFORE="$(docker inspect -f '{{.Id}}' "pb-$SLUG")"
GOOD_DIGEST="$(sqlite3 "$STATE_DB" "SELECT image_digest FROM tenant WHERE id='$SLUG'")"
FAKE='127.0.0.1:5000/pb-hardened@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
sqlite3 "$STATE_DB" "UPDATE tenant SET image_digest='$FAKE' WHERE id='$SLUG'"
sleep 12

check "citadel fleet reports the digest drift" bash -c \
    "'$CITADEL' --socket '$SOCK' --json fleet | grep -q '\"digest\"'"
check "an instance.digest_drift.detected audit row exists" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE action='instance.digest_drift.detected' AND tenant_id='$SLUG'\")\" -gt 0 ]"
CID_AFTER="$(docker inspect -f '{{.Id}}' "pb-$SLUG" 2>/dev/null || echo gone)"
if [ "$CID_BEFORE" = "$CID_AFTER" ]; then
    ok "the container was NOT recreated (same container id)"
else
    bad "the container was recreated on a digest edit; that is an unbacked-up one-way migration"
fi
sqlite3 "$STATE_DB" "UPDATE tenant SET image_digest='$GOOD_DIGEST' WHERE id='$SLUG'"
sleep 8

# ── 5. rule re-assertion ─────────────────────────────────────────────────────
log "5. a hand-deleted rule is re-asserted within one tick, loudly"
iptables -D INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP
sleep 12
check "the INPUT drop was re-asserted" \
    iptables -C INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP
check "the repair was logged loudly" bash -c "grep -q 'DRIFT REPAIRED' '$LOG'"
check "a netpolicy.rule.repaired audit row exists" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE action='netpolicy.rule.repaired'\")\" -gt 0 ]"

# ── 6. an unbacked rule is reported, never removed ──────────────────
log "6. a hand-added tagged rule is reported and NOT removed"
iptables -I DOCKER-USER 2 -s 10.213.99.9 -m comment --comment "v2p tenant=ghost grant=forged" -j ACCEPT
sleep 12
check "an unbacked rule is reported as drift" bash -c \
    "'$CITADEL' --socket '$SOCK' --json fleet | grep -q unbacked_rule"
check "the unbacked rule is STILL PRESENT (evidence is not destroyed)" \
    iptables -C DOCKER-USER -s 10.213.99.9 -m comment --comment "v2p tenant=ghost grant=forged" -j ACCEPT
check "a netpolicy.rule.unbacked audit row exists" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE action='netpolicy.rule.unbacked'\")\" -gt 0 ]"
iptables -D DOCKER-USER -s 10.213.99.9 -m comment --comment "v2p tenant=ghost grant=forged" -j ACCEPT

# ── 7. crash recovery ────────────────────────────────────────────────────────
log "7. kill -9 the control plane and restart: convergence, no orphans, no audit gap"
SEQ_BEFORE="$(sqlite3 "$STATE_DB" "SELECT COALESCE(max(seq),0) FROM audit_event")"
kill_daemon
docker stop "pb-$SLUG" >/dev/null 2>&1
# An orphan a crashed create would have left behind: a labelled container with
# no tenant row.
docker run -d --name "pb-ghost" --label v2p.managed=true --label v2p.tenant=ghost \
    --network none alpine:3.20 sleep 600 >/dev/null 2>&1 || true
start_daemon
sleep 14

check "the tenant came back healthy on its own" bash -c \
    "'$CITADEL' --socket '$SOCK' --json tenant status '$SLUG' | grep -q '\"observed_state\": *\"healthy\"'"
check_not "the orphaned container was removed" docker inspect pb-ghost
check "a controlplane.recovered audit row exists" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE action='controlplane.recovered'\")\" -gt 0 ]"
SEQ_AFTER="$(sqlite3 "$STATE_DB" "SELECT COALESCE(max(seq),0) FROM audit_event")"
if [ "$SEQ_AFTER" -gt "$SEQ_BEFORE" ]; then
    ok "the chain advanced across the crash ($SEQ_BEFORE -> $SEQ_AFTER)"
else
    bad "no audit events were written after the crash"
fi
check "the chain still verifies after the crash" citadel audit verify

# Provisioning is re-entrant: interrupt it and the next run converges.
log "7b. kill -9 mid-provision and let the reconciler finish the job"
kill_daemon
start_daemon
( citadel tenant create --slug mid --pb-version "$PB_VERSION" --owner "$OWNER" \
    --disk-mib 256 >/dev/null 2>&1 & sleep 3; kill_daemon ) || true
start_daemon
sleep 25
if sqlite3 "$STATE_DB" "SELECT id FROM tenant" | grep -qx mid; then
    check "the interrupted tenant converged to healthy on a later tick" bash -c \
        "'$CITADEL' --socket '$SOCK' --json tenant status mid | grep -q '\"observed_state\": *\"healthy\"'"
    check "its provisioning event exists with a real actor" bash -c \
        "[ \"\$(sqlite3 '$STATE_DB' \"SELECT actor_id FROM audit_event WHERE tenant_id='mid' AND action='tenant.provisioned' ORDER BY seq DESC LIMIT 1\")\" = '$OWNER' ]"
    # Destroy WITHOUT --purge: retention after deletion is D10, so the default
    # is to keep the data and report the directory as an orphan rather than
    # silently discard a customer's database.
    citadel tenant destroy mid --no-backup >/dev/null 2>&1 || true
    sleep 12
    check "a destroy without --purge RETAINS the data image (D10)" \
        test -f "$PB_ROOT/tenants/mid/data.img"
    check "the retained directory is reported as an orphan, not deleted" bash -c \
        "'$CITADEL' --socket '$SOCK' --json fleet | grep -q orphan_dir"
    umount "$PB_ROOT/tenants/mid/data" 2>/dev/null || true
    rm -rf "$PB_ROOT/tenants/mid" "$PB_ROOT/control/keys/mid".*
else
    note "the interrupted create did not reach the database; nothing to converge (also a valid outcome)"
    ok "no tenant row was left without its audit event"
fi

# ── 8. the audit log is append-only and attributable ─────────────────────────
log "8. the audit log is append-only and every change has a real actor"
# The output is captured first rather than piped: with `set -o pipefail` the
# pipeline would inherit sqlite3's non-zero exit even when grep matched, and the
# check would report a failure for exactly the behaviour it is verifying.
for stmt_name in UPDATE DELETE; do
    case "$stmt_name" in
        UPDATE) stmt="UPDATE audit_event SET action='forged' WHERE seq=1" ;;
        DELETE) stmt="DELETE FROM audit_event WHERE seq=1" ;;
    esac
    out="$(sqlite3 "$STATE_DB" "$stmt" 2>&1 || true)"
    if printf '%s' "$out" | grep -q 'append-only'; then
        ok "$stmt_name on audit_event is refused by the database"
    else
        bad "$stmt_name on audit_event was not refused: $out"
    fi
done
check "citadel audit verify passes" citadel audit verify

NULL_ACTORS="$(sqlite3 "$STATE_DB" "SELECT count(*) FROM audit_event WHERE actor_id IS NULL OR actor_id=''")"
if [ "$NULL_ACTORS" = 0 ]; then
    ok "no audit row has a null or empty actor"
else
    bad "$NULL_ACTORS audit rows have no actor"
fi
# ORDER BY seq DESC LIMIT 1: audit rows outlive the tenant, so a slug
# reused after a destroy has more than one tenant.provisioned row.
check "the tenant's provisioning event names the human who did it" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT actor_id FROM audit_event WHERE tenant_id='$SLUG' AND action='tenant.provisioned' ORDER BY seq DESC LIMIT 1\")\" = '$OWNER' ]"
check "the tenant has exactly one active owner" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM current_owner WHERE tenant_id='$SLUG'\")\" = 1 ]"
check "a second active owner is refused by the index" bash -c \
    "sqlite3 '$STATE_DB' \"INSERT INTO tenant_owner (id,tenant_id,principal_id,role,granted_by,granted_at) \
       VALUES ('x','$SLUG','platform','owner','platform','2026-09-18T00:00:00Z')\" 2>&1 | grep -q -i 'unique'"

note "audit trail for $SLUG:"
citadel audit query --tenant "$SLUG" --limit 50 2>/dev/null | sed 's/^/        /'

# ── 9. destroy leaves nothing ────────────────────────────────────────────────
if [ "$KEEP" = 1 ]; then
    log "--keep: leaving $SLUG running; destroy checks skipped"
    note "app:      http://$SLUG.$APPS_DOMAIN/"
else
    log "9. destroy leaves no orphaned container, network, rule or route"
    citadel tenant destroy "$SLUG" --no-backup --purge || bad "destroy was refused"
    sleep 14

    check_not "the container is gone" docker inspect "pb-$SLUG"
    check_not "the network is gone" docker network inspect "t-$SLUG"
    check_not "the bridge interface is gone" ip link show "br-t-$SLUG"
    check_not "no rule tagged for the tenant remains" bash -c \
        "iptables-save | grep -q 'v2p tenant=$SLUG'"
    check_not "the edge route is gone" bash -c \
        "curl -fsS -m 5 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/api/health"
    check_not "the edge is no longer attached to the tenant network" bash -c \
        "docker inspect -f '{{json .NetworkSettings.Networks}}' citadel-caddy | grep -q '\"t-$SLUG\"'"
    check_not "the data image is unmounted" mountpoint -q "$PB_ROOT/tenants/$SLUG/data"
    check "the tenant row is gone" bash -c \
        "[ -z \"\$(sqlite3 '$STATE_DB' \"SELECT id FROM tenant WHERE id='$SLUG'\")\" ]"
    # --purge was asked for, so the data and keys go with it.
    check_not "the tenant directory is gone (--purge)" test -d "$PB_ROOT/tenants/$SLUG"
    check_not "the encryption key is gone (--purge)" test -f "$PB_ROOT/control/keys/$SLUG.key"

    # The platform-wide rule is shared by every tenant; one tenant's teardown
    # must never take it out.
    check "the platform-wide INPUT drop SURVIVES the teardown" \
        iptables -C INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP
    # The record of who authorised access outlives the data it describes.
    check "the tenant's audit rows are RETAINED" bash -c \
        "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG'\")\" -gt 0 ]"
    check "a tenant.destroyed audit row exists" bash -c \
        "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG' AND action='tenant.destroyed'\")\" -gt 0 ]"
    check "the chain still verifies after the destroy" citadel audit verify
fi

echo
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32mControl-plane acceptance: all checks passed\033[0m\n'
    printf 'Reboot check is separate: stop and start the VM, then\n'
    printf 'restart the daemon and confirm the tenant returns on the first tick.\n'
    exit 0
fi
printf '\033[31mControl-plane acceptance: %d check(s) FAILED\033[0m\n' "$FAILS"
printf 'control-plane log: %s\n' "$LOG"
exit 1
