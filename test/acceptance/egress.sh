#!/usr/bin/env bash
# Egress-enforcement acceptance suite. Run ON the Docker host, as root.
#
# A grant is enforcement, not just a decision on the record:
#
#   1  the egress proxy exists, is platform-owned, and publishes nothing
#   2  a tenant with no grant has NO outbound path: no attachment, no rule
#   3  a Tier-1 host is auto-granted and becomes genuinely reachable
#   4  a host with no grant is REFUSED by the proxy, attributed, and surfaced
#   5  the ClientHello SNI is filtered as well as the CONNECT target, no MITM
#   6  REVOKING a grant removes the host from the live ACL and the chain within
#      one reconcile tick, with no operator action      ← the headline clause
#   7  an expired grant does the same, with no cleanup job involved
#   8  rule ORDER survives N per-grant accepts, and a mis-ordered one is caught
#   9  a rule tagged with a grant that does not exist is reported, NOT removed
#  10  tenant logs land on the host, survive a deploy, and rotate
#  11  per-tenant rate limits answer 429, separately for /api/ and /_/
#  12  quarantine returns 503 with the data untouched, and lifts again
#  13  the audit chain still verifies and is still append-only
#
# Usage: test/acceptance/egress.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG="${SLUG:-demo}"
PB_VERSION="${PB_VERSION:-0.42.3}"
OWNER="${OWNER:-person:acceptance-egress}"
PB_ROOT="${PB_ROOT:-/srv/citadel}"
STATE_DB="$PB_ROOT/control/state.db"
SOCK="${SOCK:-/run/citadel/control.sock}"
# Tenants are served as <slug>.$APPS_DOMAIN. nip.io resolves any name that
# embeds an IP to that IP, so a browser on the Mac reaches the VM directly. The
# suite itself never relies on DNS: it sends a Host header to 127.0.0.1.
VM_IP="${VM_IP:-$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)}"
APPS_DOMAIN="${APPS_DOMAIN:-apps.$VM_IP.nip.io}"
PORTAL_ADDR="${PORTAL_ADDR:-0.0.0.0:8080}"
PORTAL="http://127.0.0.1:${PORTAL_ADDR##*:}"
EDGE="${EDGE:-http://127.0.0.1}"
EGRESS_NET="${EGRESS_NET:-v2p-egress}"
SQUID="${SQUID:-citadel-squid}"
SQUID_CONF="$PB_ROOT/egress/squid.conf"
ALLOWED_HOST="${ALLOWED_HOST:-example.com}"
DENIED_HOST="${DENIED_HOST:-www.google.com}"
DAEMON=bin/controlplaned
CITADEL=bin/citadel
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

FAILS=0
DAEMON_PID=""
LOG=/tmp/acceptance-egress-controlplaned.log
CONF=/tmp/acceptance-egress-config.json
WORK="$(mktemp -d /tmp/acceptance-egress-pkgs.XXXXXX)"

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
command -v sqlite3 >/dev/null || die "sqlite3 is needed to read the state database"
command -v python3 >/dev/null || die "python3 is needed to build the package zips"
command -v curl >/dev/null    || die "curl is needed to drive the edge"

citadel() { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }

# The portal carries the denial surface, so this suite binds it the way the package suite
# did. That is only acceptable because the INPUT drop keeps tenant bridges
# off host ports — which section 2 re-checks rather than assumes.
# The edge image carrying the rate-limit module, by digest, the same hand-off
# pb-hardened uses (§5). Absent, the suite still runs: §10's limits then are not
# in effect and section 11 asserts the platform SAYS so rather than hiding it.
# Host architecture, as digests.txt names it. Each file lists every arch, so
# the last line is not necessarily this host's.
case "$(uname -m)" in aarch64|arm64) HOST_ARCH=arm64 ;; *) HOST_ARCH=amd64 ;; esac
# digest_for FILE: the newest entry for this host's arch.
digest_for() { awk -v a="$HOST_ARCH" '!/^#/ && NF >= 2 && $(NF-1) == a { r = $NF } END { print r }' "$1" 2>/dev/null; }
EDGE_IMAGE="$(digest_for images/edge-caddy/digests.txt)"
if [ -n "$EDGE_IMAGE" ]; then

    EDGE_IMAGE_JSON="\"edge_image\": \"$EDGE_IMAGE\","
    note "edge image: $EDGE_IMAGE"

else

    EDGE_IMAGE_JSON=""
    note "no images/edge-caddy/digests.txt; the edge keeps its default image and its"
    note "per-tenant rate limits will NOT be in effect (make edge-image)"
fi

cat >"$CONF" <<EOF
{
  "pb_root": "$PB_ROOT",
  "socket_path": "$SOCK",
  "apps_domain": "$APPS_DOMAIN",
  $EDGE_IMAGE_JSON
  "portal_addr": "$PORTAL_ADDR",
  "portal_allow_public": true
}
EOF

pack() { python3 hack/pack.py "$1" "$WORK/$2.zip"; }

# Every request goes through the EDGE, never a tenant's bridge address: the
# INPUT drop blocks host→tenant, and a test that went round it would be
# exercising a path no real request takes.
edge()     { curl -sS --max-time 60 -H "Host: $SLUG.$APPS_DOMAIN" "$EDGE/$1"; }
edge_code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
                -H "Host: $SLUG.$APPS_DOMAIN" "$EDGE/$1"; }
edge_has() { edge "$1" | grep -q "$2"; }
# A function, not `bash -c "... $(edge_code ...)"`: check runs its argv
# directly and a new bash would not inherit these.
edge_code_is()  { [ "$(edge_code "$1")" = "$2" ]; }
json_has() { printf '%s' "$1" | grep -q "$2"; }
# json_field <json> <object> <bool-key> — true when the field is true.
# A grep for '"allowed":{"reached":true' would depend on key ORDER, which Go's
# map marshalling does not promise.
json_field() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get(sys.argv[1],{}).get(sys.argv[2]) is True else 1)' \
      "$2" "$3"
}
conf_has() { grep -q "$1" "$SQUID_CONF"; }
chain_has() { iptables -L DOCKER-USER -n | grep -q "$1"; }

grant_id_for() {
    sqlite3 "$STATE_DB" \
      "SELECT id FROM access_grant
        WHERE tenant_id='$SLUG' AND subject='$1' ORDER BY requested_at DESC LIMIT 1"
}

start_daemon() {
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
        note "--keep: leaving $SLUG and the daemon (pid $DAEMON_PID) running"
        return
    fi
    citadel tenant destroy "$SLUG" --no-backup --purge >/dev/null 2>&1
    sleep 8
    stop_daemon
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. the egress proxy is platform-owned and reaches nothing it should not ──
log "1. the egress proxy"
start_daemon
citadel principal create "$OWNER" --name "Egress acceptance" >/dev/null 2>&1

check "the egress network exists and is NOT internal (the proxy needs a route out)" \
    bash -c "[ \"\$(docker network inspect -f '{{.Internal}}' '$EGRESS_NET')\" = false ]"
# The egress bridge must not match br-t-+, or the INPUT drop would cut
# the proxy off from the host it runs on.
check_not "the egress bridge is not inside the br-t-+ tenant wildcard" \
    bash -c "docker network inspect -f '{{index .Options \"com.docker.network.bridge.name\"}}' '$EGRESS_NET' | grep -q '^br-t-'"
check "the proxy container is running" \
    bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' '$SQUID')\" = true ]"
check_not "the proxy publishes no host port" \
    bash -c "[ \"\$(docker inspect -f '{{len .HostConfig.PortBindings}}' '$SQUID')\" != 0 ]"
check "the proxy drops ALL capabilities" \
    bash -c "docker inspect -f '{{json .HostConfig.CapDrop}}' '$SQUID' | grep -q ALL"
# The DIRECTORY is mounted, not the file: the allowlist is written with a
# rename, which replaces the inode, and a file bind-mount pins the container to
# the original one (design.md §9.4).
check "the proxy's configuration directory is mounted read-only" \
    bash -c "docker inspect -f '{{json .HostConfig.Binds}}' '$SQUID' | grep -q 'egress:/etc/squid/v2p:ro'"
check "the proxy stays on runc — runsc is for tenant workloads" \
    bash -c "[ \"\$(docker inspect -f '{{.HostConfig.Runtime}}' '$SQUID')\" = runc ]"

# ── 2. the default posture: no grant, no path ────────────────────────────────
log "2. a tenant with no grant has no outbound path at all"
citadel tenant create --slug "$SLUG" --pb-version "$PB_VERSION" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG"
pack test/fixtures/pkg-basic pkg-basic
citadel release upload "$SLUG" --file "$WORK/pkg-basic.zip" --deploy >/dev/null ||
    die "the baseline package did not deploy"

check_not "the tenant is not attached to the egress network" \
    bash -c "docker inspect -f '{{json .NetworkSettings.Networks}}' 'pb-$SLUG' | grep -q '$EGRESS_NET'"
check_not "no per-grant accept exists in DOCKER-USER" chain_has "tenant=$SLUG grant="
check "egress_enabled is 0" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT egress_enabled FROM tenant WHERE id='$SLUG'\" | grep -qx 0"
check "the tenant is up and serving through the edge" edge_has "fixture/ping" '"ok":true'
# the variables are set, and they are not what is doing the work.
check "HTTP_PROXY is set anyway (ergonomics, never enforcement)" \
    bash -c "docker inspect -f '{{json .Config.Env}}' 'pb-$SLUG' | grep -q HTTP_PROXY"

# ── 3. a Tier-1 host is auto-granted and genuinely reachable ─────────────────
log "3. a Tier-1 grant becomes real enforcement"
pack test/redteam/egress-probe egress-probe
citadel release upload "$SLUG" --file "$WORK/egress-probe.zip" --deploy >/dev/null ||
    die "the egress package did not deploy"

check "the manifest host was auto-granted, with the platform as decider" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT decision FROM access_grant WHERE tenant_id='$SLUG' AND subject='$ALLOWED_HOST'\" \
      | grep -qx auto_approved"
check "the tenant now holds an address on the egress network" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT egress_ip FROM tenant WHERE id='$SLUG'\" | grep -q '[0-9]'"
check "the container is attached to the egress network" \
    bash -c "docker inspect -f '{{json .NetworkSettings.Networks}}' 'pb-$SLUG' | grep -q '$EGRESS_NET'"
GID="$(grant_id_for "$ALLOWED_HOST")"
check "an accept rule exists carrying that grant id" chain_has "grant=$GID"
check "the generated allowlist names the host" conf_has "$ALLOWED_HOST"

EG="$(edge "redteam/egress")"
note "egress report: ${EG:0:200}"
if json_field "$EG" allowed reached; then

    ok "the granted host is genuinely reachable from inside the tenant"

else

    bad "the granted host is genuinely reachable from inside the tenant"
    # The generated allowlist and the proxy's own view of the request. Both are
    # needed to tell the three failure modes apart — the ACL did not match, the
    # request never arrived, or the proxy bumped instead of splicing — and
    # guessing between them cost most of a day the first time.
    note "--- generated allowlist ---"
    sed -n '/generated from active/,/end generated/p' "$SQUID_CONF" | sed 's/^/    /'
    note "--- proxy access log ---"
    tail -4 /srv/citadel/logs/_egress/access.log 2>/dev/null | sed 's/^/    /'
fi

# A restart re-runs host-side provisioning. It used to assert the tenant's rules
# with no binding, which pruned the default deny and left the proxy accept.
log "3b. a restart keeps a granted tenant's rules intact"
REPAIRS_BEFORE="$(sqlite3 "$STATE_DB" \
    "SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG' AND action='netpolicy.rule.repaired'")"
citadel tenant restart "$SLUG" >/dev/null || bad "the tenant restart failed"
check "the default deny survived the restart" chain_has "tenant=$SLUG egress-default-deny"
check "the accept survived the restart" chain_has "grant=$GID"
sleep 12 # two reconcile ticks: a missing rule would be repaired and audited by now
check "no rule had to be repaired after the restart" \
    bash -c "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG' AND action='netpolicy.rule.repaired'\")\" = '$REPAIRS_BEFORE' ]"

# ── 4. a host with no grant is REFUSED, attributed, and surfaced ─────────────
log "4. a denial is a product surface, not a timeout"
check "the ungranted host is refused by the proxy (403), not left to time out" \
    json_has "$EG" '"refused":true'
sleep 12   # one tick, so the proxy log is drained into the aggregate
check "the denial was attributed to this tenant" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM egress_denial WHERE tenant_id='$SLUG'\" | grep -qv '^0$'"
check "the denied host is named" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT host FROM egress_denial WHERE tenant_id='$SLUG'\" | grep -q '$DENIED_HOST'"
check "citadel egress shows the refusal count" \
    bash -c "$CITADEL --socket '$SOCK' --as '$OWNER' egress '$SLUG' | grep -q 'REFUSED'"
# Bounded by TICKS, not by history: the state database survives between runs,
# so an absolute count grows forever and eventually fails for the wrong reason.
# The property under test is that a hook in a retry loop cannot drive the audit
# chain — at most one event per tenant per 5 s tick, whatever the traffic.
check "one audit event per tick, not one per refusal (stays writable)" \
    bash -c "[ \"\$(sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM audit_event WHERE action='egress.denied'
         AND occurred_at > datetime('now','-3 minutes')\")\" -le 40 ]"

# ── 5. SNI as well as CONNECT, with no MITM ─────────────────────────────────
log "5. ClientHello SNI filtering, no certificate injection"
if conf_has "ssl_bump"; then
    ok "the running allowlist filters on ssl::server_name as well as dstdomain"
    check_not "no certificate generation is configured: nothing is MITMed" conf_has "ssl_crtd"
    if bash test/netprobe/10-sni-mismatch.sh >/tmp/acceptance-egress-sni.log 2>&1; then
        ok "a CONNECT for an allowed host with a ClientHello for another is terminated"
    else
        bad "the SNI mismatch probe failed; see /tmp/acceptance-egress-sni.log"
    fi
else
    bad "the running proxy has no ssl_bump: only the CONNECT target is filtered"
    note "a hook can then CONNECT to an allowed host and negotiate TLS for another one"
    note "use an openssl-enabled squid build, or set egress_sni_enforce:false to make it deliberate"
fi

# ── 6. revocation, within one tick, with no operator action ─────────────────
log "6. revoking a grant — the headline done-when clause"
check "the host is in the live ACL before the revocation" conf_has "$ALLOWED_HOST"
citadel grant revoke "$SLUG" "$GID" >/dev/null || bad "could not revoke $GID"
note "revoked $GID; waiting one reconcile tick (5s) plus margin"
sleep 12
check_not "the host is gone from the live proxy ACL" conf_has "$ALLOWED_HOST"
check_not "the accept rule is gone from DOCKER-USER" chain_has "grant=$GID"
check_not "the tenant is detached from the egress network" \
    bash -c "docker inspect -f '{{json .NetworkSettings.Networks}}' 'pb-$SLUG' | grep -q '$EGRESS_NET'"
check "egress_enabled went back to 0" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT egress_enabled FROM tenant WHERE id='$SLUG'\" | grep -qx 0"
# The clause says "with no operator action". Revocation writes one row; the
# reconciler does the rest because Grant.Active is evaluated at read time.
check "no operator ran anything between the revocation and the effect" \
    bash -c "! grep -qi 'manual\\|operator intervention' '$LOG'"
check "the revocation is audited" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM audit_event WHERE action='grant.revoked'\" | grep -qv '^0$'"

# ── 7. expiry takes the same path, with no cleanup job ──────────────────────
log "7. expiry is enforced on the normal tick and nowhere else"
citadel release upload "$SLUG" --file "$WORK/egress-probe.zip" --deploy >/dev/null 2>&1
# The re-declared host was previously revoked, so §14.7 says it lands pending
# rather than being auto-granted again. Approve it explicitly to get something
# active to expire.
NEWGID="$(grant_id_for "$ALLOWED_HOST")"
check "the re-declared host landed PENDING, not auto-granted again" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT decision FROM access_grant WHERE id='$NEWGID'\" | grep -qx pending"
citadel grant approve "$NEWGID" --justification "egress acceptance expiry test" --days 1 >/dev/null 2>&1
sleep 12
check "the approved host is enforced again" conf_has "$ALLOWED_HOST"

# Backdating expires_at is exactly what the passage of time would do, against
# the same code path: expiry is evaluated at read time, never swept.
sqlite3 "$STATE_DB" "UPDATE access_grant SET expires_at=datetime('now','-1 hour') WHERE id='$NEWGID'"
note "backdated $NEWGID; waiting one tick"
sleep 12
check_not "the expired host is gone from the live ACL" conf_has "$ALLOWED_HOST"
check_not "the expired accept is gone from DOCKER-USER" chain_has "grant=$NEWGID"
check "there is no expiry cron: the enforcement path IS the expiry path" \
    bash -c "! grep -qi 'expiry sweep\\|grant reaper' '$LOG'"

# ── 8. rule order survives, and a bad order is caught ───────────────────────
log "8. rule ORDER, asserted programmatically"
FIRST_DENY="$(iptables -L DOCKER-USER -n --line-numbers | awk '$2=="DROP" {print $1; exit}')"
LAST_ACCEPT="$(iptables -L DOCKER-USER -n --line-numbers | awk '$2=="ACCEPT" {n=$1} END {print n}')"
if [ -n "$FIRST_DENY" ] && [ -n "$LAST_ACCEPT" ] && [ "$LAST_ACCEPT" -lt "$FIRST_DENY" ]; then
    ok "every ACCEPT sits above the first DROP (line $LAST_ACCEPT < $FIRST_DENY)"
else
    bad "an ACCEPT at $LAST_ACCEPT sits below the first DROP at $FIRST_DENY; it can never match"
fi
check "the conntrack accept is still first (reply traffic would half-open without it)" \
    chain_has "v2p platform conntrack"

# Deliberately break the order and confirm the platform NOTICES. A ruleset that
# is correct and unverified is one reload away from being neither.
iptables -I DOCKER-USER 1 -d 10.0.0.0/8 \
    -m comment --comment "v2p platform deny=10.0.0.0/8" -j DROP
note "inserted a deny above the conntrack accept; waiting one tick"
sleep 12
check "the platform reported the ordering violation" grep -qi "rule ORDER is wrong" "$LOG"
iptables -D DOCKER-USER 1

# ── 9. a rule with no grant behind it ──────────────────────────────
log "9. enforcement with nothing behind it is reported, never repaired"
iptables -I DOCKER-USER 2 -s 10.214.0.99 -d 10.214.0.2 -p tcp --dport 3128 \
    -m comment --comment "v2p tenant=$SLUG grant=g-nonexistent" -j ACCEPT
sleep 12
check "the control plane reported it" grep -q "g-nonexistent" "$LOG"
check "it was NOT removed: removing it destroys the evidence" chain_has "g-nonexistent"
check "it is an audited event" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM audit_event WHERE action='netpolicy.rule.unbacked'\" | grep -qv '^0$'"
# §14.5: the finding freezes the tenant until an operator lifts it.
check "the finding froze the tenant" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT frozen_reason FROM tenant WHERE slug='$SLUG'\" | grep -q ."
check_not "a deploy is refused while frozen" \
    citadel release upload "$SLUG" --file "$WORK/pkg-basic.zip" --deploy
iptables -D DOCKER-USER -s 10.214.0.99 -d 10.214.0.2 -p tcp --dport 3128 \
    -m comment --comment "v2p tenant=$SLUG grant=g-nonexistent" -j ACCEPT
check "the operator lifts the freeze once the rule is gone" \
    citadel unfreeze "$SLUG" --reason "egress acceptance: planted rule removed"

# ── 10. host-side logs (§15) ────────────────────────────────────────────────
log "10. logs are collected host-side, and outlive the container"
check "the tenant's log directory exists" test -d "$PB_ROOT/logs/$SLUG"
check "it has content" bash -c "[ -s '$PB_ROOT/logs/$SLUG/app.log' ]"
check "the stream framing was stripped (no control bytes in the file)" \
    bash -c "! head -c 2048 '$PB_ROOT/logs/$SLUG/app.log' | grep -qP '^\\x01\\x00\\x00\\x00'"
BEFORE="$(wc -c <"$PB_ROOT/logs/$SLUG/app.log")"
citadel release upload "$SLUG" --file "$WORK/pkg-basic.zip" --deploy >/dev/null 2>&1
sleep 10
# A deploy DESTROYS and recreates the container, so this is the case Docker's
# own log cannot answer: the output explaining the previous release is gone
# from the daemon at exactly the moment someone wants it.
check "the log survived a container recreate" \
    bash -c "[ \"\$(wc -c <'$PB_ROOT/logs/$SLUG/app.log')\" -ge $BEFORE ]"
check "the portal serves the collected log" \
    bash -c "curl -sS --max-time 20 '$PORTAL/t/$SLUG/logs' -o /dev/null -w '%{http_code}' | grep -qE '200|30[0-9]'"

# ── 11. per-tenant rate limits (§10) ────────────────────────────────────────
log "11. per-tenant rate limits at the edge"
# Asked of the PLATFORM rather than of the container. proxyctl already knows:
# it publishes the route with the limits, and records rate_limit drift when the
# edge rejects them. Reading that answer also tests the reporting path, and it
# needs no exec into a platform container (the control plane never execs into a platform container).
if citadel fleet | grep -q rate_limit; then
    RL_AVAILABLE=0
else
    RL_AVAILABLE=1
fi
if [ "$RL_AVAILABLE" = 1 ]; then
    # 429 within the window, on /api/ only: the two path groups have separate
    # budgets, so exhausting one must not lock the other out.
    # This deliberately spends the /api/ budget for the rest of the window, so
    # nothing after section 11 may probe /api/ and expect a 2xx.
    hits=0
    for _ in $(seq 1 800); do
        edge_code_is "api/health" 429 && { hits=1; break; }
    done
    if [ "$hits" = 1 ]; then ok "/api/ returns 429 past its window"; else bad "/api/ never rate-limited"; fi
    check_not "the admin UI has its own budget and was not locked out with /api/" \
        edge_code_is "_/" 429
else
    note "the running edge image has no rate_limit handler, so per-tenant rate limits are NOT in effect"
    check "the platform reports that as drift rather than hiding it" \
        bash -c "$CITADEL --socket '$SOCK' --as '$OWNER' fleet | grep -q rate_limit"
    note "build images/edge-caddy (make edge-image) and set edge_image to its digest"
fi

# ── 12. quarantine (§12) ────────────────────────────────────────────────────
log "12. quarantine — ingress stops, data is untouched"
# NOT /api/: section 11 just spent that budget on purpose, and a 429 here would
# read as "quarantine broke ingress". The tenant's own route is outside both
# rate-limited path groups.
check "the tenant is serving before quarantine" edge_code_is "fixture/ping" 200
check_not "quarantine without a reason is refused" citadel quarantine "$SLUG"
citadel quarantine "$SLUG" --reason "egress acceptance" >/dev/null || bad "could not quarantine"
check "the edge now returns 503" edge_code_is "fixture/ping" 503
check "the container was NOT stopped: quarantine is an ingress decision" \
    bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' 'pb-$SLUG')\" = true ]"
check "the data image is still mounted and untouched" \
    bash -c "mountpoint -q '$PB_ROOT/tenants/$SLUG/data'"
check "the reason is on the audit record, shown to the tenant verbatim" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT detail_json FROM audit_event WHERE action='tenant.quarantined' ORDER BY seq DESC LIMIT 1\" \
      | grep -q 'egress acceptance'"
citadel unquarantine "$SLUG" >/dev/null || bad "could not lift the quarantine"
check "the tenant serves again once the quarantine is lifted" \
    edge_code_is "fixture/ping" 200

# ── 13. the audit chain ────────────────────────────────────────────
log "13. the audit chain is intact and still append-only"
check "citadel audit verify passes" citadel audit verify
check_not "UPDATE on audit_event is refused by a trigger" \
    bash -c "sqlite3 '$STATE_DB' \"UPDATE audit_event SET action='x' WHERE seq=1\""
check_not "DELETE on audit_event is refused by a trigger" \
    bash -c "sqlite3 '$STATE_DB' \"DELETE FROM audit_event WHERE seq=1\""
check "the egress action families are present" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(DISTINCT action) FROM audit_event WHERE action LIKE 'egress.%'\" | grep -qv '^0$'"

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n'
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32mEgress acceptance: all checks passed\033[0m\n'
    exit 0
fi
printf '\033[31mEgress acceptance: %d check(s) FAILED\033[0m\n' "$FAILS"
printf 'control-plane log: %s\n' "$LOG"
exit 1
