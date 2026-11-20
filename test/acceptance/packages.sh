#!/usr/bin/env bash
# Package-pipeline and portal acceptance suite. Run ON the Docker host, as root.
#
# From a zip on disk to a live instance, and every way that can go wrong:
#
#   1  a package uploads and goes live (by CLI, then by browser form in 10)
#   2  a second release deploys, and the new hook code is what serves
#   3  a package with a DELIBERATELY BROKEN MIGRATION auto-rolls-back, the
#      error is surfaced, and the database is intact
#   4  rollback to any previous deployed release
#   5  a package requesting a denied egress host is rejected with a clear reason
#   6  a Tier-2 host DEPLOYS SUCCESSFULLY, unreachable, named as pending
#   7  a revoked subject is not auto-granted again (§14.7)
#   8  an ownership transfer requires acceptance by the target
#   9  a CI token deploy has the service account as the audit actor
#  10  the portal: login, upload through the form, live in the browser
#  11  the audit chain still verifies and is still append-only
#
# Usage: test/acceptance/packages.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG="${SLUG:-demo}"
PB_VERSION="${PB_VERSION:-0.42.3}"
OWNER="${OWNER:-person:acceptance-pkg}"
DEPLOYER="${DEPLOYER:-person:dev}"
HEIR="${HEIR:-person:heir}"
CI="${CI_PRINCIPAL:-service_account:ci}"
PORTAL_PASS="${PORTAL_PASS:-acceptance-portal-password}"
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
DAEMON=bin/controlplaned
CITADEL=bin/citadel
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

FAILS=0
DAEMON_PID=""
LOG=/tmp/acceptance-pkg-controlplaned.log
CONF=/tmp/acceptance-pkg-config.json
WORK="$(mktemp -d /tmp/acceptance-pkg-pkgs.XXXXXX)"

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
command -v sqlite3 >/dev/null || die "sqlite3 is needed to read the audit chain"
command -v python3 >/dev/null || die "python3 is needed to build the package zips (hack/pack.py)"

citadel()    { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }
citadel_as() { local who="$1"; shift; "$CITADEL" --socket "$SOCK" --as "$who" "$@"; }

# The portal needs a listener a browser can reach, so the suite binds it on the
# VM's address. That is only acceptable because the INPUT drop keeps tenant
# bridges off host ports — which section 10 re-checks rather than assumes.
cat >"$CONF" <<EOF
{
  "apps_domain": "$APPS_DOMAIN",
  "portal_addr": "$PORTAL_ADDR",
  "portal_allow_public": true
}
EOF

# setsid, so the daemon lives in its own session: with --keep the script exits
# and the orb/ssh session that ran it goes away, and a SIGHUP to the old process
# group would take the portal down with it.
start_daemon() {
    setsid "$DAEMON" -config "$CONF" -log-level "${CP_LOG_LEVEL:-info}" </dev/null >>"$LOG" 2>&1 &
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

# wait_gone polls until the reconciler has finished the teardown. Destroy is a
# desired-state flip, so the row survives until a tick has removed the
# container, the network and the rules; stopping the daemon before that leaves a
# half-deleted tenant for the next run to trip over.
wait_gone() {
    for _ in $(seq 1 24); do
        [ -z "$(sqlite3 "$STATE_DB" "SELECT id FROM tenant WHERE id='$SLUG'" 2>/dev/null)" ] && return 0
        sleep 2
    done
    return 1
}

cleanup() {
    if [ "$KEEP" = 0 ]; then
        log "cleanup"
        citadel tenant destroy "$SLUG" --no-backup --purge >/dev/null 2>&1 || true
        wait_gone || note "teardown did not finish; the next run will reap it"
        stop_daemon
        umount "$PB_ROOT/tenants/$SLUG/data" 2>/dev/null || true
        rm -rf "$PB_ROOT/tenants/$SLUG" "$PB_ROOT/control/keys/$SLUG".* "$WORK"
    fi
    # With --keep the daemon is deliberately left running: the portal is the
    # thing a human came to look at, and stopping it here would leave a tenant
    # up with nothing serving the UI.
}
trap cleanup EXIT

tenant_get() {
    local path="$1"; shift
    curl -fsS -m 10 -H "Host: $SLUG.$APPS_DOMAIN" "$@" "http://127.0.0.1$path"
}

# pack builds a package zip from a fixture directory, which is what a tenant
# uploads. citadel can zip a directory itself (--app-dir); building the zip here
# as well exercises the --file path, which is what CI and the portal form use.
pack() {
    local fixture="$1" out="$WORK/$1.zip"
    python3 hack/pack.py "test/fixtures/$fixture" "$out" || return 1
    echo "$out"
}

latest_release() {
    "$CITADEL" --socket "$SOCK" --json release list "$SLUG" \
        | grep -o '"id": *"rel-[^"]*"' | head -1 | cut -d'"' -f4
}

audit_count() { sqlite3 "$STATE_DB" "SELECT count(*) FROM audit_event WHERE $1"; }
# check runs its command through `bash -c`, which does not inherit shell
# functions, so the assertions below export this one rather than calling
# sqlite3 by hand in every quoted string.
export -f audit_count
export STATE_DB

: >"$LOG"
log "starting the control plane (log: $LOG, portal: $PORTAL_ADDR)"
start_daemon
note "pid $DAEMON_PID"

# ── 0. bootstrap ─────────────────────────────────────────────────────────────
log "0. bootstrap: principals, runtime version, tenant"
for p in "$OWNER" "$DEPLOYER" "$HEIR" "$CI"; do
    "$CITADEL" --socket "$SOCK" --as "$OWNER" principal create "$p" >/dev/null 2>&1 \
        || "$CITADEL" --socket "$SOCK" principal create "$p" >/dev/null 2>&1 || true
done
check "the acting principals exist" bash -c \
    "'$CITADEL' --socket '$SOCK' --json principal list | grep -q '\"$CI\"'"

citadel runtime-version add "$PB_VERSION" >/dev/null || die "cannot register $PB_VERSION"

# A previous run that was interrupted mid-teardown leaves a row behind, and the
# unique hostname index would then refuse the create with an error that says
# nothing about why.
if [ -n "$(sqlite3 "$STATE_DB" "SELECT id FROM tenant WHERE id='$SLUG'" 2>/dev/null)" ]; then
    note "reaping a leftover $SLUG from an earlier run"
    citadel tenant destroy "$SLUG" --no-backup --purge >/dev/null 2>&1 || true
    wait_gone || die "cannot reap the leftover tenant $SLUG"
fi

citadel tenant create --slug "$SLUG" --pb-version "$PB_VERSION" --owner "$OWNER" --disk-mib 256 \
    || die "tenant create failed"
check "the empty tenant is reachable before any package" tenant_get /api/health

# ── 1. upload and deploy ─────────────────────────────────────────────────────
log "1. a package uploads, validates and goes live"
PKG1="$(pack pkg-basic)" || die "cannot build the pkg-basic zip"
citadel release upload "$SLUG" --file "$PKG1" --deploy || bad "upload+deploy of pkg-basic failed"
REL1="$(latest_release)"
note "release $REL1"

check "the hook from the uploaded package serves" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q '\"rev\":1'"
check "the package's migration created the notes collection" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' \
      http://127.0.0.1/api/collections/notes/records | grep -q 'items'"
check "the release is recorded as deployed" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT status FROM release WHERE id='$REL1'\" | grep -qx deployed"
check "the tenant points at it" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT current_release FROM tenant WHERE id='$SLUG'\" | grep -qx '$REL1'"
check "a pre_deploy snapshot was taken" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM backup WHERE tenant_id='$SLUG' AND kind='pre_deploy'\")\" -ge 1 ]"
check_not "a hook still cannot write to its own release" bash -c \
    "ls '$PB_ROOT/artifacts'/*/pb_hooks/ESCAPE_MARKER"

# A record written now is what proves the broken deploy in section 3 is
# survivable: it must still be here afterwards.
tenant_get /api/collections/notes/records -X POST -H 'Content-Type: application/json' \
    -d '{"body":"written before the bad deploy"}' >/dev/null \
    || bad "cannot write a record through the deployed app"

# ── 2. a second release goes live ────────────────────────────────────────────
log "2. a second release deploys and replaces the running code"
PKG2="$(pack pkg-v2)" || die "cannot build the pkg-v2 zip"
citadel release upload "$SLUG" --file "$PKG2" --deploy || bad "upload+deploy of pkg-v2 failed"
REL2="$(latest_release)"
check "the new hook code is what serves now" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q '\"rev\":2'"
check "the release history shows both" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM release WHERE tenant_id='$SLUG'\")\" -ge 2 ]"
check "the record written under rev 1 is still readable" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' \
      http://127.0.0.1/api/collections/notes/records | grep -q 'written before the bad deploy'"

# ── 3. a broken migration auto-rolls-back ────────────────────────────────────
log "3. a deliberately broken migration rolls back, with the data intact"
PKG3="$(pack pkg-broken-migration)" || die "cannot build the pkg-broken-migration zip"
OUT="$WORK/broken.out"
if citadel release upload "$SLUG" --file "$PKG3" --deploy >"$OUT" 2>&1; then
    bad "a package whose migration fails reported success"
else
    ok "the deploy failed rather than reporting success"
fi
sed 's/^/        /' "$OUT"
check "the failure names the rollback and the snapshot it restored" \
    grep -q "rolled back" "$OUT"
check "the container's own output is surfaced to the tenant" \
    grep -qi "migration\|error" "$OUT"

REL3="$(latest_release)"
check "the failed release is recorded as failed" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT status FROM release WHERE id='$REL3'\" | grep -qx failed"
check "the tenant still points at the previous release" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT current_release FROM tenant WHERE id='$SLUG'\" | grep -qx '$REL2'"
check "the previous release's code is serving again" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q '\"rev\":2'"
# The migration deleted the notes and COMMITTED before the boot failed, so this
# record only exists because the pre_deploy snapshot was restored.
check "THE DATABASE IS INTACT: the record survives the broken migration" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' \
      http://127.0.0.1/api/collections/notes/records | grep -q 'written before the bad deploy'"
check "the rollback is audited" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG' \
       AND action='release.deploy.failed'\")\" -ge 1 ]"

# ── 4. explicit rollback ─────────────────────────────────────────────────────
log "4. rollback to an earlier release"
citadel rollback "$SLUG" --release "$REL1" || bad "explicit rollback failed"
check "rev 1 is serving again" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q '\"rev\":1'"
check "current_release follows the rollback" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT current_release FROM tenant WHERE id='$SLUG'\" | grep -qx '$REL1'"
check "the rollback is audited as a rollback, not as a deploy" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM audit_event WHERE tenant_id='$SLUG' \
       AND action='release.rolled_back'\")\" -ge 1 ]"

# ── 5. a Tier-0 egress host is rejected ──────────────────────────────────────
log "5. a package naming a never-grantable host is rejected, with a reason"
PKG0="$(pack pkg-egress-tier0)" || die "cannot build the pkg-egress-tier0 zip"
OUT="$WORK/tier0.out"
if citadel release upload "$SLUG" --file "$PKG0" >"$OUT" 2>&1; then
    bad "a package naming the metadata endpoint was accepted"
else
    ok "the upload was rejected"
fi
check "the error names the offending host" grep -q "169.254.169.254" "$OUT"
check_not "no release row was created for it" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT count(*) FROM release WHERE manifest LIKE '%169.254.169.254%'\" | grep -qx 1"

# ── 6. a Tier-2 host deploys, pending and unreachable ────────────────────────
log "6. a Tier-2 host deploys successfully and stays unreachable, named"
PKG4="$(pack pkg-egress-tier2)" || die "cannot build the pkg-egress-tier2 zip"
citadel release upload "$SLUG" --file "$PKG4" --deploy || bad "the Tier-2 package did not deploy"
check "the app is live despite the pending host" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q ok"
check "the concrete host was auto-granted (Tier 1)" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT decision FROM access_grant WHERE tenant_id='$SLUG' \
       AND subject='api.stripe.com'\" | grep -qx auto_approved"
check "the wildcard host is pending, not granted (Tier 2)" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT decision FROM access_grant WHERE tenant_id='$SLUG' \
       AND subject='*.slack.com'\" | grep -qx pending"
check "the tenant is told which host is waiting, by name" bash -c \
    "'$CITADEL' --socket '$SOCK' --as '$OWNER' egress '$SLUG' | grep -q '\\*.slack.com'"
check "the approval queue shows it to an operator" bash -c \
    "'$CITADEL' --socket '$SOCK' --as '$OWNER' grant list | grep -q '\\*.slack.com'"
# The egress suite covers the enforcement these two checks used to assert was absent.
# They still mean something, and they mean something sharper: the Tier-1 host
# is now genuinely reachable, and the Tier-2 one is still not — which is the
# whole point of §14.3's "a deploy never blocks on a Tier-2 grant".
sleep 8   # one reconcile tick, so the derivation has been applied
check "the Tier-1 host IS enforced: the tenant now has an outbound path" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT egress_enabled FROM tenant WHERE id='$SLUG'\" | grep -qx 1"
check "the Tier-1 host is in the live proxy allowlist" \
    grep -q 'api.stripe.com' "$PB_ROOT/egress/squid.conf"
check_not "the PENDING Tier-2 host is NOT in the allowlist" \
    grep -q 'slack.com' "$PB_ROOT/egress/squid.conf"
check_not "no accept rule was written for the pending host" bash -c \
    "GID=\$(sqlite3 '$STATE_DB' \"SELECT id FROM access_grant WHERE tenant_id='$SLUG' \
       AND subject='*.slack.com'\"); iptables -L DOCKER-USER -n | grep -q \"grant=\$GID\""

# ── 7. a revoked subject is not auto-granted again (§14.7) ───────────────────
log "7. revoke, then redeploy the same package: the host needs a human again"
GID="$(sqlite3 "$STATE_DB" "SELECT id FROM access_grant WHERE tenant_id='$SLUG' AND subject='api.stripe.com' ORDER BY requested_at DESC LIMIT 1")"
citadel grant revoke "$SLUG" "$GID" || bad "revoke failed"
citadel release upload "$SLUG" --file "$PKG4" --deploy || bad "redeploy after revoke failed"
check "the re-request is pending, not auto-granted" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT decision FROM access_grant WHERE tenant_id='$SLUG' \
       AND subject='api.stripe.com' AND revoked_at IS NULL ORDER BY requested_at DESC LIMIT 1\" \
     | grep -qx pending"
check "the revocation is audited" bash -c \
    "[ \"\$(audit_count \"tenant_id='$SLUG' AND action='grant.revoked'\")\" -ge 1 ]"

log "7b. an operator decision closes the queue item"
GID2="$(sqlite3 "$STATE_DB" "SELECT id FROM access_grant WHERE tenant_id='$SLUG' AND subject='*.slack.com' AND decision='pending' LIMIT 1")"
citadel grant approve "$GID2" --justification "package acceptance" || bad "approve failed"
check "the grant is approved with a named approver" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT decided_by FROM access_grant WHERE id='$GID2'\" | grep -qx '$OWNER'"
GID3="$(sqlite3 "$STATE_DB" "SELECT id FROM access_grant WHERE tenant_id='$SLUG' AND subject='api.stripe.com' AND decision='pending' LIMIT 1")"
citadel grant deny "$GID3" --reason "not needed for this app" || bad "deny failed"
check "the denial reason is stored verbatim for the tenant" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT justification FROM access_grant WHERE id='$GID3'\" | grep -q 'not needed'"

# ── 8. two-party ownership transfer ──────────────────────────────────────────
log "8. an ownership transfer requires acceptance by the target"
citadel owner transfer "$SLUG" --to "$HEIR" || bad "offer failed"
check "ownership has NOT moved on the offer alone" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT principal_id FROM current_owner WHERE tenant_id='$SLUG'\" | grep -qx '$OWNER'"
check_not "the offering owner cannot accept on the target's behalf" \
    citadel owner accept "$SLUG"
citadel_as "$HEIR" owner accept "$SLUG" || bad "the target could not accept"
check "ownership moved on acceptance" bash -c \
    "sqlite3 '$STATE_DB' \"SELECT principal_id FROM current_owner WHERE tenant_id='$SLUG'\" | grep -qx '$HEIR'"
check "exactly one active owner remains" bash -c \
    "[ \"\$(sqlite3 '$STATE_DB' \"SELECT count(*) FROM tenant_owner WHERE tenant_id='$SLUG' \
       AND role='owner' AND revoked_at IS NULL\")\" = 1 ]"
check "both halves are audited" bash -c \
    "[ \"\$(audit_count \"tenant_id='$SLUG' AND action IN ('tenant.owner.transfer_offered','tenant.owner.transferred')\")\" -ge 2 ]"
# Give the new owner the deployer role back to the original principal, so the
# rest of the suite can still act.
citadel_as "$HEIR" owner transfer "$SLUG" --to "$OWNER" >/dev/null 2>&1 || true
citadel owner accept "$SLUG" >/dev/null 2>&1 || true

# ── 9. a CI token deploy has a real actor ────────────────────────────────────
log "9. a token-authenticated deploy is attributed to its service account"
TOKEN="$(citadel --json token create --principal "$CI" --name acceptance | grep -o '"secret": *"[^"]*"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || die "token create returned no secret"
# The service account needs a role on the tenant: a token authenticates, a role
# authorises (§14.1).
sqlite3 "$STATE_DB" "INSERT INTO tenant_owner (id,tenant_id,principal_id,role,granted_by,granted_at) \
  VALUES ('ci-role','$SLUG','$CI','deployer','$OWNER',strftime('%Y-%m-%dT%H:%M:%SZ','now'))"

BEFORE="$(audit_count "tenant_id='$SLUG' AND actor_id='$CI'")"
curl -fsS -m 300 -X POST -H "Authorization: Bearer $TOKEN" \
    "$PORTAL/api/v1/tenants/$SLUG/releases/$REL1/deploy" >/dev/null \
    || bad "the token deploy failed"
AFTER="$(audit_count "tenant_id='$SLUG' AND actor_id='$CI'")"
if [ "$AFTER" -gt "$BEFORE" ]; then
    ok "the CI deploy is attributed to $CI in the audit log"
else
    bad "the CI deploy left no audit row for $CI"
fi
check "the token's last use was recorded" bash -c \
    "[ -n \"\$(sqlite3 '$STATE_DB' \"SELECT last_used_at FROM api_token WHERE principal_id='$CI'\")\" ]"
# The header is attribution on the socket and impersonation on a port. It must
# do nothing here.
check_not "X-V2P-Principal is NOT honoured on the TCP listener" bash -c \
    "curl -fsS -m 30 -X POST -H 'X-V2P-Principal: platform' \
      '$PORTAL/api/v1/tenants/$SLUG/releases/$REL1/deploy'"
# The newest live one: an earlier run's token is still in the table, revoked.
REVOKE_ID="$(sqlite3 "$STATE_DB" "SELECT id FROM api_token WHERE principal_id='$CI' \
  AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")"
citadel token revoke "$REVOKE_ID" >/dev/null || bad "token revoke failed"
check_not "a revoked token stops working immediately" bash -c \
    "curl -fsS -m 30 -H 'Authorization: Bearer $TOKEN' '$PORTAL/api/v1/tenants/$SLUG/releases'"

# ── 10. the portal ───────────────────────────────────────────────────────────
log "10. the portal: sign in, upload through the form, see it live"
citadel principal set-password "$OWNER" --password "$PORTAL_PASS" >/dev/null \
    || bad "cannot set a portal password"

JAR="$WORK/cookies"
check "an unauthenticated page redirects to the login form" bash -c \
    "curl -sS -o /dev/null -w '%{http_code}' '$PORTAL/' | grep -qx 303"
curl -sS -c "$JAR" -o /dev/null "$PORTAL/login"
curl -sS -b "$JAR" -c "$JAR" -o /dev/null -X POST \
    -d "principal=$OWNER" -d "password=$PORTAL_PASS" "$PORTAL/login"
check "the session cookie was issued" grep -q v2p_session "$JAR"
check "the project list shows the tenant" bash -c \
    "curl -sS -b '$JAR' '$PORTAL/' | grep -q '$SLUG'"
check "the tenant page renders with its releases" bash -c \
    "curl -sS -b '$JAR' '$PORTAL/t/$SLUG' | grep -q 'Releases'"
check "a wrong password is refused" bash -c \
    "curl -sS -o /dev/null -w '%{http_code}' -X POST -d 'principal=$OWNER' -d 'password=wrong' \
      '$PORTAL/login' | grep -qx 303 && curl -sS -X POST -d 'principal=$OWNER' -d 'password=wrong' \
      -o /dev/null -D - '$PORTAL/login' | grep -qi 'location: /login?err'"

CSRF="$(curl -sS -b "$JAR" "$PORTAL/t/$SLUG" | grep -o 'name="csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)"
check "the page carries a CSRF token" bash -c "[ -n '$CSRF' ]"
check_not "a form post without the CSRF token is refused" bash -c \
    "curl -sS -f -b '$JAR' -X POST -F 'package=@$PKG2' '$PORTAL/t/$SLUG/upload'"
curl -sS -b "$JAR" -o "$WORK/upload.html" -X POST -F "csrf=$CSRF" -F "package=@$PKG2" \
    -F "deploy=1" -L "$PORTAL/t/$SLUG/upload"
check "the browser upload deployed and the new code is live" bash -c \
    "curl -fsS -m 10 -H 'Host: $SLUG.$APPS_DOMAIN' http://127.0.0.1/fixture/ping | grep -q '\"rev\":2'"
check "the upload is attributed to the portal user" bash -c \
    "[ \"\$(audit_count \"tenant_id='$SLUG' AND actor_id='$OWNER' AND action='release.uploaded'\")\" -ge 1 ]"
check "the login is audited" bash -c \
    "[ \"\$(audit_count \"action='auth.login.succeeded'\")\" -ge 1 ]"
check "a failed login is audited too" bash -c \
    "[ \"\$(audit_count \"action='auth.login.failed'\")\" -ge 1 ]"
# The portal is a host listener, which is only safe because tenant bridges
# cannot reach host ports at all. Re-checked, not assumed.
check "the platform INPUT drop is still in place" \
    iptables -C INPUT -i br-t-+ -m comment --comment "v2p platform host-protect" -j DROP
check_not "the portal is not published through the edge proxy" bash -c \
    "curl -fsS -m 5 -H 'Host: portal.$APPS_DOMAIN' http://127.0.0.1/"

# ── 11. the audit chain ──────────────────────────────────────────────────────
log "11. the audit chain covers this run and is still append-only"
for action in release.uploaded release.deployed release.deploy.failed release.rolled_back \
              backup.created backup.restored grant.auto_approved grant.requested \
              grant.approved grant.denied grant.revoked tenant.owner.transfer_offered \
              tenant.owner.transferred auth.token.created auth.token.revoked \
              auth.credential.set auth.login.succeeded; do
    check "an audit row exists for $action" bash -c \
        "[ \"\$(audit_count \"action='$action'\")\" -ge 1 ]"
done
check_not "no audit row has a NULL actor" bash -c \
    "sqlite3 '$STATE_DB' 'SELECT count(*) FROM audit_event WHERE actor_id IS NULL' | grep -vqx 0"
check "UPDATE on an audit row is refused by the database" bash -c \
    "sqlite3 '$STATE_DB' \"UPDATE audit_event SET action='x' WHERE seq=1\" 2>&1 | grep -q 'append-only'"
check "DELETE on an audit row is refused by the database" bash -c \
    "sqlite3 '$STATE_DB' 'DELETE FROM audit_event WHERE seq=1' 2>&1 | grep -q 'append-only'"
check "the chain verifies" citadel audit verify

note "audit trail for $SLUG:"
citadel audit query --tenant "$SLUG" --limit 60 2>/dev/null | sed 's/^/        /'

if [ "$KEEP" = 1 ]; then
    log "--keep: leaving $SLUG running"
    note "portal:   http://$VM_IP:${PORTAL_ADDR##*:}/   (sign in as $OWNER / $PORTAL_PASS)"
    note "the control plane is left running as pid $DAEMON_PID; stop it with:"
    note "  hack/in-vm.sh pkill -f controlplaned"
    note "app:      http://$SLUG.$APPS_DOMAIN/"
fi

echo
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32mPackage acceptance: all checks passed\033[0m\n'
    exit 0
fi
printf '\033[31mPackage acceptance: %d check(s) FAILED\033[0m\n' "$FAILS"
printf 'control-plane log: %s\n' "$LOG"
exit 1
