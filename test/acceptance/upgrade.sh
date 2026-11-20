#!/usr/bin/env bash
# Backups and independent upgrades. Run ON the Docker host, as root.
#
# Design §16's Phase 7 done-when, plus the backup work it rests on:
#
#   B  a routine backup is taken WITHOUT stopping the tenant, and restores
#   C  retention deletes what has expired and refuses to leave a tenant with
#      nothing; a restore onto a different runtime version is refused
#   D  a rehearsal is PROVEN to have had no egress, and leaves nothing behind
#   E  a deliberately incompatible package fails the rehearsal with NOTHING
#      touched — and one that declares a narrower range never rehearses at all
#   F  a tenant upgrades from the portal, with a rehearsal report first
#   G  a real failure during `applying` restores the snapshot and reverts the
#      digest automatically                                ← the headline clause
#   H  deploys and upgrades refuse to overlap, in both directions (INV-6)
#   I  EOL automation nags, then forces — and quarantines rather than applying
#      an upgrade its own rehearsal has just proven broken
#
# Usage: test/acceptance/upgrade.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG="${SLUG:-upg}"
# The version pair. PB_FROM must be a line whose JSVM API differs from PB_TO's,
# or the "deliberately incompatible" sections prove nothing: 0.22 predates the
# 0.23 rework that removed onAfterBootstrap, daos and models.
PB_FROM="${PB_FROM:-0.22.55}"
PB_TO="${PB_TO:-0.42.3}"
# A compatible pair for the happy path, so section F upgrades something that is
# genuinely expected to work.
PB_OK_FROM="${PB_OK_FROM:-0.38.2}"
OWNER="${OWNER:-person:acceptance-upgrade}"
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
SQUID="${SQUID:-citadel-squid}"
PORTAL_PASS="${PORTAL_PASS:-acceptance-upgrade-pw-1}"
DAEMON=bin/controlplaned
CITADEL=bin/citadel
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

FAILS=0
DAEMON_PID=""
LOG=/tmp/acceptance-upgrade-controlplaned.log
CONF=/tmp/acceptance-upgrade-config.json
JAR=/tmp/acceptance-upgrade-cookies.txt
WORK="$(mktemp -d /tmp/acceptance-upgrade-pkgs.XXXXXX)"

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
command -v curl >/dev/null    || die "curl is needed to drive the edge and the portal"

citadel() { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }
# "op" is the same principal on the same socket. The operator boundary in this
# platform is the LISTENER — the socket is 0600 and whoever opens it is already
# root — not the actor, which stays a real person so the audit row names a human
# (§14.1). The distinction is kept in the suite only to say which assertions are
# about the operator surface.
op() { citadel "$@"; }
# check() runs its argv directly, so the bash -c strings below start a shell
# that has never heard of these. Exported rather than inlined, so the assertions
# read as the commands an operator would actually type.
export -f citadel op
export CITADEL SOCK OWNER

# The probe image is not optional here: a rehearsal with no probe cannot report
# anything, and §12 makes the rehearsal the gate. Without it the suite would
# "pass" by never exercising the thing it exists to test.
# Host architecture, as digests.txt names it. Each file lists every arch, so
# the last line is not necessarily this host's.
case "$(uname -m)" in aarch64|arm64) HOST_ARCH=arm64 ;; *) HOST_ARCH=amd64 ;; esac
# digest_for FILE: the newest entry for this host's arch.
digest_for() { awk -v a="$HOST_ARCH" '!/^#/ && NF >= 2 && $(NF-1) == a { r = $NF } END { print r }' "$1" 2>/dev/null; }
PROBE_IMAGE="$(digest_for images/rehearse-probe/digests.txt)"
[ -n "$PROBE_IMAGE" ] || die "no images/rehearse-probe/digests.txt; run 'make probe-image' first"
note "probe image: $PROBE_IMAGE"

EDGE_IMAGE="$(digest_for images/edge-caddy/digests.txt)"
EDGE_IMAGE_JSON=""
[ -n "$EDGE_IMAGE" ] && EDGE_IMAGE_JSON="\"edge_image\": \"$EDGE_IMAGE\","

# Intervals are squeezed so a suite can observe schedules that are daily in
# production. eol_grace is zero: the wait is the thing being configured, not the
# thing being tested. rehearsal_hold keeps each rehearsal up before teardown: one
# that fails on its hooks lives about a second, too short for section D to
# inspect the isolation it is meant to prove.
cat >"$CONF" <<EOF
{
  "pb_root": "$PB_ROOT",
  "socket_path": "$SOCK",
  "apps_domain": "$APPS_DOMAIN",
  $EDGE_IMAGE_JSON
  "probe_image": "$PROBE_IMAGE",
  "portal_addr": "$PORTAL_ADDR",
  "portal_allow_public": true,
  "routine_backup_interval": "20s",
  "routine_backup_window": "",
  "backup_sweep_interval": "20s",
  "rehearsal_timeout": "8m",
  "rehearsal_hold": "15s",
  "upgrade_timeout": "20m",
  "eol_nag_interval": "20s",
  "eol_grace": "0s",
  "eol_force_batch": 3
}
EOF

pack() { python3 hack/pack.py "$1" "$WORK/$2.zip"; }

edge()      { curl -sS --max-time 60 -H "Host: $1.$APPS_DOMAIN" "$EDGE/$2"; }
edge_code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
                -H "Host: $1.$APPS_DOMAIN" "$EDGE/$2"; }
edge_code_is() { [ "$(edge_code "$1" "$2")" = "$3" ]; }
# edge_post SLUG PATH JSON: prints "<code> <body>" so a rejected write is
# visible rather than discarded.
edge_post() { curl -sS -w ' %{http_code}' --max-time 60 -H "Host: $1.$APPS_DOMAIN" \
                -H 'Content-Type: application/json' -d "$3" "$EDGE/$2"; }
export -f edge edge_code edge_code_is edge_post
export EDGE APPS_DOMAIN

# Exported, because check() runs its argv directly and the bash -c strings below
# would otherwise start a shell that has never heard of it.
q() { sqlite3 "$STATE_DB" "$1"; }
export -f q
export STATE_DB PB_ROOT

start_daemon() {
    # A previous run that aborted can leave a daemon holding the portal port,
    # and the new one then exits at start-up with the real failure buried in a
    # log nobody reads.
    pkill -f "controlplaned --config $CONF" 2>/dev/null && sleep 2
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
        note "--keep: leaving the tenants and the daemon (pid $DAEMON_PID) running"
        return
    fi
    for s in "$SLUG" "${SLUG}ok" "${SLUG}eol"; do
        citadel tenant destroy "$s" --no-backup --purge >/dev/null 2>&1
    done
    sleep 8
    stop_daemon
    rm -rf "$WORK" "$JAR"
}
trap cleanup EXIT

# job_state <slug> <jobid>
job_state() { citadel --json tenant upgrade-status "$1" "$2" | python3 -c \
    'import json,sys; print(json.load(sys.stdin).get("state",""))'; }

# await_job <slug> <jobid> — polls until terminal, then echoes the state.
await_job() {
    local s
    for _ in $(seq 1 240); do
        s="$(job_state "$1" "$2")"
        case "$s" in
            succeeded|failed|blocked|rehearsed) echo "$s"; return 0 ;;
        esac
        sleep 2
    done
    echo "timeout"
}

# await_ping <slug> — waits up to a minute for the tenant's hooks to answer.
await_ping() {
    for _ in $(seq 1 30); do
        edge_code_is "$1" "fixture/ping" 200 && return 0
        sleep 2
    done
    return 1
}
export -f await_ping

# start_job <slug> <version> [extra flags…] — echoes the job id.
start_job() {
    local s="$1" v="$2"; shift 2
    citadel --json tenant upgrade "$s" --to "$v" "$@" | python3 -c \
      'import json,sys; print(json.load(sys.stdin).get("id",""))'
}

# ── A. groundwork ────────────────────────────────────────────────────────────
log "A. two runtime versions registered, one tenant on the older one"
start_daemon
# A run that aborted leaves its tenants behind, and provisioning then fails on a
# unique hostname rather than on anything this suite is about.
for s in "$SLUG" "${SLUG}ok"; do
    if citadel tenant status "$s" >/dev/null 2>&1; then
        note "removing $s left over from an earlier run"
        citadel tenant destroy "$s" --no-backup --purge >/dev/null 2>&1
    fi
done
sleep 8
citadel principal create "$OWNER" --name "Upgrade acceptance" >/dev/null 2>&1
op runtime-version add "$PB_FROM" >/dev/null 2>&1
op runtime-version add "$PB_TO" >/dev/null 2>&1
op runtime-version add "$PB_OK_FROM" >/dev/null 2>&1

citadel tenant create --slug "$SLUG" --pb-version "$PB_FROM" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG on $PB_FROM"
pack test/fixtures/pkg-badhooks pkg-badhooks
citadel release upload "$SLUG" --file "$WORK/pkg-badhooks.zip" --deploy >/dev/null ||
    die "the legacy-hooks package did not deploy on $PB_FROM"

check "the tenant runs $PB_FROM" \
    bash -c "q \"SELECT runtime_version FROM tenant WHERE id='$SLUG'\" | grep -qx '$PB_FROM'"
check "its hooks work there: /fixture/ping answers 200" edge_code_is "$SLUG" "fixture/ping" 200

# ── B. a routine backup does not stop the tenant ─────────────────────────────
log "B. routine backups are taken live"
STARTED_BEFORE="$(docker inspect -f '{{.State.StartedAt}}' "pb-$SLUG")"
note "waiting for a routine pass (interval is 20s in this run)…"
for _ in $(seq 1 30); do
    [ "$(q "SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG' AND kind='routine'")" != 0 ] && break
    sleep 2
done
check "a routine snapshot was taken" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG' AND kind='routine'\")\" != 0 ]"
# The whole justification for VACUUM INTO: a nightly stop-the-world snapshot is
# a nightly outage. If the container restarted, it was not a live backup.
check "the container was NOT restarted for it" \
    bash -c "[ \"\$(docker inspect -f '{{.State.StartedAt}}' 'pb-$SLUG')\" = '$STARTED_BEFORE' ]"
check "it is recorded as the files format, not an image copy" \
    bash -c "q \"SELECT format FROM backup WHERE tenant_id='$SLUG' AND kind='routine' LIMIT 1\" | grep -qx files"
check "the tenant kept serving throughout" edge_code_is "$SLUG" "fixture/ping" 200

ROUTINE_PATH="$(q "SELECT path FROM backup WHERE tenant_id='$SLUG' AND kind='routine' ORDER BY created_at DESC LIMIT 1")"
check "the snapshot file exists on disk" test -s "$ROUTINE_PATH"
# The database inside it must be a database, not a torn copy. This is the check
# that would fail if the platform ever went back to cp-ing a live WAL file.
VERIFY_DIR="$WORK/verify"
mkdir -p "$VERIFY_DIR"
if tar -xf "$ROUTINE_PATH" -C "$VERIFY_DIR" 2>/dev/null ||
   { zstd -dc "$ROUTINE_PATH" 2>/dev/null | tar -x -C "$VERIFY_DIR"; }; then
    check "the vacuumed database passes integrity_check" \
        bash -c "sqlite3 '$VERIFY_DIR/data.db' 'pragma integrity_check' | grep -qx ok"
    check_not "the -wal sidecar was NOT carried into the snapshot" \
        test -e "$VERIFY_DIR/data.db-wal"
else
    bad "could not unpack the routine snapshot at $ROUTINE_PATH"
fi

# ── C. retention, and the restore guard ──────────────────────────────────────
log "C. retention sweeps, and a restore onto another version is refused"
# Expire every snapshot this tenant has. The sweep must still leave one: a
# retention policy that can empty a tenant's history is an outage waiting for a
# mistake.
q "UPDATE backup SET retain_until='2000-01-01T00:00:00Z' WHERE tenant_id='$SLUG'"
BEFORE_N="$(q "SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG'")"
note "expired $BEFORE_N snapshot(s); waiting for a sweep…"
sleep 25
AFTER_N="$(q "SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG'")"
check "the sweep deleted expired snapshots" bash -c "[ '$AFTER_N' -lt '$BEFORE_N' ]"
check "it left the tenant its newest one — never zero" bash -c "[ '$AFTER_N' -ge 1 ]"
check "a deletion is audited" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='backup.deleted'\")\" != 0 ]"
check "the pass itself is audited, so a sweep that ran is distinguishable from one that did not" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='backup.retention.swept'\")\" != 0 ]"
SWEPT_PATH="$(q "SELECT path FROM backup WHERE tenant_id='$SLUG' ORDER BY created_at DESC LIMIT 1")"
check "the surviving row still points at a file that exists" test -s "$SWEPT_PATH"

KEPT_ID="$(q "SELECT id FROM backup WHERE tenant_id='$SLUG' ORDER BY created_at DESC LIMIT 1")"
check "restoring the tenant's own snapshot works" citadel backup restore "$SLUG" "$KEPT_ID"
check "the restore is audited" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='backup.restored'\")\" != 0 ]"
# The INV-4 guard. Nothing at runtime catches a version mismatch — an old binary
# on migrated data serves /api/health perfectly — so this check is the whole
# defence.
q "UPDATE backup SET pb_version='$PB_TO' WHERE id='$KEPT_ID'"
check_not "a snapshot from another runtime version is REFUSED" \
    citadel backup restore "$SLUG" "$KEPT_ID"
check "an operator can still force it, deliberately" \
    op backup restore "$SLUG" "$KEPT_ID" --force
check "the forced restore says so on the record" \
    bash -c "q \"SELECT detail_json FROM audit_event WHERE action='backup.restored' ORDER BY seq DESC LIMIT 1\" | grep -q '\"forced\":true'"
# A forced restore across versions is data the current binary must not open
# (INV-4): the instance is left stopped for an operator to pin the runtime.
check "the forced restore left the tenant desired-stopped" \
    bash -c "q \"SELECT desired_state FROM tenant WHERE id='$SLUG'\" | grep -qx stopped"
q "UPDATE backup SET pb_version='$PB_FROM' WHERE id='$KEPT_ID'"
# The snapshot really was $PB_FROM data (only its row was edited), so starting
# it again on $PB_FROM is right here.
citadel tenant start "$SLUG" >/dev/null
await_ping "$SLUG" || bad "the tenant did not come back after the forced restore"

# ── D. the rehearsal is isolated, and leaves nothing behind ──────────────────
log "D. a rehearsal has NO egress, and full teardown is real"
JOB="$(start_job "$SLUG" "$PB_TO" --rehearse-only)"
[ -n "$JOB" ] || die "could not start a rehearse-only job"
note "job $JOB"

# Catch the rehearsal while it is running. The container is named for the job,
# so this does not race on a scan of everything — but the window has to cover
# the work BEFORE it exists: an mkfs of the tenant's full image plus a
# VACUUM INTO of its databases happen first, and on a slow disk that is minutes.
RH_NET=""
for i in $(seq 1 2000); do
    # A job that is already terminal will never create the container — a gated
    # one ends in milliseconds — so stop waiting rather than spin for minutes.
    if [ $((i % 25)) = 0 ]; then
        case "$(job_state "$SLUG" "$JOB")" in
            blocked|failed|rehearsed|succeeded)
                note "job $JOB ended ($(job_state "$SLUG" "$JOB")) before a rehearsal container was seen"
                break ;;
        esac
    fi
    if docker inspect "pb-rh-$JOB" >/dev/null 2>&1; then
        RH_NET="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "pb-rh-$JOB" 2>/dev/null)"
        # RH_NET is "net1 net2 "; unquoted on purpose so each network is an argument.
        # shellcheck disable=SC2086
        RH_SUBNET="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' ${RH_NET% } 2>/dev/null)"
        # shellcheck disable=SC2086
        RH_INTERNAL="$(docker network inspect -f '{{.Internal}}' ${RH_NET% } 2>/dev/null)"
        RH_ENV="$(docker inspect -f '{{json .Config.Env}}' "pb-rh-$JOB" 2>/dev/null)"
        RH_LABELS="$(docker inspect -f '{{json .Config.Labels}}' "pb-rh-$JOB" 2>/dev/null)"
        RH_RULES="$(iptables -S DOCKER-USER | grep -c "rehearsal=$JOB")"
        break
    fi
    sleep 0.2
done

if [ -n "$RH_NET" ]; then
    check "the rehearsal network is internal: true — no outbound path at all" \
        bash -c "[ '$RH_INTERNAL' = true ]"
    check "the rehearsal container is on exactly ONE network" \
        bash -c "[ \"\$(printf '%s' '$RH_NET' | wc -w)\" -eq 1 ]"
    check_not "it is NOT attached to the egress network, whatever the manifest asked for" \
        bash -c "printf '%s' '$RH_NET' | grep -q v2p-egress"
    check_not "it carries no HTTP_PROXY: a rehearsal has no proxy to reach" \
        bash -c "printf '%s' '$RH_ENV' | grep -q HTTP_PROXY"
    check "it is labelled for the JOB, not for the tenant" \
        bash -c "printf '%s' '$RH_LABELS' | grep -q 'v2p.rehearsal'"
    # No v2p.tenant label, or ManagedContainers would read the rehearsal as the
    # tenant's instance running the wrong digest — a drift alert the platform
    # manufactured itself.
    check_not "it does NOT carry the tenant label" \
        bash -c "printf '%s' '$RH_LABELS' | grep -q 'v2p.tenant'"
    check "the bridge matches br-t-+, so the host-protection drop covers it" \
        bash -c "docker network inspect -f '{{index .Options \"com.docker.network.bridge.name\"}}' ${RH_NET% } | grep -q '^br-t-rh'"
    check "exactly one DOCKER-USER rule exists for it: the intra-network accept" \
        bash -c "[ '$RH_RULES' -eq 1 ]"
    check_not "no per-grant accept was written for the rehearsal subnet" \
        bash -c "iptables -S DOCKER-USER | grep 'rehearsal=$JOB' | grep -q 'grant='"
else
    bad "never observed the rehearsal container (pb-rh-$JOB)"
fi

STATE="$(await_job "$SLUG" "$JOB")"
check "a rehearse-only job ends in a terminal state" \
    bash -c "[ '$STATE' = rehearsed ] || [ '$STATE' = failed ]"

# The witness the container cannot forge. It can lie about its own dial
# results; the proxy's log cannot.
if [ -n "${RH_SUBNET:-}" ] && docker inspect "$SQUID" >/dev/null 2>&1; then
    check_not "the egress proxy logged NOTHING from the rehearsal subnet" \
        bash -c "docker logs '$SQUID' 2>&1 | grep -q '${RH_SUBNET%%/*}'"
fi
# And the witness from inside: every attempt had to fail.
note "rehearsal error, if any: $(q "SELECT json_extract(rehearsal_json,'\$.error') FROM upgrade_job WHERE id='$JOB'")"
check "the report records outbound attempts, and none connected" \
    bash -c "q \"SELECT rehearsal_json FROM upgrade_job WHERE id='$JOB'\" | python3 -c \
      'import json,sys; d=json.load(sys.stdin); p=d.get(\"probe\") or {}; e=p.get(\"egress\") or []; sys.exit(0 if e and not any(x[\"connected\"] for x in e) else 1)'"

check_not "after teardown the rehearsal container is gone" docker inspect "pb-rh-$JOB"
check_not "the rehearsal network is gone" bash -c "docker network inspect 't-rh${JOB#uj-}'"
check_not "its firewall rule is gone" \
    bash -c "iptables -S DOCKER-USER | grep -q 'rehearsal=$JOB'"
check_not "the scratch data copy is gone, unmounted" \
    test -e "$PB_ROOT/scratch/rehearse/$JOB"
sleep 8
check_not "the next tick reports no unbacked rule" \
    bash -c "op --json fleet | grep -q unbacked_rule"
check_not "and no rehearsal residue" \
    bash -c "op --json fleet | grep -q rehearsal_residue"

# ── E. incompatible packages: blocked, with nothing touched ──────────────────
log "E. a deliberately incompatible package stops the upgrade"
DIGEST_BEFORE="$(q "SELECT image_digest FROM tenant WHERE id='$SLUG'")"
RUNNING_BEFORE="$(docker inspect -f '{{.Image}}' "pb-$SLUG")"
SNAPS_BEFORE="$(q "SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG' AND kind='pre_upgrade'")"

JOB2="$(start_job "$SLUG" "$PB_TO")"
STATE2="$(await_job "$SLUG" "$JOB2")"
check "the job failed on its rehearsal" bash -c "[ '$STATE2' = failed ]"
check "the rehearsal verdict is recorded as failed" \
    bash -c "q \"SELECT rehearsal FROM upgrade_job WHERE id='$JOB2'\" | grep -qx failed"
check "the report names the hook error, so the tenant can act on it" \
    bash -c "q \"SELECT rehearsal_json FROM upgrade_job WHERE id='$JOB2'\" | grep -qi 'onAfterBootstrap\|ReferenceError\|is not defined'"
# "Nothing touched" is the claim, so all four are checked rather than one.
check "the tenant's runtime version is unchanged" \
    bash -c "q \"SELECT runtime_version FROM tenant WHERE id='$SLUG'\" | grep -qx '$PB_FROM'"
check "its desired digest is unchanged" \
    bash -c "q \"SELECT image_digest FROM tenant WHERE id='$SLUG'\" | grep -qx '$DIGEST_BEFORE'"
check "the RUNNING image is unchanged" \
    bash -c "[ \"\$(docker inspect -f '{{.Image}}' 'pb-$SLUG')\" = '$RUNNING_BEFORE' ]"
check "NO pre_upgrade snapshot was taken: the ladder never got that far" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM backup WHERE tenant_id='$SLUG' AND kind='pre_upgrade'\")\" = '$SNAPS_BEFORE' ]"
check "the tenant is still serving on the old version" edge_code_is "$SLUG" "fixture/ping" 200
check "the tenant was told, with the failures in the notice" \
    bash -c "q \"SELECT body FROM notification WHERE tenant_id='$SLUG' AND kind='upgrade.rehearsal' ORDER BY created_at DESC LIMIT 1\" | grep -qi 'FAILED'"

log "E2. a package that declares a narrower range never rehearses at all"
pack test/fixtures/pkg-pinned pkg-pinned
citadel tenant create --slug "${SLUG}ok" --pb-version "$PB_OK_FROM" --owner "$OWNER" >/dev/null ||
    die "could not provision ${SLUG}ok"
citadel release upload "${SLUG}ok" --file "$WORK/pkg-pinned.zip" --deploy >/dev/null ||
    die "pkg-pinned did not deploy"
JOB3="$(start_job "${SLUG}ok" "$PB_TO")"
STATE3="$(await_job "${SLUG}ok" "$JOB3")"
check "the job is blocked, not failed: the gate refused before any work" \
    bash -c "[ '$STATE3' = blocked ]"
check "the refusal names the declared range and the version" \
    bash -c "q \"SELECT log FROM upgrade_job WHERE id='$JOB3'\" | grep -q '0.38'"
check "it never entered rehearsing" \
    bash -c "[ -z \"\$(q \"SELECT rehearsal FROM upgrade_job WHERE id='$JOB3'\")\" ]"
check "no rehearsal container was ever created for it" \
    bash -c "! docker inspect 'pb-rh-$JOB3' >/dev/null 2>&1"

# ── F. the portal path, with a report first ──────────────────────────────────
log "F. a tenant upgrades from the portal"
pack test/fixtures/pkg-basic pkg-basic
citadel release upload "${SLUG}ok" --file "$WORK/pkg-basic.zip" --deploy >/dev/null ||
    die "pkg-basic did not deploy on ${SLUG}ok"
citadel principal set-password "$OWNER" --password "$PORTAL_PASS" >/dev/null ||
    die "could not set a portal password"
rm -f "$JAR"
CSRF="$(curl -sS -c "$JAR" "$PORTAL/login" | grep -o 'name="csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)"
curl -sS -b "$JAR" -c "$JAR" -o /dev/null \
     --data-urlencode "principal=$OWNER" --data-urlencode "password=$PORTAL_PASS" \
     --data-urlencode "csrf=$CSRF" "$PORTAL/login"
PAGE="$(curl -sS -b "$JAR" "$PORTAL/t/${SLUG}ok?tab=runtime")"
export PAGE
check "the project page offers the upgrade" \
    bash -c "printf '%s' \"\$PAGE\" | grep -q 'Rehearse'"
check "and explains that rollback is a snapshot restore, not an image swap" \
    bash -c "printf '%s' \"\$PAGE\" | grep -qi 'one-way'"
PCSRF="$(printf '%s' "$PAGE" | grep -o 'name="csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)"

# A record written BEFORE the upgrade, read back after it: the thing a tenant
# actually cares about is that their data crossed the version boundary.
WROTE_F="$(edge_post "${SLUG}ok" api/collections/notes/records '{"body":"before the upgrade"}')"
check "the pre-upgrade record was written (200)" bash -c "[ '${WROTE_F##* }' = 200 ]"
note "write response: $WROTE_F"

curl -sS -b "$JAR" -o /dev/null -X POST \
     --data-urlencode "to=$PB_TO" --data-urlencode "rehearse_only=0" \
     --data-urlencode "csrf=$PCSRF" "$PORTAL/t/${SLUG}ok/upgrade"
JOB4="$(q "SELECT id FROM upgrade_job WHERE tenant_id='${SLUG}ok' ORDER BY created_at DESC LIMIT 1")"
check "the portal opened a job" bash -c "[ -n '$JOB4' ]"
STATE4="$(await_job "${SLUG}ok" "$JOB4")"
check "it succeeded" bash -c "[ '$STATE4' = succeeded ]"
check "the rehearsal ran first and passed" \
    bash -c "q \"SELECT rehearsal FROM upgrade_job WHERE id='$JOB4'\" | grep -qx passed"
check "a pre_upgrade snapshot was taken and recorded on the job" \
    bash -c "[ -n \"\$(q \"SELECT snapshot_id FROM upgrade_job WHERE id='$JOB4'\")\" ]"
check "it is retained for 30 days, not 48 hours" \
    bash -c "q \"SELECT julianday(retain_until) - julianday(created_at) FROM backup WHERE tenant_id='${SLUG}ok' AND kind='pre_upgrade' ORDER BY created_at DESC LIMIT 1\" | awk '{exit (\$1 > 29) ? 0 : 1}'"
check "the tenant now runs $PB_TO" \
    bash -c "q \"SELECT runtime_version FROM tenant WHERE id='${SLUG}ok'\" | grep -qx '$PB_TO'"
check "the running container matches the new desired digest — no drift" \
    bash -c "[ \"\$(docker inspect -f '{{.Image}}' 'pb-${SLUG}ok')\" = \"\$(docker image inspect -f '{{.Id}}' \"\$(q \"SELECT image_digest FROM tenant WHERE id='${SLUG}ok'\")\")\" ]"
check "the record written before the upgrade is still there afterwards" \
    bash -c "edge '${SLUG}ok' 'api/collections/notes/records' | grep -q 'before the upgrade'"
note "records after: $(edge "${SLUG}ok" api/collections/notes/records 2>&1 | head -c 400)"
check "the rehearsal report is on the job page" \
    bash -c "curl -sS -b '$JAR' '$PORTAL/t/${SLUG}ok/upgrade/$JOB4' | grep -qi 'Isolation'"
check "the whole ladder is audited" \
    bash -c "[ \"\$(q \"SELECT COUNT(DISTINCT action) FROM audit_event WHERE action LIKE 'upgrade.%'\")\" -ge 4 ]"

# ── G. a real failure during applying rolls back ─────────────────────────────
log "G. a failure while applying restores the snapshot"
# The failure is REAL, not injected: the same legacy-hooks package, upgraded
# with the rehearsal skipped, so verification genuinely fails on the new binary.
# PocketBase catches a throwing hook file and keeps serving, so what fails is
# the hook-registration check rather than a smoke request — which is the point:
# an instance that answers HTTP and runs none of its own hooks is broken, and
# verification has to say so.
#
# Skipping the rehearsal is operator-only: it is refused on the TCP listener and
# accepted here because this suite drives the management socket.
DIGEST_G="$(q "SELECT image_digest FROM tenant WHERE id='$SLUG'")"
WROTE_G="$(edge_post "$SLUG" api/collections/notes/records '{"body":"before the rollback"}')"
check "the pre-rollback record was written (200)" bash -c "[ '${WROTE_G##* }' = 200 ]"
note "write response: $WROTE_G"
JOB5="$(citadel --json tenant upgrade "$SLUG" --to "$PB_TO" --no-rehearse |
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')"
[ -n "$JOB5" ] || die "could not start the no-rehearsal upgrade"
STATE5="$(await_job "$SLUG" "$JOB5")"
check "the job failed" bash -c "[ '$STATE5' = failed ]"
check "it failed on the hooks, not on a smoke request" \
    bash -c "q \"SELECT log FROM upgrade_job WHERE id='$JOB5'\" | grep -qi 'did not register'"
check "its rehearsal is recorded as skipped, so the job says what was not done" \
    bash -c "q \"SELECT rehearsal FROM upgrade_job WHERE id='$JOB5'\" | grep -qx skipped"
check "a pre_upgrade snapshot exists, recorded BEFORE anything changed" \
    bash -c "[ -n \"\$(q \"SELECT snapshot_id FROM upgrade_job WHERE id='$JOB5'\")\" ]"
check "the runtime version was reverted" \
    bash -c "q \"SELECT runtime_version FROM tenant WHERE id='$SLUG'\" | grep -qx '$PB_FROM'"
check "the image digest was reverted with it" \
    bash -c "q \"SELECT image_digest FROM tenant WHERE id='$SLUG'\" | grep -qx '$DIGEST_G'"
check "the rollback is audited" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='upgrade.rolled_back'\")\" != 0 ]"
check "the instance is healthy again on the old version" edge_code_is "$SLUG" "fixture/ping" 200
check "the data written before the upgrade survived the restore" \
    bash -c "edge '$SLUG' 'api/collections/notes/records' | grep -q 'before the rollback'"
note "records after: $(edge "$SLUG" api/collections/notes/records 2>&1 | head -c 400)"
check "the fleet view shows the rollback, which is alerted on" \
    bash -c "op --json fleet | grep -q upgrade_rollback"
check "the running digest matches the reverted desired digest — no drift alert" \
    bash -c "! op --json fleet | grep -q '\"kind\":\"digest\"'"

# ── H. INV-6, both directions ────────────────────────────────────────────────
log "H. deploys and upgrades never overlap (INV-6)"
JOB6="$(start_job "$SLUG" "$PB_TO" --rehearse-only)"
[ -n "$JOB6" ] || die "could not start the interlock job"
check_not "a deploy is refused while an upgrade is in flight" \
    citadel release upload "$SLUG" --file "$WORK/pkg-badhooks.zip" --deploy
check_not "a second upgrade is refused too" \
    citadel tenant upgrade "$SLUG" --to "$PB_TO"
await_job "$SLUG" "$JOB6" >/dev/null
check "once the job ends, a deploy is accepted again" \
    citadel release upload "$SLUG" --file "$WORK/pkg-badhooks.zip" --deploy

# ── I. EOL automation ────────────────────────────────────────────────────────
log "I. EOL: nag, then force — and quarantine rather than break an instance"
# Cleared first: this database survives between runs, and a version that was
# deprecated by an earlier run already has a date to fall back on — which is
# correct behaviour and would make the assertion pass for the wrong reason.
q "UPDATE runtime_version SET eol_at = NULL, state = 'supported' WHERE version = '$PB_FROM'"
check "deprecating a version REQUIRES an EOL date" \
    bash -c "! op runtime-version set-state '$PB_FROM' --state deprecated 2>&1 | grep -qi 'is now'"
op runtime-version set-state "$PB_FROM" --state deprecated --eol-at "$(date -u -d '+30 days' +%Y-%m-%d 2>/dev/null || date -u -v+30d +%Y-%m-%d)" >/dev/null ||
    bad "could not deprecate $PB_FROM"
note "waiting for an EOL pass…"
sleep 25
check "the tenant on the deprecated version was nagged" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM notification WHERE tenant_id='$SLUG' AND kind='runtime.eol'\")\" != 0 ]"
check "the nag names the date it has to plan around" \
    bash -c "q \"SELECT body FROM notification WHERE tenant_id='$SLUG' AND kind='runtime.eol' ORDER BY created_at DESC LIMIT 1\" | grep -qi 'end of life'"
check "and it is on the audit record" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='runtime_version.eol.nagged'\")\" != 0 ]"
check "the fleet view names who is blocking the date" \
    bash -c "op --json fleet | grep -q eol_exposure"

# Past the date, with no grace: the platform moves them itself. This tenant's
# hooks are the ones that cannot work on $PB_TO, which is exactly the case the
# D11 default (design.md §12) is about.
op runtime-version set-state "$PB_FROM" --state eol --eol-at "$(date -u -d '-1 day' +%Y-%m-%d 2>/dev/null || date -u -v-1d +%Y-%m-%d)" >/dev/null ||
    bad "could not mark $PB_FROM end-of-life"
note "waiting for a forced upgrade…"
FORCED=""
for _ in $(seq 1 60); do
    FORCED="$(q "SELECT id FROM upgrade_job WHERE tenant_id='$SLUG' AND forced=1 ORDER BY created_at DESC LIMIT 1")"
    [ -n "$FORCED" ] && break
    sleep 2
done
check "the platform opened a forced job" bash -c "[ -n '$FORCED' ]"
if [ -n "$FORCED" ]; then
    check "the platform principal is its actor, not a person" \
        bash -c "q \"SELECT requested_by FROM upgrade_job WHERE id='$FORCED'\" | grep -qx platform"
    check "it is on the audit record as a scheduled force" \
        bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='runtime_version.eol.force_upgrade_scheduled'\")\" != 0 ]"
    await_job "$SLUG" "$FORCED" >/dev/null
    check "a forced job still rehearses, and still fails on a broken one" \
        bash -c "q \"SELECT rehearsal FROM upgrade_job WHERE id='$FORCED'\" | grep -qx failed"
    # Following the D11 default (design.md §12):
    # quarantine is reversible, a one-way migration onto known-broken hooks is
    # not.
    check "the upgrade was NOT applied" \
        bash -c "q \"SELECT runtime_version FROM tenant WHERE id='$SLUG'\" | grep -qx '$PB_FROM'"
    check "the tenant was quarantined instead" \
        bash -c "q \"SELECT quarantined FROM tenant WHERE id='$SLUG'\" | grep -qx 1"
    check "the edge returns 503" edge_code_is "$SLUG" "fixture/ping" 503
    check "its data is untouched and still mounted" \
        bash -c "mountpoint -q '$PB_ROOT/tenants/$SLUG/data'"
    check "the container was not stopped: quarantine is an ingress decision" \
        bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' 'pb-$SLUG')\" = true ]"
    check "the tenant was told why, with the rehearsal's failures" \
        bash -c "q \"SELECT body FROM notification WHERE tenant_id='$SLUG' AND kind='runtime.eol.quarantined' ORDER BY created_at DESC LIMIT 1\" | grep -qi 'not applied'"
    check "and an operator was told too" \
        bash -c "[ \"\$(q \"SELECT COUNT(*) FROM notification WHERE audience='operator' AND kind='runtime.eol.quarantined'\")\" != 0 ]"
    check "it is on the audit record" \
        bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='runtime_version.eol.quarantined'\")\" != 0 ]"
fi

# ── K. INV-11: no start path changes the runtime, and pin-runtime does ──────
log "K. a stopped tenant is never restarted on another image (INV-11)"
# Section I's forced EOL upgrade leaves this tenant quarantined; lifted so the
# last check can see it serve again.
op unquarantine "$SLUG" >/dev/null 2>&1
FROM_DIGEST="$(q "SELECT image_digest FROM tenant WHERE id='$SLUG'")"
FROM_VER="$(q "SELECT runtime_version FROM tenant WHERE id='$SLUG'")"
TO_DIGEST="$(q "SELECT image_digest FROM runtime_version WHERE version='$PB_TO'")"
citadel tenant stop "$SLUG" >/dev/null
sleep 10
# The stray row edit INV-11 exists for, made while the container is stopped.
q "UPDATE tenant SET runtime_version='$PB_TO', image_digest='$TO_DIGEST' WHERE id='$SLUG'"
DRIFT_BEFORE="$(q "SELECT COUNT(*) FROM audit_event WHERE action='instance.digest_drift.detected' AND tenant_id='$SLUG'")"
citadel tenant start "$SLUG" >/dev/null
sleep 15
check "the reconciler raised digest drift instead of starting it" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='instance.digest_drift.detected' AND tenant_id='$SLUG'\")\" -gt '$DRIFT_BEFORE' ]"
check_not "and the container is not running on the edited image" \
    bash -c "docker inspect -f '{{.State.Running}}' pb-$SLUG 2>/dev/null | grep -qx true"
check_not "a restart is refused the same way" citadel tenant restart "$SLUG"
citadel tenant stop "$SLUG" >/dev/null
sleep 5
check_not "pin-runtime needs a justification" op tenant pin-runtime "$SLUG" --to "$FROM_VER"
check "pin-runtime puts the stopped tenant back on the image its data belongs to" \
    op tenant pin-runtime "$SLUG" --to "$FROM_VER" --justification "acceptance: undo a stray row edit"
check "the pin is on the audit record" \
    bash -c "[ \"\$(q \"SELECT COUNT(*) FROM audit_event WHERE action='instance.runtime.pinned' AND tenant_id='$SLUG'\")\" != 0 ]"
check "the row is back on $FROM_VER" \
    bash -c "q \"SELECT image_digest FROM tenant WHERE id='$SLUG'\" | grep -qx '$FROM_DIGEST'"
citadel tenant start "$SLUG" >/dev/null
check "and it starts again" await_ping "$SLUG"

# ── J. the chain ─────────────────────────────────────────────────────────────
log "J. the audit chain is intact and still append-only"
check "citadel audit verify passes" op audit verify
check_not "UPDATE on audit_event is refused by a trigger" \
    bash -c "q \"UPDATE audit_event SET action='x' WHERE seq=1\""
check_not "DELETE on audit_event is refused by a trigger" \
    bash -c "q \"DELETE FROM audit_event WHERE seq=1\""

# ── summary ──────────────────────────────────────────────────────────────────
printf '\n'
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32mUpgrade acceptance: all checks passed\033[0m\n'
    exit 0
fi
printf '\033[31mUpgrade acceptance: %d check(s) FAILED\033[0m\n' "$FAILS"
printf 'control-plane log: %s\n' "$LOG"
exit 1
