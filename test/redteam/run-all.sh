#!/usr/bin/env bash
# The §13.3 red-team suite. Run ON the Docker host, as root.
#
# Every probe must FAIL to achieve its goal, and the platform must stay healthy
# in every case. A probe that succeeds is a breach, not a failing test, and the
# distinction is why this script reports "ESCAPED" rather than "FAIL" for those.
#
# The rule every check here is held to: it must be ABLE to fail. A probe that
# could not have seen an escape — a route that 404'd, a hook that threw before
# it tried anything, a target that was unreachable for a reason unrelated to the
# boundary under test — reports FAIL, never "contained". Each technique carries
# a positive control that proves it would have noticed.
#
# The matrix splits four ways by what the attack actually needs:
#
#   tenant packages (here)     hostile pb_hooks, deployed like any release:
#                              the escape battery (exec, dropped binaries, mounts,
#                              sockets, rootfs, raw dials to metadata, the host,
#                              the internet, the neighbour, DNS), egress-allowed,
#                              egress-denied, grant-forge, tier2-kinds,
#                              proxy-pivot, fork-bomb, memory-hog, log-flood,
#                              disk-fill, infinite-hook (CPU cap and crash loop),
#                              symlink-swap, backup-bomb
#
#                              A hook HAS a raw socket: PocketBase's SMTP mailer
#                              dials the configured host itself and never looks at
#                              HTTP_PROXY. The battery's network attempts use it;
#                              $http.send cannot reach anything but the proxy.
#
#   malformed packages (here)  zip-bomb, traversal and Tier-0 egress requests
#                              never reach a container at all: they are rejected
#                              at upload with a named error, a §6 product surface
#
#   control-plane (here)       container posture, grant-revive, expired-grant,
#                              unbacked-rule, unbacked-acl, orphan-owner,
#                              breakglass-silent, and audit tampering (edit in
#                              place, wholesale rewrite, truncation) — asserted
#                              against citadel, docker and the state database
#
#   network probes             proxy bypass from foreign addresses, the rule
#   (test/netprobe)            ordering, the proxy manager surface, the control
#                              socket, the egress-bridge INPUT drop and the edge
#                              hairpin. Driven from here, asserted there.
#
# The audit-tamper section edits the shared state database on purpose, so it
# runs LAST and restores a snapshot afterwards: the audit table is append-only,
# and a tamper that outlived the run would fail every later `audit verify` on
# this host.
#
# Usage: test/redteam/run-all.sh [--keep]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit

SLUG="${SLUG:-rt}"
SLUG_EGRESS="${SLUG_EGRESS:-rtegr}"
PB_VERSION="${PB_VERSION:-0.42.2}"
OWNER="${OWNER:-person:redteam}"
PB_ROOT="${PB_ROOT:-/srv/citadel}"
STATE_DB="$PB_ROOT/control/state.db"
SOCK="${SOCK:-/run/citadel/control.sock}"
# Tenants are served as <slug>.$APPS_DOMAIN. nip.io resolves any name that
# embeds an IP to that IP, so a browser on the Mac reaches the VM directly. The
# suite itself never relies on DNS: it sends a Host header to 127.0.0.1.
VM_IP="${VM_IP:-$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)}"
APPS_DOMAIN="${APPS_DOMAIN:-apps.$VM_IP.nip.io}"
EDGE="${EDGE:-http://127.0.0.1}"
EGRESS_NET="${EGRESS_NET:-v2p-egress}"
# The configured limits the posture and resource sections hold the platform to.
# These are the config defaults; set them if the host's config differs.
PIDS_LIMIT="${PIDS_LIMIT:-128}"
LOG_MAX_BYTES="${LOG_MAX_BYTES:-16777216}"
LOG_KEEP="${LOG_KEEP:-5}"
# How long a raw dial may take before it counts as dropped. A live listener
# answers a TLS ClientHello in milliseconds; only a DROP stays silent.
RAW_DEADLINE="${RAW_DEADLINE:-12}"
DAEMON=bin/controlplaned
CITADEL=bin/citadel
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

FAILS=0
ESCAPES=0
DAEMON_PID=""
LOG=/tmp/redteam-controlplaned.log
CONF=/tmp/redteam-config.json
WORK="$(mktemp -d /tmp/redteam-pkgs.XXXXXX)"

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
ok()   { printf '    \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '    \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
# An escape is louder than a failure on purpose: a probe that reached its goal
# is a hole in the platform, and it must not read like a flaky assertion.
esc()  { printf '    \033[41;97mESCAPED\033[0m %s\n' "$*"; ESCAPES=$((ESCAPES + 1)); }
die()  { printf '\n\033[31mabort: %s\033[0m\n' "$*" >&2; exit 2; }

check()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
check_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
# contained: the posture holds when the command FAILS. Used for every attempt
# that must not reach its goal.
contained() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then esc "$d"; else ok "$d"; fi; }
# refused_for <desc> <ERE> cmd... — contained, and for the reason under test. A
# refusal that names something else (a missing file, a daemon error) proves
# nothing about the rule, so it is a broken probe rather than a PASS.
refused_for() {
    local d="$1" re="$2" out; shift 2
    if out="$("$@" 2>&1)"; then esc "$d"
    elif printf '%s' "$out" | grep -qiE "$re"; then ok "$d"
    else bad "$d — refused for another reason, so nothing was tested: ${out:0:160}"; fi
}
# holds: the posture holds when the command SUCCEEDS, and a failure is a hole
# rather than a broken assertion — a missing hardening flag, an unbounded limit.
holds()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else esc "$d"; fi; }

[ "$(id -u)" = 0 ] || die "must run as root on the Docker host"
[ -x "$DAEMON" ] || die "$DAEMON not built; run 'make build' on the Mac first"
[ -x "$CITADEL" ]  || die "$CITADEL not built; run 'make build' on the Mac first"
command -v sqlite3 >/dev/null || die "sqlite3 is needed to read the state database"
command -v python3 >/dev/null || die "python3 is needed to build the package zips"
command -v curl >/dev/null    || die "curl is needed to drive the probe routes"
command -v findmnt >/dev/null || die "findmnt is needed to read the data mounts"

citadel() { "$CITADEL" --socket "$SOCK" --as "$OWNER" "$@"; }
tsql()    { sqlite3 "$STATE_DB" "$1"; }
# tenant_col <slug> <column>
tenant_col() { sqlite3 "$STATE_DB" "SELECT $2 FROM tenant WHERE slug='$1'"; }

# write_conf [extra JSON members] — the daemon config, with optional additions.
write_conf() {
    cat >"$CONF" <<EOF
{
  "pb_root": "$PB_ROOT",
  "socket_path": "$SOCK",
  "apps_domain": "$APPS_DOMAIN",
  "portal_addr": "",
  "anchor_interval": "${ANCHOR_INTERVAL:-1m}"${1:+,
  $1}
}
EOF
}
write_conf

pack() { python3 hack/pack.py "test/redteam/$1" "$WORK/$1.zip"; }
# deploy <slug> <package> — pack and deploy; false when the deploy failed.
deploy() { pack "$2" && citadel release upload "$1" --file "$WORK/$2.zip" --deploy >/dev/null 2>&1; }

# probe <slug> <path> [max-time] — call a hook route through the EDGE, never the
# tenant's bridge address: the INPUT drop blocks host→tenant, and going round it
# would be testing a path no real request takes.
probe() {
    curl -sS --max-time "${3:-120}" -H "Host: $1.$APPS_DOMAIN" "$EDGE/$2"
}
wait_ping() {
    for _ in $(seq 1 "${2:-30}"); do
        probe "$1" redteam/ping 5 2>/dev/null | grep -q '"ok":true' && return 0
        sleep 2
    done
    return 1
}

# probe_has exists so an assertion never has to interpolate a
# hook's JSON into a `bash -c` string. check runs its argv directly, so a
# function keeps the quoting out of it — and a hook's error strings are tenant
# input that can contain quotes of their own.
probe_has() { probe "$1" "$2" | grep -q "$3"; }
# json_field <json> <object> <bool-key> — true when the field is true.
# A grep for '"allowed":{"reached":true' would depend on key ORDER, which Go's
# map marshalling does not promise.
json_field() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get(sys.argv[1],{}).get(sys.argv[2]) is True else 1)' \
      "$2" "$3"
}
# json_top <json> <bool-key> — the same, for a key at the top level.
json_top() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; sys.exit(0 if json.load(sys.stdin).get(sys.argv[1]) is True else 1)' "$2"
}
# jget <json> <python expression over d> — one value out of a report; empty on
# anything unparseable. The expression is always this script's, never input.
jget() {
    printf '%s' "$1" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    v = eval(sys.argv[1], {"d": d})
except Exception:
    sys.exit(1)
print(json.dumps(v) if isinstance(v, (dict, list, bool)) or v is None else v)' "$2" 2>/dev/null
}
# report_from <json> <fixture> — the hook answered with ITS OWN report. Without
# this, a 404 from a release that never deployed, an edge error page or a hook
# that threw all parse as "not reached" and read as contained.
report_from() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("fixture")==sys.argv[1] and not d.get("hook_error") else 1)' \
      "$2" 2>/dev/null
}

start_daemon() {
    "$DAEMON" --config "$CONF" --seed-digests images/pb-hardened/digests.txt \
        >>"$LOG" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 60); do
        [ -S "$SOCK" ] && "$CITADEL" --socket "$SOCK" fleet >/dev/null 2>&1 && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || { tail -40 "$LOG"; die "controlplaned exited at start-up"; }
        sleep 0.5
    done
    tail -40 "$LOG"; die "controlplaned did not open $SOCK"
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
    for s in "$SLUG" "$SLUG_EGRESS"; do
        citadel tenant destroy "$s" --no-backup --purge >/dev/null 2>&1
    done
    # Wait for the rows to go rather than sleeping a guess. Teardown happens on
    # the reconcile tick, and killing the daemon early leaves the tenant row
    # behind — the next run then fails to provision the same slug with a unique
    # -constraint error that says nothing about why (design.md §8.3).
    for _ in $(seq 1 40); do
        [ "$(tsql "SELECT COUNT(*) FROM tenant WHERE slug IN ('$SLUG','$SLUG_EGRESS')" 2>/dev/null)" = 0 ] && break
        sleep 1
    done
    stop_daemon
    rm -rf "$WORK"
}
trap cleanup EXIT

: >"$LOG"

# ── 0. bring the platform up ────────────────────────────────────────────────
log "0. platform"
start_daemon
citadel principal create "$OWNER" --name "Red team" >/dev/null 2>&1
# Two named operators, so the break-glass probe can assert that a session is
# reviewed by SOMEBODY ELSE. A self-review is not a review, and a tenant
# member's is not an operator's.
citadel principal create person:oncall --name "On call" >/dev/null 2>&1
citadel principal create person:reviewer --name "Reviewer" >/dev/null 2>&1
citadel principal operator person:oncall --on >/dev/null 2>&1
citadel principal operator person:reviewer --on >/dev/null 2>&1
check "the egress network exists" docker network inspect "$EGRESS_NET"
check "the egress proxy is running" \
    bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' citadel-squid)\" = true ]"
# The proxy is platform code. If it were reachable from outside, the allowlist
# would be an allowlist for the whole internet.
check_not "the egress proxy publishes no host port" \
    bash -c "[ \"\$(docker inspect -f '{{len .HostConfig.PortBindings}}' citadel-squid)\" != 0 ]"
check "the egress proxy runs with no added capabilities" \
    bash -c "docker inspect -f '{{json .HostConfig.CapDrop}}' citadel-squid | grep -q ALL"

# ── 1. malformed packages never reach a container ───────────────────────────
log "1. malformed packages are rejected at upload"
python3 - "$WORK" "$SLUG.$APPS_DOMAIN" <<'PY'
import os, sys, zipfile
work, neighbour = sys.argv[1], sys.argv[2]
manifest = ('{"schemaVersion":1,"name":"%s","version":"1.0.0",'
            '"pocketbase":{"min":"0.38.0","max":"0.42.x"}%s}')

# A zip bomb: one highly compressible entry that expands far past the 50 MiB
# uncompressed cap. Validation has to notice before it writes anything.
with zipfile.ZipFile(os.path.join(work, "zip-bomb.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("pbapp.json", manifest % ("bomb", ""))
    z.writestr("pb_public/big.txt", "0" * (200 * 1024 * 1024))

# Path traversal: an entry that would land outside the artifact directory.
with zipfile.ZipFile(os.path.join(work, "traversal.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("pbapp.json", manifest % ("trav", ""))
    z.writestr("../../../../etc/cron.d/pwned", "* * * * * root id\n")

# Tier 0 (§14.3): what upload can refuse by reading the manifest. The metadata
# address as a literal and in the hex form inet_aton reads, an IP in shorthand,
# and another tenant's hostname (route 3). None may ever become a grant, so the
# release itself is refused rather than shipped with the host pending.
#
# A NAME that resolves to one of those (169.254.169.254.nip.io) is accepted
# here on purpose: what a name resolves to at upload proves nothing about what
# it resolves to later. The proxy refuses it on every connection, and §4c
# probes exactly that.
for slug, host in (("t0meta", "169.254.169.254"), ("t0hex", "0xa9fea9fe"),
                   ("t0short", "10.0.1"), ("t0route3", neighbour)):
    with zipfile.ZipFile(os.path.join(work, "tier0-%s.zip" % slug), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pbapp.json", manifest % (slug, ',"egress":["%s"]' % host))
PY

# Both tenants up front: the battery's neighbour dial needs the other one to
# exist, and the posture section inspects both.
citadel tenant create --slug "$SLUG" --pb-version "$PB_VERSION" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG"
citadel tenant create --slug "$SLUG_EGRESS" --pb-version "$PB_VERSION" --owner "$OWNER" >/dev/null ||
    die "could not provision $SLUG_EGRESS"
RT_ID="$(tenant_col "$SLUG" id)"
EG_ID="$(tenant_col "$SLUG_EGRESS" id)"

refused_for "a zip bomb is rejected, not unpacked" 'implausible|too large' \
    citadel release upload "$SLUG" --file "$WORK/zip-bomb.zip"
refused_for "a path-traversal entry is rejected" 'escapes the package|outside the allowed' \
    citadel release upload "$SLUG" --file "$WORK/traversal.zip"
check_not "nothing was written outside the artifact store" test -e /etc/cron.d/pwned
refused_for "tier0-forge: the metadata address is refused at upload" 'not allowlistable' \
    citadel release upload "$SLUG_EGRESS" --file "$WORK/tier0-t0meta.zip"
refused_for "tier0-forge: the metadata address in hex is refused at upload" 'not allowlistable' \
    citadel release upload "$SLUG_EGRESS" --file "$WORK/tier0-t0hex.zip"
refused_for "tier0-forge: an IP in shorthand form is refused at upload" 'not allowlistable' \
    citadel release upload "$SLUG_EGRESS" --file "$WORK/tier0-t0short.zip"
refused_for "tier0-forge: another tenant's hostname is refused at upload" 'not allowlistable' \
    citadel release upload "$SLUG_EGRESS" --file "$WORK/tier0-t0route3.zip"

# ── the escape battery, as a function: it runs on both tenants ──────────────
# raw_targets <slug> <neighbour-slug> — label|host|port|expect, one per line.
# `reached` lines are positive controls: they MUST answer, or the dials that
# share their batch prove nothing.
raw_targets() {
    local slug="$1" other="$2" gw nip
    gw="$(tenant_col "$slug" gateway_ip)"
    nip="$(tenant_col "$other" container_ip)"
    printf '%s\n' \
        "control: a closed loopback port answers with a reset|127.0.0.1|1|reached" \
        "metadata-ssrf|169.254.169.254|80|contained" \
        "internet-open|1.1.1.1|443|contained" \
        "host-scan: own bridge gateway, ssh|$gw|22|contained" \
        "host-scan: own bridge gateway, closed port (a reset would prove the host answered)|$gw|1|contained" \
        "host-scan: the host's primary address|$VM_IP|22|contained" \
        "dns-exfil: a fresh name under a public wildcard zone|rt$RANDOM$RANDOM.127.0.0.1.nip.io|1|contained"
    [ -n "$nip" ] && printf '%s\n' "neighbour-scan: $other's instance|$nip|8090|contained"
    if [ -n "$(tenant_col "$slug" "COALESCE(egress_ip,'')")" ] &&
       docker inspect -f '{{json .NetworkSettings.Networks}}' "pb-$slug" 2>/dev/null | grep -q "$EGRESS_NET"; then
        local egw pip
        egw="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$EGRESS_NET" 2>/dev/null)"
        pip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" citadel-squid 2>/dev/null)"
        printf '%s\n' \
            "control: the egress proxy answers on the egress network|$pip|3128|reached" \
            "host-scan: the egress bridge gateway, ssh|$egw|22|contained"
    fi
}

# run_battery <slug> <neighbour-slug>
run_battery() {
    local slug="$1" other="$2" rep i label host port expect out reached why
    if ! deploy "$slug" escape-battery; then
        bad "battery ($slug): the escape-battery package did not deploy; nothing was tested"
        return
    fi
    rep="$(probe "$slug" redteam/report)"
    # Via a FILE, not a pipe. `python3 - <<'EOF'` takes the PROGRAM from stdin,
    # so a pipe into it is silently discarded and the script reads an empty
    # string — which looks exactly like "the route returned nothing".
    printf '%s' "$rep" >"$WORK/battery-$slug.json"
    python3 - "$WORK/battery-$slug.json" <<'PYEOF'
import json, sys
raw = open(sys.argv[1]).read()
try:
    data = json.loads(raw)
    assert data.get("fixture") == "escape-battery"
except (ValueError, AssertionError):
    # The route answered with something that is not its report. Print it: a
    # JSON traceback here says nothing about which boundary held.
    print("    the battery route did not return a report:")
    print("    " + raw[:400])
    sys.exit(2)
for a in data["attempts"]:
    status = "\033[41;97mESCAPED\033[0m" if a["escaped"] else "\033[32mPASS\033[0m"
    print("    %s %-24s %-8s %s" % (status, a["name"], a["boundary"], a["detail"][:90]))
for c in data["controls"]:
    status = "\033[32mPASS\033[0m" if c["ok"] else "\033[31mFAIL\033[0m"
    print("    %s control: %s %s" % (status, c["name"], c["detail"][:90]))
if data["escaped"]:
    sys.exit(1)
sys.exit(3 if data["controls_failed"] else 0)
PYEOF
    case $? in
        0) ok "battery ($slug): every local escape attempt was contained" ;;
        # 2 is "no report", which is a broken probe rather than a breach. Saying
        # so keeps ESCAPED meaning exactly one thing.
        2) bad "battery ($slug): the battery did not report; the probe could not run" ;;
        3) bad "battery ($slug): a positive control failed, so the attempts it guards proved nothing" ;;
        *) esc "battery ($slug): at least one escape attempt reached its goal (see above)" ;;
    esac
    jget "$rep" 'd["key_sha256"]' >"$WORK/keyhash-$slug" 2>/dev/null

    # The raw dials, in parallel, each with its own deadline. A DROP never
    # answers, so silence past the deadline is the contained outcome — and the
    # positive controls in the same batch prove the route itself was answering.
    raw_targets "$slug" "$other" >"$WORK/raw-$slug.targets"
    # Wait for THESE pids. A bare `wait` also waits for the daemon, which
    # start_daemon put in the background, and so never returns.
    local dials=()
    i=0
    while IFS='|' read -r label host port expect; do
        curl -sS --max-time "$RAW_DEADLINE" -H "Host: $slug.$APPS_DOMAIN" \
            "$EDGE/redteam/raw?host=$host&port=$port" >"$WORK/raw-$slug-$i.json" 2>/dev/null &
        dials+=("$!")
        i=$((i + 1))
    done <"$WORK/raw-$slug.targets"
    wait "${dials[@]}"
    i=0
    while IFS='|' read -r label host port expect; do
        out="$(cat "$WORK/raw-$slug-$i.json" 2>/dev/null)"
        i=$((i + 1))
        if [ -z "$out" ]; then
            reached=false; why="no answer in ${RAW_DEADLINE}s (dropped)"
        elif ! report_from "$out" escape-battery; then
            bad "raw ($slug) $label: the dial route did not report: ${out:0:120}"
            continue
        else
            reached="$(jget "$out" 'd["reached"]')"; why="$(jget "$out" 'd["error"]')"
        fi
        if [ "$expect" = reached ]; then
            if [ "$reached" = true ]; then ok "raw ($slug) $label"
            else bad "raw ($slug) $label — NOT reached ($why); the dials beside it prove nothing"; fi
        elif [ "$reached" = true ]; then
            esc "raw ($slug) $label: $host:$port answered — ${why:0:100}"
        else
            ok "raw ($slug) $label: contained — ${why:0:100}"
        fi
    done <"$WORK/raw-$slug.targets"
    check "battery ($slug): the instance is still healthy afterwards" \
        probe_has "$slug" "redteam/ping" '"ok":true'
}

# ── 2. the escape battery on a tenant with no grant ─────────────────────────
log "2. escape battery — $SLUG, no egress grant"
run_battery "$SLUG" "$SLUG_EGRESS"
check "the host is unaffected: the control plane is still answering" citadel tenant list

# ── 3. egress: the granted host works, everything else is refused ───────────
log "3. egress enforcement"
deploy "$SLUG_EGRESS" egress-probe || die "the egress-probe package did not deploy"

EG="$(probe "$SLUG_EGRESS" "redteam/egress")"
note "egress report: $EG"
# json_field, not a grep for '"allowed":{"reached":true'. Key ORDER is not
# promised, so the grep passes or fails depending on how the hook happened to
# build the object — observed passing one run and failing the next with an
# identical, correct report. This is the trap design.md §9.4 already
# records; json_field exists for it.
check "egress-allowed: the Tier-1 granted host is reachable" \
    json_field "$EG" allowed reached
check "egress-denied: a host with no grant is REFUSED BY THE PROXY, not timed out" \
    json_field "$EG" denied refused
sleep 12   # one reconcile tick: the proxy log is drained into the aggregate there
check "the denial was attributed to this tenant and recorded" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM egress_denial WHERE tenant_id='$EG_ID'\" | grep -qv '^0$'"
check "the denial is visible to the tenant at GET /egress" \
    bash -c "$CITADEL --socket '$SOCK' --as '$OWNER' egress '$SLUG_EGRESS' | grep -qi 'refused\\|denied'"

# ── 3b. the escape battery on a tenant that holds a grant ───────────────────
# The granted tenant is the one with a route out: it sits on the egress
# network, one hop from the proxy, the egress bridge gateway and every other
# granted tenant. Its own source address is what DOCKER-USER rules 3 and 4 are
# written against, and only a hook can dial from it.
log "3b. escape battery — $SLUG_EGRESS, holding an egress grant"
run_battery "$SLUG_EGRESS" "$SLUG"

# N7: the per-tenant key. Readable inside its own sandbox by construction (§5);
# what must hold is that it is PER tenant and appears nowhere it should not.
KEY_RT="$(cat "$WORK/keyhash-$SLUG" 2>/dev/null)"
KEY_EG="$(cat "$WORK/keyhash-$SLUG_EGRESS" 2>/dev/null)"
if [ -z "$KEY_RT" ] || [ -z "$KEY_EG" ]; then
    bad "per-tenant key: a battery did not report its key digest; uniqueness was not tested"
else
    holds "per-tenant key: the two tenants' encryption keys differ" test "$KEY_RT" != "$KEY_EG"
fi
for t in "$RT_ID" "$EG_ID"; do
    kf="$PB_ROOT/control/keys/$(tsql "SELECT enc_key_ref FROM tenant WHERE id='$t'")"
    if [ -s "$kf" ]; then
        key="$(tr -d '\n' <"$kf")"
        contained "per-tenant key: $t's key is not in the control-plane log" grep -qF "$key" "$LOG"
        contained "per-tenant key: $t's key is not in any audit row" \
            bash -c "sqlite3 '$STATE_DB' 'SELECT detail_json FROM audit_event' | grep -qF '$key'"
    else
        bad "per-tenant key: no key file at $kf"
    fi
done

# ── 3c. container posture, read from the host ───────────────────────────────
# What every probe above stands on. A tenant under runc instead of runsc, with
# no memory limit or an unbounded log, passes most of the battery anyway — so
# the configuration itself is asserted, against the live containers.
log "3c. container posture — the §4 flag set on the live containers"
posture() {
    local slug="$1" c="pb-$1" tid mem binds
    tid="$(tenant_col "$slug" id)"
    insp() { docker inspect -f "$1" "$c" 2>/dev/null; }
    holds "posture ($slug): runs under runsc (D2)" test "$(insp '{{.HostConfig.Runtime}}')" = runsc
    holds "posture ($slug): every capability dropped" test "$(insp '{{json .HostConfig.CapDrop}}')" = '["ALL"]'
    holds "posture ($slug): no capability added" test "$(insp '{{len .HostConfig.CapAdd}}')" = 0
    holds "posture ($slug): not privileged" test "$(insp '{{.HostConfig.Privileged}}')" = false
    holds "posture ($slug): no-new-privileges" \
        bash -c "docker inspect -f '{{json .HostConfig.SecurityOpt}}' '$c' | grep -q 'no-new-privileges:true'"
    holds "posture ($slug): read-only root filesystem" test "$(insp '{{.HostConfig.ReadonlyRootfs}}')" = true
    mem="$(insp '{{.HostConfig.Memory}}')"
    # Memory > 0 FIRST: with no limit at all, Memory and MemorySwap are both 0
    # and "equal", and a bare equality check passes an unbounded container.
    holds "posture ($slug): a memory limit is set" test "${mem:-0}" -gt 0
    holds "posture ($slug): swap disabled (memory-swap equals memory)" \
        test "$mem" = "$(insp '{{.HostConfig.MemorySwap}}')"
    holds "posture ($slug): a CPU limit is set" test "$(insp '{{.HostConfig.NanoCpus}}')" -gt 0
    holds "posture ($slug): the pids limit is the configured $PIDS_LIMIT" \
        test "$(insp '{{.HostConfig.PidsLimit}}')" = "$PIDS_LIMIT"
    holds "posture ($slug): Docker's restart policy is 'no' (the reconciler owns restarts)" \
        test "$(insp '{{.HostConfig.RestartPolicy.Name}}')" = no
    holds "posture ($slug): on its own network" \
        test "$(insp '{{.HostConfig.NetworkMode}}')" = "$(tenant_col "$slug" network_name)"
    holds "posture ($slug): no published ports" test "$(insp '{{len .HostConfig.PortBindings}}')" = 0
    binds="$(insp '{{json .HostConfig.Binds}}')"
    holds "posture ($slug): exactly two binds, pb_data rw and the release ro" \
        python3 -c '
import json, sys
b = json.loads(sys.argv[1] or "null") or []
ok = len(b) == 2 and sum(x.endswith(":/pb/pb_data:rw") for x in b) == 1 \
     and sum(x.endswith(":/pb/app:ro") for x in b) == 1
sys.exit(0 if ok else 1)' "$binds"
    holds "posture ($slug): the data image is mounted noexec,nosuid,nodev" \
        bash -c "findmnt -no OPTIONS '$PB_ROOT/tenants/$tid/data' | tr ',' '\n' | sort | grep -cx 'noexec\|nosuid\|nodev' | grep -qx 3"
    holds "posture ($slug): the runtime's own log is capped (max-size)" \
        bash -c "docker inspect -f '{{index .HostConfig.LogConfig.Config \"max-size\"}}' '$c' | grep -qv '^<no value>$\|^$'"
}
posture "$SLUG"
posture "$SLUG_EGRESS"

# ── 3d. unbacked-acl: proxy enforcement with nothing behind it ──────────────
# The proxy-side twin of `unbacked-rule` (§6): a host in the RUNNING proxy's
# allowlist with no grant behind it. The reconciler re-renders squid.conf from
# grants, so a hand edit does not survive a tick — and that is the point. A
# rewrite that leaves no record destroys the evidence exactly as removing an
# unbacked iptables rule would (§14.5). Either the attestation catches it while
# it is live, or the reconciler records what it overwrote. Neither is an escape.
log "3d. unbacked-acl — an allowlist entry with no grant is caught, not silently erased"
SQUID_CONF="$PB_ROOT/egress/squid.conf"
ACL_HOST="www.wikipedia.org"
TAMPER_T0="$(date -u +%Y-%m-%dT%H:%M:%S)"
if python3 - "$SQUID_CONF" "$EG_ID" "$ACL_HOST" <<'PY'
import sys
path, tid, host = sys.argv[1:]
lines = open(path).read().split("\n")
try:
    i = lines.index("# " + tid)
except ValueError:
    sys.exit(1)
done = 0
for j in range(i + 1, min(i + 8, len(lines))):
    if " dstdomain " in lines[j] or " ssl::server_name " in lines[j]:
        lines[j] += " " + host
        done += 1
open(path, "w").write("\n".join(lines))
sys.exit(0 if done else 1)
PY
then
    docker exec citadel-squid squid -k reconfigure >/dev/null 2>&1
    "$CITADEL" --socket "$SOCK" --as "$OWNER" attest generate "$SLUG_EGRESS" >/dev/null 2>&1
    BY_ATTEST=0
    tsql "SELECT mismatch_json FROM attestation WHERE tenant_id='$EG_ID'
           ORDER BY generated_at DESC LIMIT 1" | python3 -c "
import json, sys
f = json.loads(sys.stdin.read().strip() or '[]')   # NULL prints as an empty line
sys.exit(0 if any(x.get('kind') == 'egress_host' and x.get('subject') == '$ACL_HOST' for x in f) else 1)" &&
        BY_ATTEST=1
    sleep 12   # the reconciler re-renders the file on its tick
    BY_TICK=0
    [ "$(tsql "SELECT COUNT(*) FROM audit_event WHERE action='egress.acl.tampered'
               AND occurred_at >= '$TAMPER_T0'")" != 0 ] && BY_TICK=1
    note "caught by the attestation: $BY_ATTEST, recorded by the reconciler: $BY_TICK"
    holds "unbacked-acl: the entry was caught — by the attestation or by an audited repair" \
        test $((BY_ATTEST + BY_TICK)) -gt 0
    check "unbacked-acl: the reconciler restored the generated allowlist" \
        bash -c "! grep -qF '$ACL_HOST' '$SQUID_CONF'"
else
    bad "unbacked-acl: $SLUG_EGRESS has no allowlist block in $SQUID_CONF; nothing was tampered"
fi

# ── 4. grant-forge: a manifest cannot grant anything ───────────────
log "4. grant-forge — a wildcard ships pending and stays unreachable"
deploy "$SLUG_EGRESS" grant-forge ||
    bad "the grant-forge package did not deploy; a Tier-2 request must never block a deploy"
FORGE="$(probe "$SLUG_EGRESS" "redteam/forge")"
note "forge report: $FORGE"
if report_from "$FORGE" grant-forge; then
    contained "the wildcard host is unreachable despite being in the manifest" \
        json_field "$FORGE" wildcard reached
    check "the wildcard host is REFUSED BY THE PROXY, not timed out" \
        json_field "$FORGE" wildcard refused
else
    bad "grant-forge: the probe did not report; the wildcard was not tested"
fi
check "the wildcard landed as a PENDING grant, named to the tenant" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT decision FROM access_grant WHERE tenant_id='$EG_ID' AND subject='*.slack.com'\" \
      | grep -qx pending"

# ── 4b. tier2-kinds: a grant of the wrong kind never opens egress ─────────
log "4b. tier2-kinds — Tier-2 kinds land pending, and no kind but egress_host opens egress"
# The manifest can only ask for egress_host, so these are requested the way a
# tenant really would: through the grants API. The subjects are hostnames on
# purpose, and real ones — tier2-probe probes the same three, and a host that
# does not resolve fails whatever the proxy does.
#
#   kind            subject                  direction  TTL (§14.2)
T2_KINDS="oauth_provider:accounts.google.com:outbound:365
object_storage:storage.googleapis.com:outbound:180
custom_domain:www.iana.org:outbound:180
backup_export:s3.amazonaws.com/rt-export:inbound:7"

# t2_target <json> <kind> <key> — true when targets.<kind>.<key> is true.
t2_target() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; d=json.load(sys.stdin)["targets"]; sys.exit(0 if d.get(sys.argv[1],{}).get(sys.argv[2]) is True else 1)' \
      "$2" "$3"
}
# t2_report_ok <json> — the probe ran and reported. Without this, a hook that
# threw, a 404 from a release that never deployed or a curl timeout all parse
# as "not reached" and read as contained.
t2_report_ok() {
    printf '%s' "$1" | python3 -c \
      'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("fixture")=="tier2-probe" and not d.get("hook_error") and len(d.get("targets",{}))==3 else 1)'
}
# t2_assert_refused <phase> <json> — every outbound kind refused BY THE PROXY.
t2_assert_refused() {
    local phase="$1" rep="$2" kind
    if ! t2_report_ok "$rep"; then
        bad "tier2 ($phase): the probe did not report; nothing was tested"
        return
    fi
    for kind in oauth_provider object_storage custom_domain; do
        contained "tier2 ($phase): the $kind subject is not reachable" \
            t2_target "$rep" "$kind" reached
        check "tier2 ($phase): the $kind subject is REFUSED BY THE PROXY, not timed out" \
            t2_target "$rep" "$kind" refused
    done
}

T2_GIDS=""
while IFS=: read -r kind subject direction days; do
    resp="$(curl -sS --unix-socket "$SOCK" -H "X-V2P-Principal: $OWNER" \
        -H 'Content-Type: application/json' -X POST \
        -d "{\"kind\":\"$kind\",\"subject\":\"$subject\",\"justification\":\"redteam tier2-kinds\"}" \
        "http://controlplane/api/v1/tenants/$SLUG_EGRESS/grants")"
    gid="$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["grant"]["id"])' 2>/dev/null)"
    if [ -z "$gid" ]; then
        bad "tier2: the $kind request was not accepted: $resp"
        continue
    fi
    T2_GIDS="$T2_GIDS $gid"
    check "tier2: $kind landed PENDING at tier 2, $direction" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT decision || '|' || tier || '|' || direction FROM access_grant WHERE id='$gid'\" \
          | grep -qx 'pending|2|$direction'"
    # '|' as the separator: the two timestamps may be written in different
    # formats, one of which contains a space.
    check "tier2: $kind expires after the §14.2 default of $days days" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT requested_at || '|' || expires_at FROM access_grant WHERE id='$gid'\" |
          python3 -c \"
import sys, datetime
a, b = sys.stdin.read().strip().split('|')
p = lambda v: datetime.datetime.fromisoformat(v.replace('Z', '+00:00').replace(' ', 'T'))
days = (p(b) - p(a)).total_seconds() / 86400
sys.exit(0 if abs(days - $days) < 0.01 else 1)\""
done <<<"$T2_KINDS"

if ! deploy "$SLUG_EGRESS" tier2-probe; then
    bad "the tier2-probe package did not deploy; the tier2 probes were not run"
else
    T2="$(probe "$SLUG_EGRESS" "redteam/tier2")"
    note "tier2 report (pending): $T2"
    t2_assert_refused pending "$T2"

    # Approve them all. Nothing enforces these kinds (§16), so approval must
    # change nothing on the host: an approved oauth_provider is not an
    # approved egress host, whatever its subject looks like.
    for gid in $T2_GIDS; do
        citadel grant approve "$gid" --justification "redteam tier2-kinds" --days 1 >/dev/null ||
            bad "tier2: could not approve $gid"
    done
    sleep 12   # one reconcile tick
    while IFS=: read -r kind subject _ _; do
        host="${subject%%/*}"
        contained "tier2 (approved): $kind '$host' did not reach the live proxy ACL" \
            grep -qF "$host" "$SQUID_CONF"
    done <<<"$T2_KINDS"
    for gid in $T2_GIDS; do
        contained "tier2 (approved): no DOCKER-USER rule carries grant $gid" \
            bash -c "iptables -L DOCKER-USER -n | grep -q 'grant=$gid'"
    done
    T2="$(probe "$SLUG_EGRESS" "redteam/tier2")"
    note "tier2 report (approved): $T2"
    t2_assert_refused approved "$T2"

    # §16: the attestation says so explicitly, rather than reporting a match
    # that implies these grants are in force.
    "$CITADEL" --socket "$SOCK" --as "$OWNER" attest generate "$SLUG_EGRESS" >/dev/null 2>&1
    for gid in $T2_GIDS; do
        check "tier2 (approved): the attestation names $gid as having no enforcement path" \
            bash -c "sqlite3 '$STATE_DB' \
              \"SELECT mismatch_json FROM attestation WHERE tenant_id='$EG_ID'
                 ORDER BY generated_at DESC LIMIT 1\" |
              python3 -c \"
import json, sys
f = json.loads(sys.stdin.read().strip() or '[]')   # NULL prints as an empty line
sys.exit(0 if any(x.get('grant_id') == '$gid' and x.get('kind') == 'no_enforcement_path' for x in f) else 1)\""
    done
fi

# Withdraw them so the grant lifecycle and attestation checks below start
# from the state they were written against.
for gid in $T2_GIDS; do
    citadel grant revoke "$SLUG_EGRESS" "$gid" >/dev/null 2>&1
done

# ── 4c. proxy-pivot: a granted name re-pointed where no grant may go ────────
log "4c. proxy-pivot — the proxy refuses denied DESTINATIONS, whatever name led there"
# A tenant that controls DNS for a name it was granted can re-point it after
# approval: at the metadata endpoint, at the host, at another tenant, at the
# edge's own listener. That cannot be staged deterministically against public
# DNS, so the grants are written straight into the table — each row stands for
# "approved while it resolved somewhere harmless". nip.io answers with the
# address in the name, so each one now resolves into a denied range, and Squid's
# v2p_blocked_dst condition is the only thing left to refuse it (§9.5).
EGW="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$EGRESS_NET" 2>/dev/null)"
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$EGRESS_NET\").IPAddress}}" citadel-squid 2>/dev/null)"
PIVOT_NAMES="169.254.169.254.nip.io
127.0.0.1.nip.io
$VM_IP.nip.io
$(tenant_col "$SLUG" container_ip).nip.io
$EGW.nip.io"
# pivot_case <url> <access.log target> — one request through the proxy, judged
# by the PROXY's record of it. The hook alone cannot tell "the proxy cut it"
# from "the destination's TLS failed": a deny that waits on DNS (the dst ACL)
# answers the CONNECT 200 and then cuts the bumped session, so the hook sees a
# TLS error, not a reset. And a proxy that dialled the edge, whose certificate
# the hook then rejected, would look exactly the same from inside. Squid's
# access log says which: TCP_DENIED with HIER_NONE is a refusal that opened no
# upstream connection; any upstream hop is an escape whatever the hook saw.
PIVOT_SRC="$(tenant_col "$SLUG_EGRESS" "COALESCE(egress_ip,'')")"
pivot_case() {
    local url="$1" target="$2" before rep line code hier
    before="$(docker exec citadel-squid wc -l /var/log/squid/access.log 2>/dev/null | awk '{print $1}')"
    rep="$(probe "$SLUG_EGRESS" "redteam/pivot?url=$url")"
    if ! report_from "$rep" proxy-pivot; then
        bad "proxy-pivot: no report for $url"
        return
    fi
    line="$(docker exec citadel-squid tail -n +"$((${before:-0} + 1))" /var/log/squid/access.log 2>/dev/null |
        awk -v src="$PIVOT_SRC" -v t="$target" '$3 == src && $7 == t' | tail -1)"
    code="$(awk '{print $4}' <<<"$line")"; hier="$(awk '{print $9}' <<<"$line")"
    if json_top "$rep" reached; then
        esc "proxy-pivot: $url went through the proxy (${code:-no log line}, ${hier:-?})"
    elif [ -z "$line" ]; then
        bad "proxy-pivot: the proxy logged nothing for $url; it cannot be told apart from a request that never left the hook ($(jget "$rep" 'd.get("error","")' | cut -c1-90))"
    elif [ "${hier%%/*}" != HIER_NONE ]; then
        esc "proxy-pivot: the proxy dialled ${hier#*/} for $url ($code), whatever the hook then saw"
    elif [ "${code%%/*}" = TCP_DENIED ]; then
        ok "proxy-pivot: $url is REFUSED BY THE PROXY ($code, no upstream connection)"
    else
        bad "proxy-pivot: $url ended $code/$hier, neither a refusal nor an upstream hop"
    fi
}
PIVOT_GIDS=""
n=0
while read -r name; do
    n=$((n + 1))
    gid="g-rtpivot-$n"
    tsql "INSERT INTO access_grant (id, tenant_id, kind, direction, subject, tier, decision,
            requested_by, requested_at, decided_by, decided_at, policy_version, justification, expires_at)
          VALUES ('$gid', '$EG_ID', 'egress_host', 'outbound', '$name', 1, 'approved',
            '$OWNER', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'platform', strftime('%Y-%m-%dT%H:%M:%SZ','now'),
            'redteam', 'redteam proxy-pivot: stands in for a name re-pointed after approval',
            strftime('%Y-%m-%dT%H:%M:%SZ','now','+1 day'))" ||
        bad "proxy-pivot: could not stage the grant for $name"
    PIVOT_GIDS="$PIVOT_GIDS $gid"
done <<<"$PIVOT_NAMES"
if ! deploy "$SLUG_EGRESS" proxy-pivot; then
    bad "the proxy-pivot package did not deploy; the pivots were not tested"
else
    sleep 12   # one reconcile tick: the grants reach the running proxy
    PIV="$(probe "$SLUG_EGRESS" "redteam/pivot?url=https://example.com/")"
    if report_from "$PIV" proxy-pivot && json_top "$PIV" reached; then
        ok "proxy-pivot control: the granted example.com is reachable through the proxy"
    else
        bad "proxy-pivot control: example.com is not reachable ($PIV); the refusals below prove nothing"
    fi
    MGR="$(curl -sf --noproxy '*' --max-time 5 "http://$PROXY_IP:3128/squid-internal-mgr/config" 2>/dev/null)"
    printf '%s' "$MGR" | grep -q 'http_access' ||
        bad "proxy-pivot: the running proxy's configuration is unreadable; the allowlist was not confirmed"
    while read -r name; do
        # In the running allowlist, the refusal below is Squid's destination
        # check at work. Kept out of it, the name was stopped earlier — also
        # contained, but by a different layer, and said so.
        if printf '%s' "$MGR" | grep -qF "$name"; then
            note "$name is in the running allowlist; only the destination check stands in the way"
        else
            note "$name never reached the running allowlist (filtered before render)"
        fi
        pivot_case "https://$name/" "$name:443"
        pivot_case "http://$name/" "http://$name/"
    done <<<"$PIVOT_NAMES"
    # A granted host is granted on 443 (CONNECT) and 80/443 (plain), nothing
    # else: a granted name on :25 would be an SMTP relay nobody approved.
    pivot_case "https://example.com:22/" "example.com:22"
    pivot_case "http://example.com:25/" "http://example.com:25/"
fi
for gid in $PIVOT_GIDS; do
    citadel grant revoke "$SLUG_EGRESS" "$gid" >/dev/null 2>&1 ||
        tsql "UPDATE access_grant SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), revoked_by='$OWNER' WHERE id='$gid'"
done

# ── 5. expired-grant and grant-revive (§14.7) ───────────────────────────────
log "5. grant lifecycle — expiry and revocation need no operator action"
GID="$(tsql "SELECT id FROM access_grant WHERE tenant_id='$EG_ID' AND subject='example.com' LIMIT 1")"
[ -n "$GID" ] || bad "no grant row for example.com"

if [ -n "$GID" ]; then
    # Expiry is evaluated at READ time, so backdating expires_at is exactly what
    # the passage of time would do — no clock skew, no sleep, same code path.
    tsql "UPDATE access_grant SET expires_at = datetime('now','-1 hour') WHERE id='$GID'"
    note "backdated $GID; waiting one reconcile tick"
    sleep 12
    contained "expired-grant: the host is gone from the proxy allowlist within a tick" \
        bash -c "grep -q 'example.com' '$SQUID_CONF'"
    contained "expired-grant: the accept rule is gone from DOCKER-USER" \
        bash -c "iptables -L DOCKER-USER -n | grep -q 'grant=$GID'"
    # And end to end: the last grant going may recreate the container without
    # its egress attachment, so wait for it to serve before asking.
    wait_ping "$SLUG_EGRESS" 30
    PIV="$(probe "$SLUG_EGRESS" "redteam/pivot?url=https://example.com/")"
    if report_from "$PIV" proxy-pivot; then
        contained "expired-grant: the tenant can no longer reach example.com" json_top "$PIV" reached
    else
        bad "expired-grant: the pivot route did not report; expiry was not tested end to end"
    fi

    # §14.7: re-declaring a refused subject must not auto-grant it again.
    deploy "$SLUG_EGRESS" egress-probe
    tsql "UPDATE access_grant SET revoked_at = datetime('now'), revoked_by='$OWNER'
           WHERE tenant_id='$EG_ID' AND subject='example.com'"
    deploy "$SLUG_EGRESS" egress-probe
    check "grant-revive: a revoked subject re-enters as PENDING, never auto-granted" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT decision FROM access_grant WHERE tenant_id='$EG_ID'
             AND subject='example.com' ORDER BY requested_at DESC LIMIT 1\" | grep -qx pending"
    sleep 12
    wait_ping "$SLUG_EGRESS" 30
    EG="$(probe "$SLUG_EGRESS" "redteam/egress")"
    if report_from "$EG" egress-probe; then
        contained "grant-revive: the revived subject is unreachable while it is pending" \
            json_field "$EG" allowed reached
    else
        bad "grant-revive: the egress route did not report; the revival was not tested end to end"
    fi
fi

# ── 6. unbacked-rule: enforcement with nothing behind it ───────────
log "6. unbacked-rule — reported, never silently repaired"
iptables -I DOCKER-USER 2 -s 10.214.0.99 -d 10.214.0.2 -p tcp --dport 3128 \
    -m comment --comment "v2p tenant=$EG_ID grant=g-forged" -j ACCEPT
note "inserted a rule tagged with a grant that does not exist"
sleep 12
check "the control plane reported it" grep -q "grant=g-forged" "$LOG"
check "the rule was NOT removed: removing it destroys the evidence" \
    bash -c "iptables -L DOCKER-USER -n | grep -q 'g-forged'"
check "it is an audited event, not just a log line" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM audit_event WHERE action='netpolicy.rule.unbacked'\" | grep -qv '^0$'"

# §14.5: the alert says something is wrong; the attestation is the signed record
# of WHAT, and it is what the tenant's own report shows. Generated here, and the
# LATEST report asserted, so an earlier finding (3d) cannot stand in for this one.
"$CITADEL" --socket "$SOCK" --as "$OWNER" attest generate "$SLUG_EGRESS" >/dev/null 2>&1
check "the attestation names the outcome enforcement_without_grant" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT outcome FROM attestation WHERE tenant_id='$EG_ID'
         ORDER BY generated_at DESC LIMIT 1\" | grep -qx enforcement_without_grant"
check "the report is signed, so it can be checked by somebody who did not write it" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT signature FROM attestation WHERE tenant_id='$EG_ID'
         ORDER BY generated_at DESC LIMIT 1\" | grep -q ."
check "the forged grant id is named in the report, not just counted" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT mismatch_json FROM attestation WHERE tenant_id='$EG_ID'
         ORDER BY generated_at DESC LIMIT 1\" | grep -q 'g-forged'"
check "a signed report was also written where it can be replicated off the host" \
    bash -c "ls '$PB_ROOT/audit/attestations/$EG_ID'/*.json >/dev/null 2>&1"
check "citadel exits non-zero on the security outcome, so CI can gate on it" \
    bash -c "! '$CITADEL' --socket '$SOCK' --as '$OWNER' attest generate '$SLUG_EGRESS' >/dev/null 2>&1"
check "the rule is STILL there after the attestation ran" \
    bash -c "iptables -L DOCKER-USER -n | grep -q 'g-forged'"

# §14.5: and the tenant is FROZEN, so the configuration under investigation
# does not move until an operator says the investigation is over.
check "the security outcome froze the tenant" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT frozen_reason FROM tenant WHERE id='$EG_ID'\" | grep -q ."
check_not "a deploy is refused while it is frozen" \
    "$CITADEL" --socket "$SOCK" --as "$OWNER" release upload "$SLUG_EGRESS" --file "$WORK/egress-probe.zip" --deploy
check_not "lifting the freeze needs a reason" \
    "$CITADEL" --socket "$SOCK" --as "$OWNER" unfreeze "$SLUG_EGRESS"

iptables -D DOCKER-USER -s 10.214.0.99 -d 10.214.0.2 -p tcp --dport 3128 \
    -m comment --comment "v2p tenant=$EG_ID grant=g-forged" -j ACCEPT 2>/dev/null
check "the operator lifts the freeze once the planted rule is gone" \
    "$CITADEL" --socket "$SOCK" --as "$OWNER" unfreeze "$SLUG_EGRESS" --reason "redteam: unbacked-rule probe removed"
check "and the lift is on the audit record" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT COUNT(*) FROM audit_event WHERE action='tenant.unfrozen' AND tenant_id='$EG_ID'\" | grep -qv '^0$'"

# ── 7. orphan-owner ────────────────────────────────────────────────
log "7. orphan-owner — a tenant is never left without an accountable owner"
# Asserted against the PLATFORM's surface, not with a raw DELETE on the
# database. A direct write bypasses the control plane the way editing iptables
# by hand bypasses netpolicy: it proves that root can corrupt state, which was
# never in doubt and is not what the rule claims. The rule is that no
# operation the platform OFFERS can leave a tenant unowned.
check_not "the platform exposes no way to delete a principal at all" \
    bash -c "'$CITADEL' --socket '$SOCK' --as '$OWNER' principal delete '$OWNER'"
check "ownership is enforced in SQL, where it cannot be forgotten" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT sql FROM sqlite_master WHERE name='one_owner_per_tenant'\" \
      | grep -q \"role = 'owner' AND revoked_at IS NULL\""
contained "a second owner row for the same tenant is refused by that index" \
    bash -c "sqlite3 '$STATE_DB' \
      \"INSERT INTO tenant_owner (id,tenant_id,principal_id,role,granted_by,granted_at)
         VALUES ('forged','$RT_ID','$OWNER','owner','$OWNER',datetime('now'))\""
check "the tenant still has exactly one active owner row" \
    bash -c "sqlite3 '$STATE_DB' \
      \"SELECT COUNT(*) FROM tenant_owner WHERE tenant_id='$RT_ID' AND role='owner' AND revoked_at IS NULL\" \
      | grep -qx 1"

# ── 9. resource exhaustion ──────────────────────────────────────────────────
log "9. resource exhaustion — contained in the container, host unaffected"
DATA_DIR="$PB_ROOT/tenants/$RT_ID/data"
IMG_BYTES="$(stat -c %s "$PB_ROOT/tenants/$RT_ID/data.img" 2>/dev/null || echo 0)"
IMG_MIB=$((IMG_BYTES / 1048576))
DISK_MIB="$(tenant_col "$SLUG" disk_mib)"

# Each one is judged on what it REPORTS, and on evidence when it reports
# nothing: an empty answer is what a killed sandbox looks like, and also what a
# probe that never ran looks like.
resource_fork() {
    local out spawned limit
    out="$(probe "$SLUG" redteam/fork)"
    note "fork-bomb: ${out:0:200}"
    if ! report_from "$out" fork-bomb; then
        bad "fork-bomb: no report; the instance may have died, and nothing says which limit held"
        return
    fi
    spawned="$(jget "$out" 'd["spawned"]')"; limit="$(jget "$out" 'd["limit"]')"
    if [ "${spawned:-0}" -lt 1 ]; then
        bad "fork-bomb: nothing was spawned, so no limit was reached ($(jget "$out" 'd["stopped_by"]'))"
    elif ! json_top "$out" bounded; then
        esc "fork-bomb: $spawned processes started and no limit held"
    elif [ "$limit" = none ]; then
        bad "fork-bomb: stopped by something that is not a resource limit: $(jget "$out" 'd["stopped_by"]')"
    else
        ok "fork-bomb: $spawned children, then the $limit limit held"
    fi
}
resource_memory() {
    local out before_start before_rc after_start after_rc state
    before_start="$(docker inspect -f '{{.State.StartedAt}}' "pb-$SLUG" 2>/dev/null)"
    before_rc="$(tsql "SELECT restart_count FROM instance WHERE tenant_id='$RT_ID'")"
    out="$(probe "$SLUG" redteam/hog)"
    note "memory-hog: ${out:0:200}"
    if [ -z "$out" ]; then
        sleep 3
        state="$(docker inspect -f '{{.State.Running}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "pb-$SLUG" 2>/dev/null)"
        after_start="$(docker inspect -f '{{.State.StartedAt}}' "pb-$SLUG" 2>/dev/null)"
        after_rc="$(tsql "SELECT restart_count FROM instance WHERE tenant_id='$RT_ID'")"
        local why=""
        [[ "$state" != true* ]] && why="$why not running ($state);"
        [[ "$state" == *oom=true* ]] && why="$why OOMKilled;"
        [ "$after_start" != "$before_start" ] && why="$why restarted at $after_start;"
        [ "${after_rc:-0}" -gt "${before_rc:-0}" ] && why="$why restart_count ${before_rc:-0} -> $after_rc;"
        if [ -n "$why" ]; then
            ok "memory-hog: no answer, and the sandbox was killed inside its limit:${why%;}"
        else
            bad "memory-hog: no answer, and no sign the sandbox was killed; the probe proves nothing"
        fi
    elif ! report_from "$out" memory-hog; then
        bad "memory-hog: the route did not report: ${out:0:120}"
    elif ! json_top "$out" bounded; then
        esc "memory-hog: $(jget "$out" 'd["allocated_mib"]') MiB allocated and no limit held"
    elif [ "$(jget "$out" 'd["allocated_mib"]')" -lt 1 ]; then
        bad "memory-hog: the first allocation failed, so no limit was reached: $(jget "$out" 'd["stopped_by"]')"
    else
        ok "memory-hog: $(jget "$out" 'd["allocated_mib"]') MiB, then the limit held"
    fi
}
resource_logs() {
    local out flood=64 path max collected
    path="$(docker inspect -f '{{.LogPath}}' "pb-$SLUG" 2>/dev/null)"
    max="$(docker inspect -f '{{index .HostConfig.LogConfig.Config "max-size"}}' "pb-$SLUG" 2>/dev/null)"
    out="$(probe "$SLUG" "redteam/flood?mib=$flood")"
    note "log-flood: ${out:0:200}"
    if ! report_from "$out" log-flood || [ "$(jget "$out" 'd["written_mib"]')" -lt "$flood" ]; then
        bad "log-flood: the hook did not write its $flood MiB; nothing was tested"
        return
    fi
    sleep 5   # the collector drains the stream
    collected="$(cat "$PB_ROOT/logs/$RT_ID"/app.log* 2>/dev/null | wc -c)"
    check "log-flood control: the flood reached the host's collector ($((collected / 1048576)) MiB on disk)" \
        test "$collected" -ge $((LOG_MAX_BYTES / 2))
    if [ -z "$max" ] || [ "$max" = "<no value>" ]; then
        esc "log-flood: the runtime's own log has no max-size; $flood MiB of tenant stdout is $(( $(stat -c %s "$path" 2>/dev/null || echo 0) / 1048576 )) MiB on the host disk"
    else
        holds "log-flood: the runtime's own log stays under its max-size ($max)" \
            python3 -c '
import os, sys
units = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
m = sys.argv[2].lower()
cap = int(m[:-1]) * units[m[-1]] if m[-1] in units else int(m)
sys.exit(0 if os.path.getsize(sys.argv[1]) <= cap + (1 << 20) else 1)' "$path" "$max"
    fi
    holds "log-flood: the collected copy stays under log_max_bytes x (log_keep + 1)" \
        test "$collected" -le $((LOG_MAX_BYTES * (LOG_KEEP + 1) + 1048576))
}
resource_disk() {
    local out avail_before avail_after written stopped
    avail_before="$(df -B1 --output=avail "$PB_ROOT" | tail -1 | tr -d ' ')"
    out="$(probe "$SLUG" redteam/fill)"
    avail_after="$(df -B1 --output=avail "$PB_ROOT" | tail -1 | tr -d ' ')"
    note "disk-fill: ${out:0:200}"
    if ! report_from "$out" disk-fill; then
        bad "disk-fill: no report; the quota was not tested"
        return
    fi
    written="$(jget "$out" 'd["written_mib"]')"; stopped="$(jget "$out" 'd["stopped_by"]')"
    if ! json_top "$out" bounded; then
        esc "disk-fill: $written MiB written and the quota never stopped it"
        return
    fi
    if printf '%s' "$stopped" | grep -qi 'no space left'; then
        ok "disk-fill: stopped by ENOSPC after $written MiB"
    else
        bad "disk-fill: stopped by something other than the quota after $written MiB: $stopped"
    fi
    check "disk-fill: it filled the quota ($written MiB of a ${DISK_MIB} MiB quota, ${IMG_MIB} MiB image)" \
        test "$written" -ge $((DISK_MIB * 85 / 100)) -a "$written" -le "$IMG_MIB"
    holds "disk-fill: the host lost no more than the image's size" \
        test $((avail_before - avail_after)) -le $((IMG_BYTES + 67108864))
}

for probe_pkg in fork-bomb memory-hog log-flood disk-fill; do

    # Clear the previous probe's damage first. Each of these is designed to
    # break the instance it runs on — that is the point — and the reconciler
    # marks an instance `failed` once the restart ladder is exhausted (§8.3).
    # A deploy onto a failed instance cannot verify, so the NEXT probe would
    # report a boundary it never reached.
    citadel tenant restart "$SLUG" >/dev/null 2>&1
    wait_ping "$SLUG" 30

    if ! deploy "$SLUG" "$probe_pkg"; then
        bad "$probe_pkg did not deploy; the probe was not run"
        continue
    fi
    case "$probe_pkg" in
        fork-bomb)  resource_fork ;;
        memory-hog) resource_memory ;;
        log-flood)  resource_logs ;;
        disk-fill)  resource_disk ;;
    esac
    check "$probe_pkg: the host is unaffected — the control plane still answers" citadel tenant list
    check "$probe_pkg: the OTHER tenant is unaffected" \
        probe_has "$SLUG_EGRESS" "redteam/ping" '"ok":true'
done
# disk-fill ends with a full data volume, and the next deploy then cannot write
# its snapshot — which surfaces as "File not found" from a tenant still serving
# the previous release and looks nothing like a disk problem. Cleared from the
# host, so what follows tests what it claims to.
rm -f "$DATA_DIR"/redteam-fill-*

# ── 10. infinite-hook: a CPU cap, and backoff rather than a restart storm ───
log "10. infinite-hook — a CPU cap, and backoff rather than a restart storm"
citadel tenant restart "$SLUG" >/dev/null 2>&1
wait_ping "$SLUG" 30
if ! deploy "$SLUG" infinite-hook; then
    bad "the infinite-hook package did not deploy; neither the CPU cap nor the ladder was tested"
else
    # CPU: four spinning handlers ask for four CPUs. --cpus gives one.
    for _ in 1 2 3 4; do
        ( probe "$SLUG" "redteam/hang?s=30" 40 >/dev/null 2>&1 & )
    done
    sleep 8
    CPU="$(docker stats --no-stream --format '{{.CPUPerc}}' "pb-$SLUG" 2>/dev/null | tr -d '% ')"
    note "pb-$SLUG CPU while four handlers spin: ${CPU:-?}%"
    check "infinite-hook control: the spinning handlers really burn CPU (${CPU:-?}%)" \
        python3 -c "import sys; sys.exit(0 if float('${CPU:-0}') >= 50 else 1)"
    holds "infinite-hook: the sandbox is held to its one-CPU share (${CPU:-?}% <= 120%)" \
        python3 -c "import sys; sys.exit(0 if 0 < float('${CPU:-0}') <= 120 else 1)"
    SLOWEST="$(for _ in 1 2 3 4 5; do
        curl -s -o /dev/null -w '%{time_total}\n' --max-time 5 \
            -H "Host: $SLUG_EGRESS.$APPS_DOMAIN" "$EDGE/redteam/ping"; done | sort -n | tail -1)"
    holds "infinite-hook: the OTHER tenant still answers promptly (slowest ${SLOWEST}s < 2s)" \
        python3 -c "import sys; sys.exit(0 if float('${SLOWEST:-9}') < 2 else 1)"

    # The crash loop. Armed from inside, unarmable only from the host.
    STARTS_BEFORE="$(tsql "SELECT COUNT(*) FROM audit_event WHERE action='tenant.started' AND tenant_id='$RT_ID'")"
    T0="$(date +%s)"
    probe "$SLUG" redteam/arm 10 >/dev/null 2>&1
    STATE=""; MAXRC=0
    for _ in $(seq 1 60); do
        sleep 5
        STATE="$(tsql "SELECT observed_state FROM instance WHERE tenant_id='$RT_ID'")"
        RC="$(tsql "SELECT restart_count FROM instance WHERE tenant_id='$RT_ID'")"
        [ "${RC:-0}" -gt "$MAXRC" ] && MAXRC="$RC"
        [ "$STATE" = failed ] && break
    done
    ELAPSED=$(( $(date +%s) - T0 ))
    STARTS=$(( $(tsql "SELECT COUNT(*) FROM audit_event WHERE action='tenant.started' AND tenant_id='$RT_ID'") - STARTS_BEFORE ))
    note "crash-loop: state $STATE after ${ELAPSED}s, restart_count peaked at $MAXRC, $STARTS starts"
    check "crash-loop control: the ladder was exercised (restart_count rose to $MAXRC)" test "$MAXRC" -ge 1
    holds "crash-loop: the instance ends 'failed' instead of restarting forever" test "$STATE" = failed
    holds "crash-loop: restarts are bounded by the ladder ($MAXRC <= 5)" test "$MAXRC" -le 5
    holds "crash-loop: $STARTS container starts, not a storm (<= 6)" test "$STARTS" -le 6
    check "crash-loop: the backoff was honoured, not skipped (failed after ${ELAPSED}s >= 150s)" \
        test "$ELAPSED" -ge 150
    rm -f "$DATA_DIR/rt-crashloop"
    citadel tenant restart "$SLUG" >/dev/null 2>&1
    check "crash-loop: with the marker gone, a restart recovers the instance" wait_ping "$SLUG" 45
fi
check "the host is unaffected" citadel tenant list

# ── 11. the network probes ──────────────────────────────────────────────────
log "11. network probes (foreign addresses and host-side surfaces)"
for p in 07-controlplane 08-egress-acl 09-neighbour-scan 11-proxy-bypass 12-dns-exfil \
         13-squid-mgr 14-egress-bridge-input 15-edge-hairpin; do

    # Expanded BEFORE the prefix: bash performs assignments in a command
    # prefix left to right and later ones see the earlier ones, so
    # `SLUG="$SLUG_EGRESS" SLUG_B="$SLUG"` silently makes A and B the same
    # tenant — and a neighbour-scan against itself reports an escape.
    probe_b="$SLUG"
    out="$(SLUG="$SLUG_EGRESS" SLUG_A="$SLUG_EGRESS" SLUG_B="$probe_b" PIDS_LIMIT="$PIDS_LIMIT" \
             bash "test/netprobe/$p.sh" 2>&1)"
    rc=$?
    printf '%s\n' "$out" | sed 's/^/      /'
    if [ "$rc" -ne 0 ]; then
        esc "netprobe $p reported a hole"
    elif printf '%s' "$out" | grep -q 'SKIP'; then
        # A skipped probe has found no hole, which is not the same as having looked.
        bad "netprobe $p skipped; it tested nothing"
    else
        ok "netprobe $p"
    fi
done
if bash test/netprobe/10-sni-mismatch.sh; then
    ok "netprobe 10-sni-mismatch"
else
    bad "netprobe 10-sni-mismatch (SNI filtering unavailable or not enforced)"
fi

# ── 13. breakglass-silent ───────────────────────────────────────────
log "13. breakglass-silent — an operator cannot read a tenant's data quietly"
# The claim is not that root is prevented. A root operator can read the bind
# mount regardless (D15), so that path is detection. Break-glass is the door
# that needs no root: it opens the tenant in the portal for the named operator
# who opened it, the reason is mandatory, the box is hard, and the tenant is
# told at GRANT time rather than at review time.
contained "only a named operator opens break-glass: the tenant owner cannot" \
    bash -c "'$CITADEL' --socket '$SOCK' --as '$OWNER' breakglass open '$SLUG' --reason 'not an operator'"
contained "the shared platform principal cannot hold break-glass" \
    bash -c "'$CITADEL' --socket '$SOCK' --as platform breakglass open '$SLUG' --reason 'names nobody'"
BG_JSON="$($CITADEL --socket "$SOCK" --as person:oncall --json \
    breakglass open "$SLUG" --reason "redteam: probing the access path" 2>&1)"
BG_ID="$(printf '%s' "$BG_JSON" | sed -n 's/.*"id"[ :]*"\(g-[^"]*\)".*/\1/p' | head -1)"
if [ -z "$BG_ID" ]; then
    bad "breakglass-silent: could not open a break-glass session ($BG_JSON)"
else
    check "the read is attributed in the audit log" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT actor_id FROM audit_event WHERE action='grant.breakglass.opened'
             AND subject_ref='grant/$BG_ID'\" | grep -q 'person:oncall'"
    # This is the property that makes the path honest rather than merely logged.
    check "the TENANT was told, in the same transaction that opened it" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT body FROM notification WHERE audience='tenant'
             AND subject_ref='grant/$BG_ID'\" | grep -q 'person:oncall'"
    check "the reason reaches the tenant verbatim" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT body FROM notification WHERE audience='tenant'
             AND subject_ref='grant/$BG_ID'\" | grep -q 'probing the access path'"
    check "a second operator was told too, at grant time" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT COUNT(*) FROM notification WHERE audience='operator'
             AND subject_ref='grant/$BG_ID'\" | grep -qv '^0$'"
    check "it appears in the tenant's own access log" \
        bash -c "curl -sf --unix-socket '$SOCK' -H 'X-V2P-Principal: $OWNER' \
          'http://controlplane/api/v1/tenants/$SLUG/access-log' | grep -q '$BG_ID'"
    # Computed in python rather than with julianday(): the control plane writes
    # RFC3339 and the probe's own backdating writes SQLite's space-separated
    # form, so a single SQL expression would be comparing two formats and
    # rounding the difference. The claim is "one hour, hard" — assert that, with
    # a second of slack, not an exact float.
    check "the time box is hard: 60 minutes, not a policy default" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT requested_at || ' ' || expires_at FROM access_grant WHERE id='$BG_ID'\" |
          python3 -c \"
import sys, datetime
a, b = sys.stdin.read().split()
p = lambda v: datetime.datetime.fromisoformat(v.replace('Z', '+00:00').replace(' ', 'T'))
mins = (p(b) - p(a)).total_seconds() / 60
sys.exit(0 if 59 <= mins <= 61 else 1)\""
    contained "a reason is mandatory: an empty one is refused" \
        bash -c "'$CITADEL' --socket '$SOCK' --as person:oncall breakglass open '$SLUG' --reason ''"
    contained "the operator cannot review their own session" \
        bash -c "'$CITADEL' --socket '$SOCK' --as person:oncall breakglass review '$BG_ID' \
          --outcome justified --notes 'self-review'"
    contained "the tenant owner cannot review it: the verdict is a second operator's" \
        bash -c "'$CITADEL' --socket '$SOCK' --as '$OWNER' breakglass review '$BG_ID' \
          --outcome justified --notes 'owner review'"
    # Now that the session grants something, ending it is the operator's call.
    # The tenant's say is the notice at grant time and the verdict at review.
    contained "the tenant cannot revoke a break-glass session" \
        bash -c "curl -sf -X DELETE --unix-socket '$SOCK' -H 'X-V2P-Principal: $OWNER' \
          'http://controlplane/api/v1/tenants/$SLUG/grants/$BG_ID'"
    check "the opener can end it early" \
        bash -c "'$CITADEL' --socket '$SOCK' --as person:oncall breakglass close '$BG_ID' --reason 'done'"
    check "an early close is recorded, and the tenant is told" \
        bash -c "sqlite3 '$STATE_DB' \
          \"SELECT COUNT(*) FROM access_grant WHERE id='$BG_ID' AND revoked_at IS NOT NULL\" | grep -q '^1$' &&
          sqlite3 '$STATE_DB' \
          \"SELECT COUNT(*) FROM notification WHERE audience='tenant' AND kind='breakglass.closed'
             AND subject_ref='grant/$BG_ID'\" | grep -q '^1$'"
    # A session left unreviewed past its 24h window blocks the same principal
    # (a younger one does not, and the unit tests pin that), and only somebody else
    # can clear it. That is what stops break-glass becoming routine.
    tsql "UPDATE access_grant SET requested_at = datetime('now','-2 days') WHERE id='$BG_ID'"
    contained "an unreviewed session past 24h blocks that operator from opening another" \
        bash -c "'$CITADEL' --socket '$SOCK' --as person:oncall breakglass open '$SLUG' \
          --reason 'second attempt'"
    check "another operator can review it, and that clears the block" \
        bash -c "'$CITADEL' --socket '$SOCK' --as person:reviewer breakglass review '$BG_ID' \
          --outcome justified --notes 'redteam probe, expected'"
fi

# ── 14. audit anchors ───────────────────────────────────────────────
log "14. audit anchors — the chain head is signed and copied out (tampered in 16)"
check "the chain verifies" citadel audit verify
check "the chain head is anchored and signed" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT COUNT(*) FROM audit_anchor\" | grep -qv '^0$'"
check "a copy was written where it can be replicated off the host" \
    bash -c "ls '$PB_ROOT/audit/anchors'/*.json >/dev/null 2>&1"
check "verification checks the anchors, not only its own arithmetic" \
    bash -c "'$CITADEL' --socket '$SOCK' --as '$OWNER' audit verify 2>&1 | grep -q 'anchor'"

# ── 15. symlink-swap ────────────────────────────────────────────────────────
log "15. symlink-swap — tenant code re-points pb_data while a live backup reads it"
# Routine backups are the live copy, the path that reads pb_data while the
# tenant runs. They are daily by default, so the daemon is restarted with a
# fast schedule for this section and the next; nothing after them depends on
# the old one.
stop_daemon
write_conf '"routine_backup_interval": "5s",
  "routine_backup_window": ""'
start_daemon
# On the egress tenant, not $SLUG: the resource probes (section 9) leave $SLUG's
# instance in whatever state they broke it into.
SWAP_SLUG="$SLUG_EGRESS"
deploy "$SWAP_SLUG" symlink-swap || die "the symlink-swap package did not deploy"

PRIM="$(probe "$SWAP_SLUG" redteam/symlink-primitive)"
if json_top "$PRIM" created; then

    note "tenant code CAN plant a symlink to any host path (\$os.openRoot(...).symlink);"
    note "the host must never follow one"

else

    note "this PocketBase gives hooks no symlink primitive ($PRIM); the race is not reachable from a hook"
fi

TENANT_ID="$EG_ID"
routine_count() {
    tsql "SELECT COUNT(*) FROM backup WHERE tenant_id='$TENANT_ID' AND kind='routine'"
}
routine_failed() {
    grep -c "routine backup failed.*$TENANT_ID" "$LOG" 2>/dev/null
}
BEFORE="$(routine_count)"
FAILED_BEFORE="$(routine_failed)"
# The control plane's key directory under the documented default root: small,
# so a walk that follows the link finishes inside one hold, and it holds every
# tenant's PocketBase encryption key. Against the pre-fix copy this leaked a key
# into the tenant's own backup within a handful of routine backups.
probe "$SWAP_SLUG" "redteam/swap?ms=40000&target=$PB_ROOT/control/keys" >"$WORK/swap.json"
note "swap: $(cat "$WORK/swap.json")"
TAKEN=$(( $(routine_count) - BEFORE ))
REFUSED=$(( $(routine_failed) - FAILED_BEFORE ))
note "live backups during the swap: $TAKEN taken, $REFUSED refused (a refusal is a pass)"
check "live backups actually ran against the swap" test $((TAKEN + REFUSED)) -gt 0

# list_archive <path> — the entries of a `files` snapshot.
list_archive() {
    case "$1" in
        *.zst) zstd -dc "$1" | tar -tf - ;;
        *)     tar -tzf "$1" ;;
    esac
}
LEAKED=""
while read -r path; do

    [ -n "$path" ] || continue
    # Anything under rtswap/ other than the tenant's own file came through the
    # symlink: the host walked out of pb_data and archived what it found there.
    extra="$(list_archive "$path" 2>/dev/null | sed 's|^\./||' |
             grep -E '^rtswap/(dir|real)/.' | grep -vE '/own\.txt$' | head -3 | tr '\n' ' ')"
    [ -n "$extra" ] && LEAKED="$LEAKED $path: $extra"
done < <(tsql "SELECT path FROM backup WHERE tenant_id='$TENANT_ID' AND format='files'")
[ -n "$LEAKED" ] && note "host files found in a backup:$LEAKED"
contained "no backup holds a host file reached through a swapped directory" test -n "$LEAKED"
check "the swap ran, so the race was actually exercised" \
    grep -qE '"flips":[1-9]' "$WORK/swap.json"
check "the instance is still healthy after the swap" \
    probe_has "$SWAP_SLUG" "redteam/ping" '"ok":true'

# ── 15b. backup-bomb: a sparse file the quota cannot see ────────────────────
log "15b. backup-bomb — a file's claimed size must not become the host's problem"
EG_IMG="$(stat -c %s "$PB_ROOT/tenants/$EG_ID/data.img" 2>/dev/null || echo 0)"
AVAIL="$(df -B1 --output=avail "$PB_ROOT" | tail -1 | tr -d ' ')"
# Above the image, so a copy that honoured the quota could never hold it; at
# most a quarter of the free space, so a platform without the bound survives
# the probe that proves it.
BOMB=$((EG_IMG * 2)); [ "$BOMB" -gt $((AVAIL / 4)) ] && BOMB=$((AVAIL / 4))
if [ "$BOMB" -le "$EG_IMG" ]; then
    bad "backup-bomb: the host has too little free space to run this safely (${AVAIL} bytes free)"
elif ! deploy "$SWAP_SLUG" backup-bomb; then
    bad "the backup-bomb package did not deploy; the probe was not run"
else
    OUT="$(probe "$SWAP_SLUG" "redteam/sparse?bytes=$BOMB")"
    note "sparse: $OUT"
    if ! report_from "$OUT" backup-bomb || [ "$(jget "$OUT" 'd["size"]')" != "$BOMB" ]; then
        bad "backup-bomb: the hook could not create its sparse file; nothing was tested"
    else
        # Wait for an outcome, not a fixed time: a backup already in flight when
        # the file appeared finishes without it and proves nothing, and the one
        # that reads it may take a while to densify and compress 2x the image.
        # Only a refusal that names the budget, or an archive that holds the
        # file, decides it. Free space is sampled throughout.
        LOG_T0="$(wc -l <"$LOG")"
        tsql "SELECT id FROM backup WHERE tenant_id='$TENANT_ID'" >"$WORK/bomb-seen"
        MIN="$AVAIL"; NEW=0; DENSE=""; BUDGET=""
        for _ in $(seq 1 180); do
            a="$(df -B1 --output=avail "$PB_ROOT" | tail -1 | tr -d ' ')"
            [ "$a" -lt "$MIN" ] && MIN="$a"
            BUDGET="$(tail -n +"$((LOG_T0 + 1))" "$LOG" | grep 'routine backup failed' |
                      grep -F "$TENANT_ID" | grep -m1 'claims more bytes than its image')"
            [ -n "$BUDGET" ] && break
            while read -r id path; do
                [ -n "$id" ] || continue
                echo "$id" >>"$WORK/bomb-seen"
                NEW=$((NEW + 1))
                list_archive "$path" 2>/dev/null | grep -q 'rt-sparse\.bin' && DENSE="$DENSE $path"
            done < <(tsql "SELECT id, path FROM backup WHERE tenant_id='$TENANT_ID' AND kind='routine'" |
                     tr '|' ' ' | grep -vwFf "$WORK/bomb-seen")
            [ -n "$DENSE" ] && break
            sleep 1
        done
        DROP=$((AVAIL - MIN))
        note "with the sparse file present: $NEW routine backups finished, refusal: $([ -n "$BUDGET" ] && echo yes || echo none);" \
             "host free space dipped by $((DROP / 1048576)) MiB (image is $((EG_IMG / 1048576)) MiB)"
        if [ -n "$DENSE" ]; then
            esc "backup-bomb: a routine backup archived the sparse file at its claimed size (in$DENSE)"
        elif [ -n "$BUDGET" ]; then
            ok "backup-bomb: the routine backup was refused, naming the budget"
        else
            bad "backup-bomb: in 180s no routine backup either archived the file or was refused for it; nothing was decided"
        fi
        holds "backup-bomb: host free space never dipped by more than the tenant's image" \
            test "$DROP" -le "$EG_IMG"
    fi
    probe "$SWAP_SLUG" redteam/unsparse >/dev/null 2>&1
fi

# ── 16. audit-tamper ────────────────────────────────────────────────
log "16. audit-tamper — an edit, a wholesale rewrite and a truncation all fail verification"
# LAST, deliberately, and against a snapshot that is restored afterwards. The
# append-only triggers are dropped — root can always do that, so a trigger
# refusing the edit proves nothing about verification — and the audit table on
# this host is shared by every suite: a tamper that outlived the run would fail
# every later `audit verify` here, permanently.
#
# The daemon is stopped for each tamper and restarted with a long anchor
# interval, so no anchor is signed over the tampered chain mid-test.
SNAP="$WORK/audit-snap"
mkdir -p "$SNAP"
stop_daemon
sqlite3 "$STATE_DB" ".backup '$SNAP/state.db'"
ls "$PB_ROOT/audit/anchors" >"$SNAP/anchors.list" 2>/dev/null
SAVED_CONF="$(cat "$CONF")"

audit_restore() {
    stop_daemon
    cp "$SNAP/state.db" "$STATE_DB"
    rm -f "$STATE_DB-wal" "$STATE_DB-shm"
    # An anchor written since the snapshot signs a head that no longer exists.
    for f in "$PB_ROOT/audit/anchors"/*; do
        [ -e "$f" ] || continue
        grep -qxF "$(basename "$f")" "$SNAP/anchors.list" || rm -f "$f"
    done
}
# audit_case <name> <expect-regex> — the tamper has been applied; verify must
# fail and say why in the expected terms.
audit_case() {
    local name="$1" want="$2" out
    ANCHOR_INTERVAL=24h write_conf
    start_daemon
    out="$("$CITADEL" --socket "$SOCK" --as "$OWNER" audit verify 2>&1)"
    local rc=$?
    note "$name: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
    if [ "$rc" -eq 0 ]; then
        esc "audit-tamper ($name): verification PASSED a tampered chain"
    elif printf '%s' "$out" | grep -qE "$want"; then
        ok "audit-tamper ($name): verification fails, naming it ($want)"
    else
        bad "audit-tamper ($name): verification failed, but not for the tampered reason"
    fi
    audit_restore
}

ANCHOR_SEQ="$(sqlite3 "$STATE_DB" "SELECT MAX(seq) FROM audit_anchor")"
if [ -z "$ANCHOR_SEQ" ] || [ "$ANCHOR_SEQ" -lt 4 ]; then
    bad "audit-tamper: no anchor past seq 3 to contradict; the rewrite and truncation cases cannot run"
fi

# (a) edit in place: one row changed, its hash left alone.
SEQ="$(sqlite3 "$STATE_DB" "SELECT seq FROM audit_event ORDER BY seq LIMIT 1 OFFSET 2")"
sqlite3 "$STATE_DB" "DROP TRIGGER IF EXISTS audit_event_no_update;
                     UPDATE audit_event SET action='tampered' WHERE seq=$SEQ;" >/dev/null 2>&1
if [ "$(sqlite3 "$STATE_DB" "SELECT action FROM audit_event WHERE seq=$SEQ")" = tampered ]; then
    audit_case "edit in place at seq $SEQ" "FAILED at seq $SEQ"
else
    bad "audit-tamper (edit in place): the edit did not land; verification was not tested"
    audit_restore
fi

if [ -n "$ANCHOR_SEQ" ] && [ "$ANCHOR_SEQ" -ge 4 ]; then
    # (b) the wholesale rewrite §14.4 is about: the table re-chained so it
    # agrees with itself, and only an anchor signed before it can disagree.
    RSEQ=$((ANCHOR_SEQ - 1))
    if ! python3 -I test/redteam/lib/rechain.py selfcheck "$STATE_DB" >"$WORK/rechain.out" 2>&1; then
        bad "audit-tamper (rewrite): the rechain mirror cannot reproduce the chain: $(cat "$WORK/rechain.out")"
    elif python3 -I test/redteam/lib/rechain.py rewrite "$STATE_DB" "$RSEQ" >"$WORK/rechain.out" 2>&1; then
        note "$(cat "$WORK/rechain.out")"
        audit_case "wholesale rewrite from seq $RSEQ" "CONTRADICTS the anchor at seq|now hashes to"
    else
        bad "audit-tamper (rewrite): the rewrite failed: $(cat "$WORK/rechain.out")"
        audit_restore
    fi

    # (c) truncation: the rows from the newest anchored head onwards deleted.
    sqlite3 "$STATE_DB" "DROP TRIGGER IF EXISTS audit_event_no_delete;
                         DELETE FROM audit_event WHERE seq >= $ANCHOR_SEQ;" >/dev/null 2>&1
    if [ "$(sqlite3 "$STATE_DB" "SELECT MAX(seq) FROM audit_event")" -lt "$ANCHOR_SEQ" ]; then
        audit_case "truncation at seq $ANCHOR_SEQ" "seq $ANCHOR_SEQ"
    else
        bad "audit-tamper (truncation): the delete did not land; verification was not tested"
        audit_restore
    fi
fi

printf '%s\n' "$SAVED_CONF" >"$CONF"
start_daemon
check "the snapshot was restored: this host's chain verifies again" citadel audit verify
check "and the append-only triggers are back" \
    bash -c "sqlite3 '$STATE_DB' \"SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'audit_event_no_%'\" | grep -qx 2"

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n'
if [ "$ESCAPES" -gt 0 ]; then
    printf '\033[41;97m RED TEAM: %d probe(s) ACHIEVED THEIR GOAL \033[0m\n' "$ESCAPES"
    printf 'This is a hole in the platform, not a flaky test. Fix the platform, never the test.\n'
    printf 'control-plane log: %s\n' "$LOG"
    [ "$FAILS" -gt 0 ] && printf '\033[31m%d other check(s) FAILED\033[0m\n' "$FAILS"
    exit 1
fi
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32mRed team: every probe failed to achieve its goal\033[0m\n'
    exit 0
fi
printf '\033[31mRed team: %d check(s) FAILED (no escapes)\033[0m\n' "$FAILS"
printf 'control-plane log: %s\n' "$LOG"
exit 1
