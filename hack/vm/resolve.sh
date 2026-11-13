#!/usr/bin/env bash
# Resolve a UTM VM name to exactly one UUID.
#
# `utmctl` accepts a name wherever it takes a UUID, but when two VMs share the
# name it silently picks one — and UTM can be left with a stale registry entry
# of the same name (and the same bundle path) after a VM is deleted and
# recreated. Then `utmctl status citadel` reports the ghost as stopped while the
# real VM runs. So everything here talks to UTM by UUID, and an ambiguous name
# is an error, never a guess.
#
# Sourced:   . hack/vm/resolve.sh; uuid="$(utm_vm_uuid citadel)"
# Executed:  bash hack/vm/resolve.sh citadel     # prints the UUID
#
# Exit status: 0 with the UUID on stdout; 1 if no VM has the name; 2 if more
# than one does (the matching rows go to stderr).

# All VMs whose name is exactly $1, as "UUID STATUS" lines.
utm_vm_matches() {
    utmctl list 2>/dev/null | awk -v want="$1" 'NR > 1 {
        uuid = $1; status = $2
        name = $0
        sub(/^[^ ]+ +[^ ]+ +/, "", name)
        if (name == want) print uuid, status
    }'
}

utm_vm_uuid() {
    local matches n
    matches="$(utm_vm_matches "$1")"
    n="$(printf '%s' "$matches" | grep -c . || true)"
    case "$n" in
        0) echo "no UTM VM named '$1'" >&2; return 1 ;;
        1) printf '%s\n' "${matches%% *}" ;;
        *)
            {
                echo "$n UTM VMs are named '$1' — refusing to guess which one is meant:"
                printf '%s\n' "$matches" | sed 's/^/    /'
                echo "One is usually a stale registry entry; see 'Duplicate VM entries' in hack/vm/README.md."
            } >&2
            return 2 ;;
    esac
}

# ── What utmctl cannot see ───────────────────────────────────────────────────
# Two states produce duplicate VMs and neither shows up in `utmctl list`:
#
#   * A stale registry entry whose bundle path is NAME.utm. UTM hides an entry
#     whose bundle is missing, so while no NAME.utm exists the entry is
#     invisible — and the moment a new VM is created at that path, the entry's
#     bookmark resolves to the new bundle and a second NAME appears.
#   * An orphan QEMU process: a VM whose bundle was deleted while it ran. QEMU
#     keeps the unlinked disk open and stays on the network; UTM, unable to load
#     the entry, stops listing it.
#
# So these helpers read UTM's registry and the process table directly.

UTM_DOCS="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents"
UTM_PREFS="$HOME/Library/Containers/com.utmapp.UTM/Data/Library/Preferences/com.utmapp.UTM.plist"

utm_bundle_path() { printf '%s/%s.utm\n' "$UTM_DOCS" "$1"; }

# The UUID the bundle itself claims, or nothing when there is no bundle.
utm_bundle_uuid() {
    local plist
    plist="$(utm_bundle_path "$1")/config.plist"
    [ -f "$plist" ] || return 0
    plutil -extract Information.UUID raw -o - "$plist" 2>/dev/null || true
}

# UUIDs of every registry entry for bundle NAME.utm or named NAME, whether or
# not utmctl shows it. Read through `defaults` so it is cfprefsd's live view,
# not a file UTM may not have flushed yet.
utm_registry_for_bundle() {
    [ -f "$UTM_PREFS" ] || return 0
    defaults export "$UTM_PREFS" - 2>/dev/null |
        python3 -c '
import plistlib, sys
raw = sys.stdin.buffer.read()
d = plistlib.loads(raw) if raw else {}
path, name = sys.argv[1], sys.argv[2]
for uuid, e in (d.get("Registry") or {}).items():
    p = ((e.get("Package") or {}).get("Path") or "").rstrip("/")
    if p == path or e.get("Name") == name:
        print(uuid)
' "$(utm_bundle_path "$1")" "$1"
}

# "PID UUID" for every QEMU process running off bundle NAME.utm.
utm_qemu_for_bundle() {
    local pid uuid
    for pid in $(pgrep -f "QEMULauncher.*/Documents/$1\\.utm/" 2>/dev/null); do
        uuid="$(ps -o args= -p "$pid" 2>/dev/null | sed -n 's/.* -uuid \([0-9A-Fa-f-]*\).*/\1/p')"
        [ -n "$uuid" ] && printf '%s %s\n' "$pid" "$uuid"
    done
}

# Remove registry entries by UUID. UTM keeps the registry in memory and writes
# it back, so it has to be quit first — which would kill any running VM, hence
# the refusal. A timestamped backup is left beside the plist.
utm_registry_purge() {
    [ $# -gt 0 ] || return 0
    if utmctl list 2>/dev/null | awk 'NR > 1 && $2 != "stopped" { found = 1 } END { exit !found }'; then
        echo "a UTM VM is running; stop it before purging stale registry entries ($*)" >&2
        return 1
    fi
    if pgrep -xq UTM; then
        osascript -e 'quit app "UTM"' >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do pgrep -xq UTM || break; sleep 1; done
        pgrep -xq UTM && { echo "UTM did not quit within 30s" >&2; return 1; }
    fi
    cp "$UTM_PREFS" "$UTM_PREFS.bak-$(date +%Y%m%d%H%M%S)"
    defaults export "$UTM_PREFS" - | python3 -c '
import plistlib, sys
d = plistlib.loads(sys.stdin.buffer.read())
for u in sys.argv[1:]:
    (d.get("Registry") or {}).pop(u, None)
    if u in (d.get("VMEntryList") or []):
        d["VMEntryList"].remove(u)
sys.stdout.buffer.write(plistlib.dumps(d))
' "$@" | defaults import "$UTM_PREFS" -
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -eu
    [ $# -eq 1 ] || { echo "usage: $0 VM_NAME" >&2; exit 64; }
    utm_vm_uuid "$1"
fi
