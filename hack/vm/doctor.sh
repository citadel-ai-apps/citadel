#!/usr/bin/env bash
# Find (and with --fix, clear) the UTM states that produce duplicate VMs.
#
#   hack/vm/doctor.sh [--fix]
#
# Reports, for the VM named $PB_VM (default citadel):
#
#   ghost    a registry entry for NAME.utm that is not the VM the bundle claims
#            to be. It shares the real VM's bundle, so deleting it from UTM
#            deletes the real VM's disk; --fix edits it out of the registry.
#   orphan   a QEMU process running off NAME.utm under another UUID — a VM
#            whose bundle was deleted while it ran. Its disk is already
#            unlinked; --fix kills it.
#   bundle   NAME.utm on disk with no registry entry. Reported only: it may
#            hold the only copy of a disk. `make vm-create ARGS=--recreate`
#            replaces it.
#
# Exit status: 0 when clean (or everything was fixed), 1 otherwise.
set -euo pipefail

VM_NAME="${PB_VM:-citadel}"
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/resolve.sh"

log() { printf '%s\n' "$*"; }

BUNDLE="$(utm_bundle_path "$VM_NAME")"
REAL="$(utm_bundle_uuid "$VM_NAME")"

ghosts=()
for u in $(utm_registry_for_bundle "$VM_NAME"); do
    [ "$u" = "$REAL" ] || ghosts+=("$u")
done

orphans=()
while read -r pid uuid; do
    [ -n "${pid:-}" ] || continue
    [ "$uuid" = "$REAL" ] || orphans+=("$pid:$uuid")
done < <(utm_qemu_for_bundle "$VM_NAME")

leftover=0
if [ -n "$REAL" ] && ! utm_registry_for_bundle "$VM_NAME" | grep -qx "$REAL"; then
    leftover=1
fi

for g in ${ghosts[@]+"${ghosts[@]}"}; do log "ghost:   registry entry $g points at $BUNDLE"; done
for o in ${orphans[@]+"${orphans[@]}"}; do log "orphan:  QEMU pid ${o%%:*} runs $VM_NAME as ${o#*:}, whose bundle is gone"; done
[ "$leftover" = 0 ] || log "bundle:  $BUNDLE ($REAL) is on disk but not registered in UTM"

if [ ${#ghosts[@]} -eq 0 ] && [ ${#orphans[@]} -eq 0 ] && [ "$leftover" = 0 ]; then
    log "doctor:  no ghosts, orphans or stray bundles"
    exit 0
fi
[ "$FIX" = 1 ] || { log "run 'make vm-doctor ARGS=--fix' to clear ghosts and orphans"; exit 1; }

for o in ${orphans[@]+"${orphans[@]}"}; do
    pid="${o%%:*}"
    log "killing orphan QEMU $pid"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -9 "$pid" 2>/dev/null || true
done

if [ ${#ghosts[@]} -gt 0 ]; then
    restart=0
    if [ -n "$REAL" ] && [ "$(utmctl status "$REAL" 2>/dev/null)" = started ]; then
        log "stopping $VM_NAME ($REAL): UTM has to quit to edit its registry"
        utmctl stop "$REAL"
        for _ in $(seq 1 60); do
            [ "$(utmctl status "$REAL" 2>/dev/null)" = stopped ] && break
            sleep 1
        done
        restart=1
    fi
    log "purging ${ghosts[*]} from UTM's registry"
    utm_registry_purge "${ghosts[@]}"
    open -ga UTM
    for _ in $(seq 1 30); do utmctl list >/dev/null 2>&1 && break; sleep 1; done
    if [ "$restart" = 1 ]; then
        log "starting $VM_NAME again"
        utmctl start "$REAL"
    fi
fi

[ "$leftover" = 0 ] || { log "the stray bundle is left alone; see above"; exit 1; }
log "fixed"
