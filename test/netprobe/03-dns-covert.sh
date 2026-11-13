#!/usr/bin/env bash
# Task 4 (§9.4): what does Docker's embedded resolver (127.0.0.11) do on an
# internal network? If external names resolve, DNS is a covert exfiltration
# channel regardless of any TCP blocking.
. "$(dirname "$0")/lib.sh"
require_root; require_docker
trap np_cleanup EXIT
np_cleanup

np_net_create
np_run a
np_run b

log "resolv.conf inside the container:"
run_in "${NP_PREFIX}-a" cat /etc/resolv.conf | sed 's/^/    /'

# Container-name resolution should work (service discovery on the network).
expect_ok  "embedded resolver answers for container names on the same network" \
    run_in "${NP_PREFIX}-a" nslookup -timeout=3 "${NP_PREFIX}-b" 127.0.0.11

# External names must NOT resolve — this is the covert-channel probe. A unique
# label makes accidental cache hits impossible.
RAND="np-$(date +%s)-$RANDOM"
expect_err "external name does not resolve via 127.0.0.11" \
    run_in "${NP_PREFIX}-a" nslookup -timeout=5 "${RAND}.example.com" 127.0.0.11
expect_err "well-known external name does not resolve either" \
    run_in "${NP_PREFIX}-a" nslookup -timeout=5 google.com 127.0.0.11

# Direct queries to an external resolver must be blocked by the network posture.
expect_err "direct query to 8.8.8.8 fails (no route off the internal network)" \
    run_in "${NP_PREFIX}-a" nslookup -timeout=3 example.com 8.8.8.8

np_summary
