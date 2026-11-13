#!/bin/sh
# Entrypoint of the egress proxy image: generate the ssl-bump startup
# certificate, then become squid.
#
# The certificate only satisfies Squid's precondition for an `ssl-bump` port
# (see the Containerfile). It is never presented to anyone, so a new one per
# start costs nothing. Generated here, not at build time, so the image stays
# reproducible and no private key ships inside it.
#
# /run is a tmpfs in production (internal/egressctl). Group-readable rather
# than 0400-owned-by-squid: with capabilities dropped, the pre-drop root
# process must still be able to read it.
set -eu

d=/run/squid-bump
mkdir -p "$d"
openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -subj "/CN=v2p-egress-never-presented" \
    -keyout "$d/bump.key" -out "$d/bump.crt" 2>/dev/null
cat "$d/bump.key" "$d/bump.crt" > "$d/bump.pem"
rm -f "$d/bump.key" "$d/bump.crt"
chown root:squid "$d/bump.pem"
chmod 0440 "$d/bump.pem"

exec squid -N -d 1 "$@"
