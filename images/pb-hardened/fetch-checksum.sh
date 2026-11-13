#!/usr/bin/env bash
# Pin a PocketBase release: fetch upstream checksums.txt ONCE and commit the
# linux_<arch> lines under checksums/. The image build verifies the downloaded
# zip against these committed values only — never against the network (§5).
# Usage: fetch-checksum.sh <version> [arch ...]     (default: amd64 arm64)
set -eu

VER="${1:?usage: fetch-checksum.sh <version> [arch ...]}"
shift
if [ $# -gt 0 ]; then ARCHES=("$@"); else ARCHES=(amd64 arm64); fi

DIR="$(cd "$(dirname "$0")" && pwd)/checksums"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Upstream moved off GitHub: releases >= 0.41 are on the new host only, older
# ones on GitHub only. Try the new host first, then fall back to GitHub.
curl -fsSL -o "$TMP" \
  "https://ganigeorgiev.com/meta/pocketbase/pocketbase/download/v${VER}/checksums.txt" \
  || curl -fsSL -o "$TMP" \
  "https://github.com/pocketbase/pocketbase/releases/download/v${VER}/checksums.txt"

# Refuse anything that isn't a sha256sum listing (e.g. an HTML/JSON error page).
if ! grep -qE '^[0-9a-f]{64}  pocketbase_' "$TMP"; then
  echo "error: checksums.txt for v${VER} is not a sha256sum listing" >&2
  exit 1
fi

for ARCH in "${ARCHES[@]}"; do
  ZIP="pocketbase_${VER}_linux_${ARCH}.zip"
  OUT="$DIR/pocketbase_${VER}_linux_${ARCH}.sha256"
  grep " ${ZIP}\$" "$TMP" > "$OUT"
  echo "pinned: $OUT"
  cat "$OUT"
done
