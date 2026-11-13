#!/usr/bin/env bash
# Hardened-image verification (design §5), run BY DIGEST against the local
# registry. Asserts, under runc (seccomp + AppArmor where the kernel has it)
# and again under runsc (the D2 tenant runtime):
#
#   1. /api/health responds
#   2. real data-plane persistence across stop/start AND container recreate —
#      superuser auth, not just health (design.md INV-4: health lies)
#   3. the fixture hook executes from a read-only /pb/app mount
#   4. the hook's attempt to write into /pb/app fails (host-side marker check)
#   5. pb_public static assets served
#
# No published ports: probes hit the container IP on the docker bridge from
# the host. Runs as root on the Docker host (use hack/in-vm.sh on macOS).
# Usage: smoke.sh <image-ref-by-digest> <pb-version>
set -eu

IMG="${1:?usage: smoke.sh <image@sha256:...> <pb-version>}"
VER="${2:?usage: smoke.sh <image@sha256:...> <pb-version>}"

case "$IMG" in *@sha256:*) ;; *) echo "FATAL: run by digest, never by tag: $IMG"; exit 1;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SECCOMP="$HERE/seccomp.json"
APPARMOR_PROFILE="$HERE/apparmor/pb-hardened"

# Pre-0.23 = legacy JSVM + admin API surface
MINOR="$(echo "$VER" | cut -d. -f2)"
if [ "$(echo "$VER" | cut -d. -f1)" = "0" ] && [ "$MINOR" -lt 23 ]; then
  FIXTURE="$REPO_ROOT/test/fixtures/basic-hook-legacy"
  AUTH_PATH="/api/admins/auth-with-password"
  SU_CMD=(admin create)
  NEEDS_MIGRATE=1   # 0.22: `admin create` on empty pb_data requires `migrate up`
                    # first, and exits 0 on that failure — run it explicitly.
else
  FIXTURE="$REPO_ROOT/test/fixtures/basic-hook"
  AUTH_PATH="/api/collections/_superusers/auth-with-password"
  SU_CMD=(superuser upsert)
  NEEDS_MIGRATE=0
fi

SU_EMAIL="smoke@example.invalid"
SU_PASS="smoke-$(openssl rand -hex 8)"
ENC_KEY="$(openssl rand -hex 16)"
CNAME="pb-smoke-$$"

WORK="$(mktemp -d /var/tmp/pb-smoke.XXXXXX)"   # VM-local disk: pb_data must not
DATA="$WORK/data"                              # live on the shared Mac FS
APP="$WORK/app"
mkdir -p "$DATA"
cp -R "$FIXTURE" "$APP"

# userns-remap shifts the container's 10001 to base+10001 on the host (D3).
BASE_UID=0
if docker info --format '{{json .SecurityOptions}}' | grep -q userns; then
  BASE_UID="$(awk -F: '/^dockremap:/{print $2}' /etc/subuid)"
  [ -n "$BASE_UID" ] || { echo "FATAL: userns active but no dockremap in /etc/subuid"; exit 1; }
fi
chown -R "$((BASE_UID + 10001)):$((BASE_UID + 10001))" "$DATA"

cleanup() {
  docker rm -f "$CNAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; docker logs "$CNAME" 2>&1 | tail -20 || true; exit 1; }

run_pb() { # run_pb <runtime> [extra docker-run args...]
  local runtime="$1"; shift
  docker run -d --name "$CNAME" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 128 \
    --memory 256m --memory-swap 256m \
    --cpus 1.0 \
    --restart no \
    --runtime "$runtime" \
    -v "$DATA:/pb/pb_data:rw" \
    -v "$APP:/pb/app:ro" \
    -e PB_ENCRYPTION_KEY="$ENC_KEY" \
    "$@" \
    "$IMG" >/dev/null
}

container_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CNAME"
}

wait_health() {
  local ip; ip="$(container_ip)"
  for _ in $(seq 1 60); do
    curl -fsS "http://$ip:8090/api/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

check_auth() { # data-plane check: superuser password auth must yield a token
  local ip; ip="$(container_ip)"
  curl -fsS -X POST "http://$ip:8090$AUTH_PATH" \
    -H 'Content-Type: application/json' \
    -d "{\"identity\":\"$SU_EMAIL\",\"password\":\"$SU_PASS\"}" | grep -q '"token"'
}

check_fixture() {
  local ip; ip="$(container_ip)"
  curl -fsS "http://$ip:8090/fixture/ping" | grep -q '"ok":true' || return 1
  curl -fsS "http://$ip:8090/" | grep -q 'basic-hook fixture' || return 1
}

run_suite() { # run_suite <runtime> [extra docker-run args...]
  local runtime="$1"; shift
  echo "--- suite: runtime=$runtime $* ---"

  # Superuser via one-shot CLI container BEFORE the server runs — never two
  # processes on one pb_data, and never exec into a live container.
  if [ "$NEEDS_MIGRATE" = 1 ]; then
    docker run --rm --runtime "$runtime" \
      -v "$DATA:/pb/pb_data:rw" -e PB_ENCRYPTION_KEY="$ENC_KEY" \
      --entrypoint /pb/pocketbase "$IMG" migrate up \
      --dir /pb/pb_data --encryptionEnv PB_ENCRYPTION_KEY >/dev/null \
      || { echo "FAIL: migrate up"; exit 1; }
  fi
  docker run --rm \
    --runtime "$runtime" \
    -v "$DATA:/pb/pb_data:rw" \
    -e PB_ENCRYPTION_KEY="$ENC_KEY" \
    --entrypoint /pb/pocketbase \
    "$IMG" "${SU_CMD[@]}" "$SU_EMAIL" "$SU_PASS" \
    --dir /pb/pb_data --encryptionEnv PB_ENCRYPTION_KEY >/dev/null \
    || { echo "FAIL: superuser create"; exit 1; }

  run_pb "$runtime" "$@"
  wait_health                          || fail "health never came up"
  check_auth                           || fail "superuser auth (fresh boot)"
  check_fixture                        || fail "fixture hook route / static asset"
  [ ! -e "$APP/pb_hooks/ESCAPE_MARKER" ] || fail "hook WROTE into read-only /pb/app"

  docker stop "$CNAME" >/dev/null
  docker start "$CNAME" >/dev/null
  wait_health                          || fail "health after stop/start"
  check_auth                           || fail "auth after stop/start (persistence)"

  docker rm -f "$CNAME" >/dev/null     # recreate: same data, brand-new container
  run_pb "$runtime" "$@"
  wait_health                          || fail "health after recreate"
  check_auth                           || fail "auth after recreate (persistence)"
  check_fixture                        || fail "fixture after recreate"

  docker rm -f "$CNAME" >/dev/null
  echo "--- suite OK: runtime=$runtime ---"
}

echo "=== smoke: $IMG (PocketBase $VER) ==="
docker pull "$IMG" >/dev/null

# --- runc: the seccomp (and AppArmor, if available) enforcement run ---------
RUNC_OPTS=(--security-opt "seccomp=$SECCOMP")
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] \
   && command -v apparmor_parser >/dev/null; then
  apparmor_parser -Kr "$APPARMOR_PROFILE"
  RUNC_OPTS+=(--security-opt apparmor=pb-hardened)
  echo "apparmor: profile pb-hardened loaded and applied"
else
  echo "WARNING: AppArmor unavailable on this kernel — profile NOT verified here." >&2
  echo "WARNING: re-run this on a host with AppArmor before treating the profile as verified." >&2
fi
run_suite runc "${RUNC_OPTS[@]}"

# --- runsc: the D2 tenant runtime (own syscall filter; seccomp profile inert) --
if docker info --format '{{json .Runtimes}}' | grep -q runsc; then
  rm -rf "$DATA"; mkdir -p "$DATA"    # fresh pb_data for the second suite
  chown -R "$((BASE_UID + 10001)):$((BASE_UID + 10001))" "$DATA"
  run_suite runsc
else
  echo "WARNING: runsc runtime not registered on this daemon — D2 runtime NOT verified." >&2
  exit 1
fi

echo "=== smoke OK: $IMG ==="
