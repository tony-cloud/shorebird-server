#!/usr/bin/env bash
# End-to-end self-update run on this host (Linux or macOS), with the public
# DEVELOPMENT-ONLY signing key. It builds four signed versions, runs v1 under
# the supervisor and drives the administrator API:
#
#   v1 -> upload v2 (stable ZIP) -> trial -> healthy
#   manual rollback (password re-authentication) -> v1, v2 quarantined
#   upload v3 (dev ZIP whose /health fails) -> watchdog rollback -> v1, v3 quarantined
#   upload v4 -> trial -> healthy
#
# Usage: scripts/e2e_self_update.sh WORK_DIR
# WORK_DIR must be outside the source tree; it is removed and recreated.
set -euo pipefail

work=${1:?usage: e2e_self_update.sh WORK_DIR}
source_dir=$(cd "$(dirname "$0")/.." && pwd)
port=${E2E_PORT:-18089}
base=http://127.0.0.1:$port
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=darwin-arm64 ;;
  Darwin-x86_64) target=darwin-amd64 ;;
  Linux-x86_64) target=linux-amd64 ;;
  Linux-aarch64 | Linux-arm64) target=linux-arm64 ;;
  *) echo "unsupported host" >&2; exit 2 ;;
esac
rm -rf "$work"
mkdir -p "$work"
work=$(cd "$work" && pwd)
case "$work/" in "$source_dir"/*) echo "WORK_DIR must be outside $source_dir" >&2; exit 2 ;; esac

log() { printf '[e2e %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { log "FAIL: $*"; tail -n 60 "$work/install/server.log" >&2 || true; exit 1; }

build() { # VERSION SOURCE_DIR
  python3 "$2/scripts/build_update_zip.py" --out "$work/builds" --development --allow-dirty \
    --target "$target" --version "$1" | awk '{print $1}'
}

V1=v0.2.0 V2=v0.2.1 V3=v0.2.2-dev.1.unhealthy V4=v0.2.3
log "building $V1 $V2 $V4 from $source_dir"
build "$V1" "$source_dir" >/dev/null
zip2=$(build "$V2" "$source_dir")
zip4=$(build "$V4" "$source_dir")

log "building $V3 with a failing /health from a patched copy"
unhealthy="$work/unhealthy-src"
mkdir -p "$unhealthy"
(cd "$source_dir" && tar --exclude=.git --exclude=bin --exclude=data -cf - .) | (cd "$unhealthy" && tar -xf -)
perl -0pi -e 's/(\t\tw\.Write\(\[\]byte\(`\{"status":"ok")/\t\tw.WriteHeader(http.StatusServiceUnavailable)\n$1/' \
  "$unhealthy/internal/api/handlers/router.go"
grep -q 'WriteHeader(http.StatusServiceUnavailable)' "$unhealthy/internal/api/handlers/router.go" || fail "health patch not applied"
git -C "$unhealthy" init -q && git -C "$unhealthy" add -A && \
  git -C "$unhealthy" -c user.name=e2e -c user.email=e2e@example.invalid commit -qm unhealthy
zip3=$(build "$V3" "$unhealthy")

asset=shorebird-server-$target
install_dir="$work/install"
mkdir -p "$install_dir/bin"
cp "$work/builds/$V1/release/$asset" "$install_dir/bin/shorebird-server"
cd "$install_dir"
export SERVER_HOST=127.0.0.1 SERVER_PORT=$port SERVER_BASE_URL=$base DB_DRIVER=sqlite \
  DB_PATH="$install_dir/data/shorebird.db" STORAGE_DRIVER=local STORAGE_LOCAL_DIR="$install_dir/data/storage" \
  JWT_SECRET=e2e-jwt-secret-0123456789abcdef0123456789 DEFAULT_ADMIN_PASSWORD=admin123 \
  SERVER_UPDATE_TRIAL_SECONDS=8 SERVER_UPDATE_STARTUP_TIMEOUT_SECONDS=20 SERVER_UPDATE_MIRROR_URL=off
unset SHOREBIRD_SERVER_MANAGED_EXTERNALLY SERVER_SELF_UPDATE
"$install_dir/bin/shorebird-server" >"$install_dir/server.log" 2>&1 &
supervisor=$!
cleanup() {
  kill -TERM "$supervisor" 2>/dev/null || true
  wait "$supervisor" 2>/dev/null || true
}
trap cleanup EXIT

wait_for() { # DESCRIPTION SECONDS JQ_CONDITION
  local deadline=$((SECONDS + $2)) body=""
  while ((SECONDS < deadline)); do
    if body=$(curl -fsS -H "Authorization: Bearer $token" "$base/api/v1/admin/server/update" 2>/dev/null) &&
      jq -e "$3" >/dev/null <<<"$body"; then
      log "ok: $1 -> $(jq -c '{current_version,state,journal_state,error_code,last_rollback,rolled_back_version,rollback_version}' <<<"$body")"
      return 0
    fi
    sleep 1
  done
  fail "$1 (last status: $body)"
}
request() { # METHOD PATH [CONTENT_TYPE BODY|@FILE] -> prints "STATUS BODY"
  local out="$work/response" code
  if (($# > 2)); then
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $token" -H "Content-Type: $3" --data-binary "$4" "$base$2")
  else
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $token" "$base$2")
  fi
  printf '%s %s\n' "$code" "$(cat "$out")"
}
expect() { # WANT_STATUS WANT_CODE_OR_- "STATUS BODY"
  local status=${3%% *} body=${3#* }
  [[ "$status" == "$1" ]] || fail "HTTP $status, want $1: $body"
  if [[ "$2" != - ]]; then
    [[ "$(jq -r .code <<<"$body")" == "$2" ]] || fail "code $(jq -r .code <<<"$body"), want $2"
  fi
}

log "waiting for $V1"
for _ in $(seq 1 60); do curl -fsS "$base/health" >/dev/null 2>&1 && break; sleep 0.5; done
token=$(curl -fsS -H 'Content-Type: application/json' -d '{"email":"admin@example.com","password":"admin123"}' "$base/auth/token" | jq -r .token)
curl -fsS -X PATCH -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"current_password":"admin123","new_password":"e2e-admin-password"}' "$base/api/v1/users/me/password"
token=$(curl -fsS -H 'Content-Type: application/json' -d '{"email":"admin@example.com","password":"e2e-admin-password"}' "$base/auth/token" | jq -r .token)
wait_for "$V1 active under the supervisor" 30 ".mode == \"active\" and .current_version == \"$V1\" and .development_trust == true"

log "upload $V2 (stable ZIP on the stable channel)"
expect 202 - "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip2")"
wait_for "$V2 on trial" 60 ".current_version == \"$V2\" and .journal_state == \"trial\""
wait_for "$V2 healthy after its trial" 60 ".current_version == \"$V2\" and .journal_state == \"healthy\" and .rollback_version == \"$V1\""

log "manual rollback to $V1"
rollback_body() { jq -cn --arg p "$1" --arg c "$V2" --arg r "$V1" '{current_password:$p,current_version:$c,rollback_version:$r}'; }
wrong=$(rollback_body wrong)
right=$(rollback_body e2e-admin-password)
expect 401 REAUTH_FAILED "$(request POST /api/v1/admin/server/update/rollback application/json "$wrong")"
expect 202 - "$(request POST /api/v1/admin/server/update/rollback application/json "$right")"
wait_for "$V1 restored by manual rollback" 60 ".current_version == \"$V1\" and .last_rollback == \"manual\" and .rolled_back_version == \"$V2\" and .state == \"idle\""
expect 409 version_quarantined "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip2")"

log "upload unhealthy $V3 (dev ZIP)"
expect 409 dev_channel_required "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip3")"
settings='{"auto_update":false,"check_interval_seconds":86400,"channel":"dev"}'
expect 200 - "$(request PUT /api/v1/admin/server/update application/json "$settings")"
expect 202 - "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip3")"
wait_for "$V3 running on trial" 60 ".current_version == \"$V3\" and .journal_state == \"trial\""
wait_for "watchdog rolled $V3 back to $V1" 90 ".current_version == \"$V1\" and .last_rollback == \"watchdog\" and .rolled_back_version == \"$V3\" and .error_code == \"update_rolled_back\""
expect 409 version_quarantined "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip3")"

log "upload $V4 after the quarantine"
expect 202 - "$(request POST /api/v1/admin/server/update/upload application/zip "@$zip4")"
wait_for "$V4 healthy" 90 ".current_version == \"$V4\" and .journal_state == \"healthy\""

expect 200 - "$(request GET '/api/v1/admin/server/update/audit?limit=20')"
log "audit: $(jq -c '[.events[] | {action,result,auth}]' "$work/response")"
if grep -q 'e2e-admin-password' "$install_dir/bin/server-update-audit.jsonl" "$install_dir/server.log"; then
  fail "a password reached the audit log or server log"
fi

log "operator stop"
kill -TERM "$supervisor"
wait "$supervisor" || true
trap - EXIT
sleep 1
if pgrep -f "$install_dir/bin/shorebird-server" >/dev/null; then
  fail "a server process survived the supervisor"
fi
grep -E 'update_(trial|healthy|restart|trial_failed|rolled_back)' "$install_dir/server.log" | sed 's/^/    /'
ls -1 "$install_dir/bin" | sed 's/^/    bin: /'
log "PASS"
