#!/usr/bin/env bash
set -euo pipefail

# One-command local controlled-devnet rehearsal:
#   - boots genesis backend on 8001
#   - boots observer-edge backend on 8002
#   - starts an operator reconcile worker for observer tx queue -> genesis -> observer sync
#   - creates/prepares the observer test account through the observer path
#   - writes dev-bootstrap manifests for two separate browser origins
#   - starts observer frontend on 5173 and genesis frontend on 5174
#
# This is a local devnet convenience harness. It does not enable production
# authority, validator signing on the observer, direct session mutation, or demo
# state mutation. Secrets are emitted only under .weall-devnet/generated and are
# exposed to local frontends only when WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE=1.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$(cd "${REPO_ROOT}/.." && pwd)"
WEB_ROOT="${WEALL_WEB_ROOT:-${WORKSPACE_ROOT}/web}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
LOG_DIR="${WEALL_DEVNET_LOG_DIR:-${DEVNET_DIR}/logs}"
GENERATED_DIR="${DEVNET_DIR}/generated"
NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"
NODE2_API="${NODE2_API:-http://127.0.0.1:8002}"
GENESIS_BIND="${GENESIS_BIND:-127.0.0.1:8001}"
OBSERVER_BIND="${OBSERVER_BIND:-127.0.0.1:8002}"
OBSERVER_FRONTEND_PORT="${OBSERVER_FRONTEND_PORT:-5173}"
GENESIS_FRONTEND_PORT="${GENESIS_FRONTEND_PORT:-5174}"

# Bind Vite to all WSL interfaces by default so Windows browsers can reach it.
FRONTEND_BIND_HOST="${WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST:-0.0.0.0}"
FRONTEND_PUBLIC_HOST="${WEALL_LOCAL_REHEARSAL_FRONTEND_PUBLIC_HOST:-127.0.0.1}"
OBSERVER_ACCOUNT="${WEALL_OBSERVER_TEST_ACCOUNT:-@errol}"
GENESIS_ACCOUNT="${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-@devnet-genesis}"
OBSERVER_KEYFILE="${WEALL_OBSERVER_TEST_KEYFILE:-${DEVNET_DIR}/accounts/errol.json}"
GENESIS_KEYFILE="${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}"
OBSERVER_TOKEN="${WEALL_OBSERVER_EDGE_OPERATOR_TOKEN:-local-observer-operator-token}"
SYNC_TOKEN="${WEALL_STATE_SYNC_OPERATOR_TOKEN:-local-rehearsal-sync-token}"
LIVE_ROOM_TRANSPORT_MODE="${VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE:-p2p}"
LIVE_ROOM_BASE_URL="${VITE_WEALL_LIVE_ROOM_BASE_URL:-}"
LIVE_ROOM_EMBED="${VITE_WEALL_LIVE_ROOM_EMBED:-0}"
RESET="${WEALL_LOCAL_REHEARSAL_RESET:-1}"
KEEP_RUNNING="${WEALL_LOCAL_REHEARSAL_KEEP_RUNNING:-1}"
NPM_INSTALL="${WEALL_LOCAL_REHEARSAL_NPM_INSTALL:-1}"
STOP_OLD="${WEALL_LOCAL_REHEARSAL_STOP_OLD:-1}"
START_IPFS="${WEALL_LOCAL_REHEARSAL_START_IPFS:-1}"
IPFS_COMPOSE_FILE="${WEALL_IPFS_COMPOSE_FILE:-${REPO_ROOT}/docker-compose.ipfs.yml}"
IPFS_SERVICE="${WEALL_IPFS_SERVICE:-ipfs}"
IPFS_API_BASE="${WEALL_IPFS_API_BASE:-http://127.0.0.1:5001}"
IPFS_GATEWAY_BASE="${WEALL_IPFS_GATEWAY_BASE:-http://127.0.0.1:8080}"
IPFS_WAIT_SECONDS="${WEALL_LOCAL_REHEARSAL_IPFS_WAIT_SECONDS:-180}"
IPFS_PORT_REPAIR="${WEALL_LOCAL_REHEARSAL_IPFS_PORT_REPAIR:-1}"
IPFS_API_FALLBACK_PORT="${WEALL_LOCAL_REHEARSAL_IPFS_API_FALLBACK_PORT:-15001}"
IPFS_GATEWAY_FALLBACK_PORT="${WEALL_LOCAL_REHEARSAL_IPFS_GATEWAY_FALLBACK_PORT:-18080}"
IPFS_PARTITION_PATH="${WEALL_IPFS_PARTITION_PATH:-${DEVNET_DIR}/ipfs_partition}"

NODE1_PID=""
NODE2_PID=""
RECONCILE_PID=""
DOWNSTREAM_SYNC_PID=""
FRONTEND_OBSERVER_PID=""
FRONTEND_GENESIS_PID=""

cd "${REPO_ROOT}"

_bool_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

activate_repo_venv() {
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    return 0
  fi
  local activate_path="${REPO_ROOT}/.venv/bin/activate"
  if [[ -f "${activate_path}" ]]; then
    # shellcheck disable=SC1090
    source "${activate_path}"
    return 0
  fi
  echo "ERROR: Python virtualenv not active and ${activate_path} was not found." >&2
  echo "Run: cd ${REPO_ROOT} && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
}

_cleanup() {
  local status=$?
  if [[ "${KEEP_RUNNING}" != "1" ]]; then
    for pid in "${FRONTEND_GENESIS_PID}" "${FRONTEND_OBSERVER_PID}" "${DOWNSTREAM_SYNC_PID}" "${RECONCILE_PID}" "${NODE2_PID}" "${NODE1_PID}"; do
      if [[ -n "${pid}" ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" >/dev/null 2>&1 || true
      fi
    done
  else
    cat <<EOF2

==> Local rehearsal processes left running:
node1_pid=${NODE1_PID:-}
node2_pid=${NODE2_PID:-}
reconcile_pid=${RECONCILE_PID:-}
downstream_sync_pid=${DOWNSTREAM_SYNC_PID:-}
observer_frontend_pid=${FRONTEND_OBSERVER_PID:-}
genesis_frontend_pid=${FRONTEND_GENESIS_PID:-}
logs=${LOG_DIR}
EOF2
  fi
  exit "${status}"
}
trap _cleanup EXIT INT TERM

_wait_http() {
  local url="$1"
  local timeout_s="${2:-45}"
  local log_path="${3:-}"
  local deadline=$((SECONDS + timeout_s))
  until curl -fsS "${url}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "ERROR: timed out waiting for ${url}" >&2
      if [[ -n "${log_path}" && -f "${log_path}" ]]; then
        echo >&2
        echo "=== recent log: ${log_path} ===" >&2
        tail -n 160 "${log_path}" >&2 || true
      fi
      echo >&2
      echo "=== listening ports ===" >&2
      ss -ltnp 2>/dev/null | grep -E ':8001|:8002|:5173|:5174' >&2 || true
      return 1
    fi
    sleep 0.5
  done
}


_wait_frontend_root() {
  local base_url="${1%/}"
  local timeout_s="${2:-90}"
  local log_path="${3:-}"
  local deadline=$((SECONDS + timeout_s))
  local body=""
  until body="$(curl -fsS --max-time 5 "${base_url}/" 2>/dev/null || true)" && \
    printf '%s' "${body}" | grep -Eq 'id="root"|src="/src/main\.tsx"|src="/src/main\.ts"'; do
    if (( SECONDS >= deadline )); then
      echo "ERROR: timed out waiting for frontend index ${base_url}/" >&2
      echo >&2
      echo "=== curl probe: ${base_url}/ ===" >&2
      curl -sv --max-time 8 "${base_url}/" -o /tmp/weall-frontend-index-probe.html >&2 || true
      echo >&2
      echo "=== recent frontend log: ${log_path} ===" >&2
      if [[ -n "${log_path}" && -f "${log_path}" ]]; then
        tail -n 180 "${log_path}" >&2 || true
      fi
      echo >&2
      echo "=== listening ports ===" >&2
      ss -ltnp 2>/dev/null | grep -E ':8001|:8002|:5173|:5174' >&2 || true
      return 1
    fi
    sleep 0.5
  done
}

_wait_ipfs_api() {
  local api_base="${1%/}"
  local timeout_s="${2:-60}"
  local deadline=$((SECONDS + timeout_s))
  until curl -fsS --max-time 2 -X POST "${api_base}/api/v0/version" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 1
  done
}

_prepare_local_ipfs_repo_dirs() {
  # Kubo must create its own blockstore layout during `ipfs init`.
  # Do not pre-create blocks/ or blocks/temp before initialization; doing so
  # produces: "directory missing SHARDING file: /data/ipfs/blocks".
  mkdir -p "${IPFS_PARTITION_PATH}"
  chmod u+rwX,go+rwX "${IPFS_PARTITION_PATH}" 2>/dev/null || true

  if [[ -d "${IPFS_PARTITION_PATH}/blocks" && ! -f "${IPFS_PARTITION_PATH}/blocks/SHARDING" ]]; then
    echo "==> Resetting corrupt local IPFS repo: blocks/ exists without SHARDING"
    rm -rf "${IPFS_PARTITION_PATH}"
    mkdir -p "${IPFS_PARTITION_PATH}"
    chmod u+rwX,go+rwX "${IPFS_PARTITION_PATH}" 2>/dev/null || true
  fi

  # Batch 388 compatibility/safety: after Kubo has initialized a valid
  # sharded blockstore, make sure its transient batch directory exists and is
  # writable for local rehearsal uploads.  This is intentionally after the
  # corrupt-blockstore reset guard above so we never preserve a blocks/ tree
  # without SHARDING.
  if [[ -f "${IPFS_PARTITION_PATH}/blocks/SHARDING" ]]; then
    mkdir -p "${IPFS_PARTITION_PATH}/blocks/temp" || {
      echo "ERROR: failed to create batch temp directory: ${IPFS_PARTITION_PATH}/blocks/temp" >&2
      return 1
    }
    chmod u+rwX,go+rwX "${IPFS_PARTITION_PATH}/blocks/temp" 2>/dev/null || true
  fi
}

_ipfs_add_healthcheck() {
  local api_base="${1%/}"
  local tmp_file="${LOG_DIR}/ipfs-add-healthcheck.txt"
  mkdir -p "${LOG_DIR}"
  printf 'weall local rehearsal ipfs healthcheck\n' >"${tmp_file}"
  curl -fsS --max-time 15 \
    -X POST \
    -F "file=@${tmp_file};filename=weall-healthcheck.txt;type=text/plain" \
    "${api_base}/api/v0/add?pin=false&wrap-with-directory=false&progress=false" \
    >/dev/null 2>&1
}

_url_port() {
  local url="${1:-}"
  python3 - "${url}" <<'PY'
from urllib.parse import urlparse
import sys

url = sys.argv[1]
parsed = urlparse(url if "://" in url else f"http://{url}")
port = parsed.port
if port is None:
    if parsed.scheme == "https":
        port = 443
    else:
        port = 80
print(port)
PY
}

_replace_url_port() {
  local url="${1:-}"
  local port="${2:-}"
  python3 - "${url}" "${port}" <<'PY'
from urllib.parse import urlparse, urlunparse
import sys

url, port = sys.argv[1], sys.argv[2]
parsed = urlparse(url if "://" in url else f"http://{url}")
host = parsed.hostname or "127.0.0.1"
netloc = f"{host}:{port}"
print(urlunparse((parsed.scheme or "http", netloc, parsed.path or "", parsed.params, parsed.query, parsed.fragment)))
PY
}

_ipfs_compose_failure_looks_like_port_forward() {
  local log_path="${1:-}"
  [[ -f "${log_path}" ]] || return 1
  grep -Eiq 'ports are not available|forwards/expose|address already in use|Bind for .* failed|port is already allocated|listen tcp' "${log_path}"
}

_kill_local_port_listener() {
  local port="${1:-}"
  [[ -n "${port}" ]] || return 0

  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
    return 0
  fi

  ss -ltnp 2>/dev/null \
    | grep -E ":${port}\\b" \
    | sed -n 's/.*pid=\\([0-9][0-9]*\\).*/\\1/p' \
    | sort -u \
    | xargs -r kill >/dev/null 2>&1 || true
}

_repair_local_ipfs_ports() {
  if ! _bool_true "${IPFS_PORT_REPAIR}"; then
    return 0
  fi

  local api_port
  local gateway_port
  api_port="$(_url_port "${IPFS_API_BASE}")"
  gateway_port="$(_url_port "${IPFS_GATEWAY_BASE}")"

  echo "==> Cleaning stale local IPFS containers and port users (${api_port}/${gateway_port})"

  pkill -f "ipfs daemon" >/dev/null 2>&1 || true

  if command -v docker >/dev/null 2>&1 && [[ -f "${IPFS_COMPOSE_FILE}" ]]; then
    (
      cd "${REPO_ROOT}"
      export WEALL_IPFS_PARTITION_PATH="${IPFS_PARTITION_PATH}"
      docker compose -f "${IPFS_COMPOSE_FILE}" rm -sf "${IPFS_SERVICE}" >/dev/null 2>&1 || true
      docker compose -f "${IPFS_COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true
    )
    docker rm -f weall-ipfs ipfs Weall-Protocol-ipfs-1 weall-protocol-ipfs-1 >/dev/null 2>&1 || true
  fi

  _kill_local_port_listener "${api_port}"
  _kill_local_port_listener "${gateway_port}"
}

_print_ipfs_port_diagnostics() {
  echo >&2
  echo "=== IPFS port diagnostics ===" >&2
  echo "api=${IPFS_API_BASE} gateway=${IPFS_GATEWAY_BASE}" >&2
  ss -ltnp 2>/dev/null | grep -E ':4001|:5001|:8080|:15001|:18080' >&2 || true
  if command -v docker >/dev/null 2>&1; then
    docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}' >&2 || true
  fi
}

_docker_compose_up_ipfs() {
  local api_port
  local gateway_port
  api_port="$(_url_port "${IPFS_API_BASE}")"
  gateway_port="$(_url_port "${IPFS_GATEWAY_BASE}")"

  (
    cd "${REPO_ROOT}"
    export WEALL_IPFS_PARTITION_PATH="${IPFS_PARTITION_PATH}"
    # These exports let docker-compose.ipfs.yml use fallback ports when Docker
    # Desktop/WSL keeps a stale localhost forward even though `ss` shows no
    # Linux listener. Compose files that do not consume the variables continue
    # to use their existing literal mapping.
    export WEALL_IPFS_API_PORT="${api_port}"
    export WEALL_IPFS_GATEWAY_PORT="${gateway_port}"
    export IPFS_API_PORT="${api_port}"
    export IPFS_GATEWAY_PORT="${gateway_port}"
    docker compose -f "${IPFS_COMPOSE_FILE}" up -d --remove-orphans "${IPFS_SERVICE}"
  )
}

_start_ipfs_with_docker_compose_repair() {
  local compose_log="${LOG_DIR}/local-ipfs-compose-up.log"
  : >"${compose_log}"

  if _docker_compose_up_ipfs >"${compose_log}" 2>&1; then
    return 0
  fi

  cat "${compose_log}" >&2 || true
  if ! _ipfs_compose_failure_looks_like_port_forward "${compose_log}"; then
    return 1
  fi

  echo "==> Docker reported a local IPFS port bind/WSL forward problem; retrying after cleanup"
  _repair_local_ipfs_ports
  sleep 2

  : >"${compose_log}"
  if _docker_compose_up_ipfs >"${compose_log}" 2>&1; then
    return 0
  fi

  cat "${compose_log}" >&2 || true
  if ! _ipfs_compose_failure_looks_like_port_forward "${compose_log}"; then
    return 1
  fi

  # Docker Desktop on WSL can retain a stale localhost forward that is invisible
  # to `ss` inside the distro. Avoid forcing the operator to run `wsl --shutdown`
  # by moving this rehearsal's IPFS ports to known alternate localhost ports.
  local old_api="${IPFS_API_BASE}"
  local old_gateway="${IPFS_GATEWAY_BASE}"
  IPFS_API_BASE="$(_replace_url_port "${IPFS_API_BASE}" "${IPFS_API_FALLBACK_PORT}")"
  IPFS_GATEWAY_BASE="$(_replace_url_port "${IPFS_GATEWAY_BASE}" "${IPFS_GATEWAY_FALLBACK_PORT}")"

  echo "==> Falling back IPFS ports for this rehearsal:"
  echo "    api: ${old_api} -> ${IPFS_API_BASE}"
  echo "    gateway: ${old_gateway} -> ${IPFS_GATEWAY_BASE}"

  _repair_local_ipfs_ports
  sleep 2

  : >"${compose_log}"
  if _docker_compose_up_ipfs >"${compose_log}" 2>&1; then
    return 0
  fi

  cat "${compose_log}" >&2 || true
  cat >&2 <<EOF_REPAIR
ERROR: Docker still could not expose IPFS ports after cleanup and fallback.

This usually means Docker Desktop/WSL has a stale port-forward outside the
Linux process table. The script already tried:
  - docker compose rm/down
  - removing likely stale IPFS containers
  - killing local Linux listeners
  - retrying on fallback ports ${IPFS_API_BASE} / ${IPFS_GATEWAY_BASE}

Last resort from Windows PowerShell:
  wsl --shutdown

Then reopen WSL and rerun this script.
EOF_REPAIR
  return 1
}

_stop_local_ipfs_daemon() {
  if ! _bool_true "${START_IPFS}"; then
    return 0
  fi
  _repair_local_ipfs_ports
}

_start_local_ipfs_daemon() {
  if ! _bool_true "${START_IPFS}"; then
    echo "==> Skipping IPFS daemon startup (WEALL_LOCAL_REHEARSAL_START_IPFS=${START_IPFS})"
    return 0
  fi

  mkdir -p "${LOG_DIR}"
  _prepare_local_ipfs_repo_dirs

  if _wait_ipfs_api "${IPFS_API_BASE}" 2; then
    if _ipfs_add_healthcheck "${IPFS_API_BASE}"; then
      echo "==> IPFS daemon already reachable and add-healthy at ${IPFS_API_BASE}"
      return 0
    fi
    echo "==> IPFS daemon is reachable but add-unhealthy; restarting local rehearsal IPFS"
    _stop_local_ipfs_daemon
    sleep 2
  fi

  _prepare_local_ipfs_repo_dirs
  echo "==> Starting local IPFS daemon for PoH evidence uploads"

  if command -v docker >/dev/null 2>&1 && [[ -f "${IPFS_COMPOSE_FILE}" ]]; then
    if ! _start_ipfs_with_docker_compose_repair; then
      _print_ipfs_port_diagnostics
      docker compose -f "${IPFS_COMPOSE_FILE}" ps "${IPFS_SERVICE}" >&2 || true
      docker compose -f "${IPFS_COMPOSE_FILE}" logs "${IPFS_SERVICE}" --tail 160 >&2 || true
      exit 2
    fi
    if ! _wait_ipfs_api "${IPFS_API_BASE}" "${IPFS_WAIT_SECONDS}"; then
      echo "ERROR: IPFS daemon did not become reachable at ${IPFS_API_BASE}" >&2
      _print_ipfs_port_diagnostics
      docker compose -f "${IPFS_COMPOSE_FILE}" ps "${IPFS_SERVICE}" >&2 || true
      docker compose -f "${IPFS_COMPOSE_FILE}" logs "${IPFS_SERVICE}" --tail 160 >&2 || true
      exit 2
    fi
    _prepare_local_ipfs_repo_dirs
    if ! _ipfs_add_healthcheck "${IPFS_API_BASE}"; then
      echo "ERROR: IPFS daemon is reachable but /api/v0/add failed at ${IPFS_API_BASE}" >&2
      docker compose -f "${IPFS_COMPOSE_FILE}" logs "${IPFS_SERVICE}" --tail 160 >&2 || true
      exit 2
    fi
    echo "==> IPFS daemon ready and add-healthy at ${IPFS_API_BASE}"
    return 0
  fi

  if command -v ipfs >/dev/null 2>&1; then
    export IPFS_PATH="${WEALL_IPFS_PATH:-${DEVNET_DIR}/ipfs}"
    mkdir -p "${IPFS_PATH}" "${IPFS_PATH}/blocks" "${IPFS_PATH}/blocks/temp"
    if [[ ! -f "${IPFS_PATH}/config" ]]; then
      ipfs init --profile=server >/dev/null
    fi
    nohup ipfs daemon --migrate=true >"${LOG_DIR}/local-ipfs-daemon.log" 2>&1 &
    if ! _wait_ipfs_api "${IPFS_API_BASE}" "${IPFS_WAIT_SECONDS}"; then
      echo "ERROR: local ipfs daemon did not become reachable at ${IPFS_API_BASE}" >&2
      tail -n 160 "${LOG_DIR}/local-ipfs-daemon.log" >&2 || true
      exit 2
    fi
    if ! _ipfs_add_healthcheck "${IPFS_API_BASE}"; then
      echo "ERROR: local ipfs daemon is reachable but /api/v0/add failed at ${IPFS_API_BASE}" >&2
      tail -n 160 "${LOG_DIR}/local-ipfs-daemon.log" >&2 || true
      exit 2
    fi
    echo "==> IPFS daemon ready and add-healthy at ${IPFS_API_BASE}"
    return 0
  fi

  cat >&2 <<EOF2
ERROR: IPFS daemon is required for PoH async video evidence uploads, but no daemon is reachable at ${IPFS_API_BASE}.
Install Docker with the compose plugin or install Kubo/ipfs, then rerun this script.
Set WEALL_LOCAL_REHEARSAL_START_IPFS=0 only if you have already started a compatible IPFS daemon yourself.
EOF2
  exit 2
}

_stop_existing_rehearsal_processes() {
  echo "==> Stopping old local rehearsal processes on 8001/8002/5173/5174"
  pkill -f "vite .*--port ${OBSERVER_FRONTEND_PORT}" >/dev/null 2>&1 || true
  pkill -f "vite .*--port ${GENESIS_FRONTEND_PORT}" >/dev/null 2>&1 || true
  pkill -f "gunicorn.*weall" >/dev/null 2>&1 || true
  pkill -f "uvicorn.*weall" >/dev/null 2>&1 || true

  if command -v fuser >/dev/null 2>&1; then
    fuser -k 8001/tcp 8002/tcp "${OBSERVER_FRONTEND_PORT}/tcp" "${GENESIS_FRONTEND_PORT}/tcp" >/dev/null 2>&1 || true
  else
    ss -ltnp 2>/dev/null \
      | grep -E ":8001|:8002|:${OBSERVER_FRONTEND_PORT}|:${GENESIS_FRONTEND_PORT}" \
      | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' \
      | sort -u \
      | xargs -r kill >/dev/null 2>&1 || true
  fi

  sleep 2
  echo "==> Port state after cleanup"
  ss -ltnp 2>/dev/null | grep -E ':8001|:8002|:5173|:5174' || true
}

_json_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
cur = data
for part in field.split('.'):
    cur = cur.get(part) if isinstance(cur, dict) else None
print(str(cur or '').strip())
PY
}

_write_secret_and_manifest() {
  local account="$1"
  local keyfile="$2"
  local secret_file="$3"
  local manifest_file="$4"
  local profile="$5"
  local create_account="$6"
  python3 - "$account" "$keyfile" "$secret_file" "$manifest_file" "$profile" "$create_account" <<'PY'
import base64, json, sys, time
from pathlib import Path
account, keyfile, secret_file, manifest_file, profile, create_account = sys.argv[1:]
key = json.loads(Path(keyfile).read_text(encoding='utf-8'))
seed = bytes.fromhex(str(key.get('private_key_hex') or ''))
pub = bytes.fromhex(str(key.get('public_key_hex') or ''))
if len(seed) != 32 or len(pub) != 32:
    raise SystemExit(f'invalid keyfile for {account}: {keyfile}')
secret_b64 = base64.b64encode(seed + pub).decode('ascii')
pub_b64 = base64.b64encode(pub).decode('ascii')
Path(secret_file).parent.mkdir(parents=True, exist_ok=True)
Path(secret_file).write_text(json.dumps({
    'account': account,
    'pubkey_b64': pub_b64,
    'secret_key_b64': secret_b64,
    'session_ttl_seconds': 24 * 60 * 60,
    'warning': 'local controlled-devnet browser bootstrap secret; never commit or use in production',
}, indent=2) + '\n', encoding='utf-8')
Path(manifest_file).parent.mkdir(parents=True, exist_ok=True)
Path(manifest_file).write_text(json.dumps({
    'profile': profile,
    'generated_at_ms': int(time.time() * 1000),
    'account': account,
    'pubkeyB64': pub_b64,
    'apiBase': '/',
    'createAccount': create_account.lower() in {'1', 'true', 'yes', 'on'},
    'waitForAccountMs': 45000,
    'sessionTtlSeconds': 24 * 60 * 60,
    'note': 'Generated by scripts/devnet_local_two_frontend_rehearsal.sh',
}, indent=2) + '\n', encoding='utf-8')
print(f'wrote {secret_file}')
print(f'wrote {manifest_file}')
PY
}


_account_exists() {
  local api="$1"
  local account="$2"
  python3 - "$api" "$account" <<'PY'
import json, sys, urllib.parse, urllib.request
api, account = sys.argv[1].rstrip('/'), sys.argv[2]
try:
    with urllib.request.urlopen(api + '/v1/accounts/' + urllib.parse.quote(account, safe=''), timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8') or '{}')
except Exception:
    raise SystemExit(1)
state = data.get('state') if isinstance(data, dict) else {}
if not isinstance(state, dict):
    raise SystemExit(1)
if int(state.get('nonce') or 0) > 0 or str(state.get('pubkey') or '').strip() or state.get('keys'):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

_wait_tx_local_state_synced() {
  local api="$1"
  local tx_id="$2"
  local timeout_s="${3:-90}"
  if [[ -z "${tx_id}" ]]; then
    return 0
  fi
  python3 - "$api" "$tx_id" "$OBSERVER_TOKEN" "$SYNC_TOKEN" "$timeout_s" <<'PYSYNC'
import json, sys, time, urllib.parse, urllib.request, urllib.error
api, tx_id, observer_token, sync_token, timeout_s = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5])
deadline = time.time() + timeout_s
last = {}

def request(method, path):
    headers = {
        'accept': 'application/json',
        'x-weall-observer-operator-token': observer_token,
        'x-weall-state-sync-operator-token': sync_token,
    }
    data = None
    if method != 'GET':
        data = b'{}'
        headers['content-type'] = 'application/json'
    req = urllib.request.Request(api + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode('utf-8', errors='replace')
        try:
            return json.loads(raw) if raw.strip() else {'ok': False, 'status': exc.code}
        except Exception:
            return {'ok': False, 'status': exc.code, 'raw': raw[:500]}
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__, 'detail': str(exc)[:256]}

encoded = urllib.parse.quote(tx_id, safe=':')
while time.time() <= deadline:
    last = request('GET', f'/v1/tx/status/{encoded}')
    if bool(last.get('ok')) and last.get('local_state_synced') is True:
        print(json.dumps({'ok': True, 'tx_id': tx_id, 'local_state_synced': True, 'source': 'status'}))
        raise SystemExit(0)
    rec = request('POST', f'/v1/observer/edge/reconcile/{encoded}')
    if bool(rec.get('ok')) and rec.get('local_state_synced') is True:
        print(json.dumps({'ok': True, 'tx_id': tx_id, 'local_state_synced': True, 'source': 'reconcile'}))
        raise SystemExit(0)
    last = {'status': last, 'reconcile': rec}
    time.sleep(1.0)
print(json.dumps({'ok': False, 'tx_id': tx_id, 'local_state_synced': False, 'last': last}, indent=2), file=sys.stderr)
raise SystemExit(1)
PYSYNC
}

_wait_account_nonce() {
  local api="$1"
  local account="$2"
  local min_nonce="$3"
  local timeout_s="${4:-60}"
  python3 - "$api" "$account" "$min_nonce" "$timeout_s" <<'PY'
import json, sys, time, urllib.parse, urllib.request
api, account, min_nonce, timeout_s = sys.argv[1].rstrip('/'), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
deadline = time.time() + timeout_s
last = {}
while time.time() <= deadline:
    try:
        with urllib.request.urlopen(api + '/v1/accounts/' + urllib.parse.quote(account, safe=''), timeout=5) as resp:
            last = json.loads(resp.read().decode('utf-8') or '{}')
        state = last.get('state') if isinstance(last, dict) else {}
        nonce = int((state or {}).get('nonce') or 0)
        if nonce >= min_nonce:
            print(json.dumps({'ok': True, 'api': api, 'account': account, 'nonce': nonce}, sort_keys=True))
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(0.5)
print(json.dumps({'ok': False, 'api': api, 'account': account, 'min_nonce': min_nonce, 'last': last}, sort_keys=True))
raise SystemExit(1)
PY
}

activate_repo_venv
mkdir -p "${LOG_DIR}" "${GENERATED_DIR}" "${DEVNET_DIR}/accounts" "${WEB_ROOT}/public" "${REPO_ROOT}/data"

if _bool_true "${STOP_OLD}"; then
  _stop_existing_rehearsal_processes
fi

if _bool_true "${RESET}"; then
  echo "==> Resetting local controlled-devnet state"
  _stop_local_ipfs_daemon
  WEALL_DEVNET_DIR="${DEVNET_DIR}" bash scripts/devnet_reset_state.sh
  rm -f "${REPO_ROOT}/data/observer_tx_queue.json"
  mkdir -p "${LOG_DIR}" "${GENERATED_DIR}" "${DEVNET_DIR}/accounts" "${WEB_ROOT}/public"
fi

_start_local_ipfs_daemon

python3 scripts/devnet_tx.py ensure-keyfile --account "${GENESIS_ACCOUNT}" --keyfile "${GENESIS_KEYFILE}" >/dev/null
python3 scripts/devnet_tx.py ensure-keyfile --account "${OBSERVER_ACCOUNT}" --keyfile "${OBSERVER_KEYFILE}" >/dev/null

GENESIS_SECRET="${GENERATED_DIR}/dev-bootstrap-genesis-secret.json"
OBSERVER_SECRET="${GENERATED_DIR}/dev-bootstrap-observer-secret.json"
GENESIS_MANIFEST="${WEB_ROOT}/public/dev-bootstrap-genesis.json"
OBSERVER_MANIFEST="${WEB_ROOT}/public/dev-bootstrap-observer.json"
_write_secret_and_manifest "${GENESIS_ACCOUNT}" "${GENESIS_KEYFILE}" "${GENESIS_SECRET}" "${GENESIS_MANIFEST}" "local-controlled-devnet-genesis" "0"
_write_secret_and_manifest "${OBSERVER_ACCOUNT}" "${OBSERVER_KEYFILE}" "${OBSERVER_SECRET}" "${OBSERVER_MANIFEST}" "local-controlled-devnet-observer" "1"

GENESIS_LOG="${LOG_DIR}/local-genesis-rehearsal.log"
OBSERVER_LOG="${LOG_DIR}/local-observer-rehearsal.log"
RECONCILE_LOG="${LOG_DIR}/local-observer-reconcile.log"
DOWNSTREAM_SYNC_LOG="${LOG_DIR}/local-genesis-to-observer-sync.log"
FRONTEND_OBSERVER_LOG="${LOG_DIR}/frontend-observer-5173.log"
FRONTEND_GENESIS_LOG="${LOG_DIR}/frontend-genesis-5174.log"

pkill -f "vite .*--port ${OBSERVER_FRONTEND_PORT}" >/dev/null 2>&1 || true
pkill -f "vite .*--port ${GENESIS_FRONTEND_PORT}" >/dev/null 2>&1 || true

if ! curl -fsS "${NODE1_API}/v1/status" >/dev/null 2>&1; then
  echo "==> Booting genesis backend ${NODE1_API}"
  (
    export WEALL_DEVNET_DIR="${DEVNET_DIR}"
    export WEALL_MODE=devnet
    export WEALL_RUNTIME_PROFILE=controlled_devnet
    export WEALL_CHAIN_ID=weall-controlled-devnet
    export WEALL_NODE_ID="${GENESIS_ACCOUNT}"
    export GUNICORN_BIND="${GENESIS_BIND}"
    export WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE=1
    export WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN=1
    export WEALL_STATE_SYNC_OPERATOR_TOKEN="${SYNC_TOKEN}"
    export WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN="${SYNC_TOKEN}"
    export WEALL_WEBRTC_SIGNAL_BRIDGE_AUTODRAIN=1
    export WEALL_WEBRTC_SIGNAL_PEER_URLS="${NODE2_API}"
    export WEALL_WEBRTC_SIGNAL_PEERS_JSON='[{"node_id":"@local-observer","url":"'"${NODE2_API}"'","chain_id":"weall-controlled-devnet","bridge_token":"'"${SYNC_TOKEN}"'"}]'
    export WEALL_WEBRTC_STUN_URLS="${WEALL_WEBRTC_STUN_URLS:-}"
    export WEALL_STATE_RAW_READ_TOKEN="${SYNC_TOKEN}"
    # Local rehearsal has two frontends, a sync worker, an observer queue drain,
    # and manual user clicks sharing localhost. Keep production rate limits
    # intact while giving this controlled devnet explicit local headroom.
    export WEALL_RL_WRITE_RATE_PER_SEC="${WEALL_RL_WRITE_RATE_PER_SEC:-80}"
    export WEALL_RL_WRITE_BURST="${WEALL_RL_WRITE_BURST:-240}"
    export WEALL_RL_READ_RATE_PER_SEC="${WEALL_RL_READ_RATE_PER_SEC:-160}"
    export WEALL_RL_READ_BURST="${WEALL_RL_READ_BURST:-480}"
    export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE=1
    export WEALL_STATE_SYNC_APPLY_REQUIRE_OPERATOR_TOKEN=1
    export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE=1
    export WEALL_DEV_BOOTSTRAP_SECRET_PATH="${GENESIS_SECRET}"
    # Local controlled-devnet rehearsal permits this node-local evidence intake
    # helper. Production remains fail-closed because the endpoint is disabled
    # unless explicitly enabled by the operator.
    export WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1
    # A browser-recorded 60-120 second WebM can exceed the generic 1MB
    # request cap. Keep this local controlled-devnet rehearsal usable without
    # weakening production defaults; the route still enforces its own explicit
    # PoH video cap.
    export WEALL_POH_ASYNC_VIDEO_MAX_BYTES="${WEALL_POH_ASYNC_VIDEO_MAX_BYTES:-104857600}"
    export WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}"
    export WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}"
    export WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}"
    export WEALL_POH_ASYNC_REJECTION_THRESHOLD="${WEALL_POH_ASYNC_REJECTION_THRESHOLD:-1}"
    export WEALL_POH_ASYNC_MIN_REP_MILLI="${WEALL_POH_ASYNC_MIN_REP_MILLI:-0}"
    # Local one-reviewer live verification quorum.  This keeps the controlled
    # two-frontend rehearsal usable before a real reviewer pool exists while
    # preserving production defaults unless these env vars are explicitly set.
    export WEALL_POH_LIVE_MIN_REP_MILLI="${WEALL_POH_LIVE_MIN_REP_MILLI:-0}"
    export WEALL_POH_LIVE_PASS_THRESHOLD_NUM="${WEALL_POH_LIVE_PASS_THRESHOLD_NUM:-1}"
    export WEALL_POH_LIVE_PASS_THRESHOLD_DEN="${WEALL_POH_LIVE_PASS_THRESHOLD_DEN:-1}"
    export WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"
    export WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT="${WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT:-500}"
    export WEALL_IPFS_API_BASE="${IPFS_API_BASE}"
    export WEALL_IPFS_GATEWAY_BASE="${IPFS_GATEWAY_BASE}"
    exec bash scripts/devnet_boot_genesis_node.sh
  ) >"${GENESIS_LOG}" 2>&1 &
  NODE1_PID="$!"
fi
_wait_http "${NODE1_API}/v1/status" 90 "${GENESIS_LOG}"

if ! curl -fsS "${NODE2_API}/v1/status" >/dev/null 2>&1; then
  echo "==> Booting observer backend ${NODE2_API}"
  (
    export WEALL_DEVNET_DIR="${DEVNET_DIR}"
    export NODE1_API="${NODE1_API}"
    export WEALL_MODE=devnet
    export WEALL_RUNTIME_PROFILE=controlled_devnet
    export WEALL_CHAIN_ID=weall-controlled-devnet
    export WEALL_NODE_ID="@local-observer"
    export WEALL_DB_PATH="${DEVNET_DIR}/node2/weall.db"
    export GUNICORN_BIND="${OBSERVER_BIND}"
    export WEALL_OBSERVER_MODE=1
    export WEALL_NODE_LIFECYCLE_STATE=observer_onboarding
    export WEALL_NET_ENABLED=0
    export WEALL_BFT_ENABLED=0
    export WEALL_VALIDATOR_SIGNING_ENABLED=0
    export WEALL_BLOCK_LOOP_AUTOSTART=0
    export WEALL_OBSERVER_EDGE_MODE=1
    export WEALL_GENESIS_API_BASE="${NODE1_API}"
    export WEALL_BOOTSTRAP_API_BASE="${NODE1_API}"
    export WEALL_TX_UPSTREAM_URLS="${NODE1_API}"
    export WEALL_TX_UPSTREAM_REQUIRED=1
    export WEALL_TX_UPSTREAM_VERIFY_IDENTITY=1
    export WEALL_TX_UPSTREAM_REQUIRE_MANIFEST=0
    export WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT=0
    export WEALL_TX_QUEUE_AUTODRAIN=1
    export WEALL_TX_QUEUE_DRAIN_INTERVAL_S="${WEALL_TX_QUEUE_DRAIN_INTERVAL_S:-1}"
    export WEALL_TX_QUEUE_DRAIN_BATCH="${WEALL_TX_QUEUE_DRAIN_BATCH:-25}"
    export WEALL_OPERATOR_TOKEN="${OBSERVER_TOKEN}"
    export WEALL_OBSERVER_EDGE_OPERATOR_TOKEN="${OBSERVER_TOKEN}"
    export WEALL_STATE_SYNC_OPERATOR_TOKEN="${SYNC_TOKEN}"
    export WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN="${SYNC_TOKEN}"
    export WEALL_WEBRTC_SIGNAL_BRIDGE_AUTODRAIN=1
    export WEALL_WEBRTC_SIGNAL_PEER_URLS="${NODE1_API}"
    # pinned peer marker: "node_id":"${GENESIS_ACCOUNT}"
    export WEALL_WEBRTC_SIGNAL_PEERS_JSON='[{"node_id":"'"${GENESIS_ACCOUNT}"'","url":"'"${NODE1_API}"'","chain_id":"weall-controlled-devnet","bridge_token":"'"${SYNC_TOKEN}"'"}]'
    export WEALL_WEBRTC_STUN_URLS="${WEALL_WEBRTC_STUN_URLS:-}"
    export WEALL_STATE_RAW_READ_TOKEN="${SYNC_TOKEN}"
    # Local rehearsal has two frontends, a sync worker, an observer queue drain,
    # and manual user clicks sharing localhost. Keep production rate limits
    # intact while giving this controlled devnet explicit local headroom.
    export WEALL_RL_WRITE_RATE_PER_SEC="${WEALL_RL_WRITE_RATE_PER_SEC:-80}"
    export WEALL_RL_WRITE_BURST="${WEALL_RL_WRITE_BURST:-240}"
    export WEALL_RL_READ_RATE_PER_SEC="${WEALL_RL_READ_RATE_PER_SEC:-160}"
    export WEALL_RL_READ_BURST="${WEALL_RL_READ_BURST:-480}"
    export WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE=1
    export WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN=1
    export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE=1
    export WEALL_STATE_SYNC_APPLY_REQUIRE_OPERATOR_TOKEN=1
    export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE=1
    export WEALL_DEV_BOOTSTRAP_SECRET_PATH="${OBSERVER_SECRET}"
    # Local controlled-devnet rehearsal permits this node-local evidence intake
    # helper. Production remains fail-closed because the endpoint is disabled
    # unless explicitly enabled by the operator.
    export WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD=1
    # Observer UI uploads native async verification video evidence through this
    # backend. Use an explicit local rehearsal cap large enough for a 60-120
    # second browser recording while preserving fail-closed production defaults.
    export WEALL_POH_ASYNC_VIDEO_MAX_BYTES="${WEALL_POH_ASYNC_VIDEO_MAX_BYTES:-104857600}"
    export WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}"
    export WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}"
    export WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}"
    export WEALL_POH_ASYNC_REJECTION_THRESHOLD="${WEALL_POH_ASYNC_REJECTION_THRESHOLD:-1}"
    export WEALL_POH_ASYNC_MIN_REP_MILLI="${WEALL_POH_ASYNC_MIN_REP_MILLI:-0}"
    # Local one-reviewer live verification quorum.  This keeps the controlled
    # two-frontend rehearsal usable before a real reviewer pool exists while
    # preserving production defaults unless these env vars are explicitly set.
    export WEALL_POH_LIVE_MIN_REP_MILLI="${WEALL_POH_LIVE_MIN_REP_MILLI:-0}"
    export WEALL_POH_LIVE_PASS_THRESHOLD_NUM="${WEALL_POH_LIVE_PASS_THRESHOLD_NUM:-1}"
    export WEALL_POH_LIVE_PASS_THRESHOLD_DEN="${WEALL_POH_LIVE_PASS_THRESHOLD_DEN:-1}"
    export WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"
    export WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT="${WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT:-500}"
    export WEALL_IPFS_API_BASE="${IPFS_API_BASE}"
    export WEALL_IPFS_GATEWAY_BASE="${IPFS_GATEWAY_BASE}"
    export WEALL_CORS_ORIGINS="http://${FRONTEND_PUBLIC_HOST}:${OBSERVER_FRONTEND_PORT},http://localhost:${OBSERVER_FRONTEND_PORT},http://${FRONTEND_PUBLIC_HOST}:${GENESIS_FRONTEND_PORT},http://localhost:${GENESIS_FRONTEND_PORT}"
    exec bash scripts/devnet_boot_joining_node.sh
  ) >"${OBSERVER_LOG}" 2>&1 &
  NODE2_PID="$!"
fi
_wait_http "${NODE2_API}/v1/status" 90 "${OBSERVER_LOG}"

if [[ -z "${RECONCILE_PID}" ]]; then
  echo "==> Starting observer reconcile worker"
  (
    export OBSERVER_API="${NODE2_API}"
    export WEALL_OBSERVER_EDGE_OPERATOR_TOKEN="${OBSERVER_TOKEN}"
    export WEALL_STATE_SYNC_OPERATOR_TOKEN="${SYNC_TOKEN}"
    export WEALL_RECONCILE_POLL_S="${WEALL_RECONCILE_POLL_S:-1}"
    exec bash scripts/devnet_observer_tx_queue_reconcile_loop.sh
  ) >"${RECONCILE_LOG}" 2>&1 &
  RECONCILE_PID="$!"
fi

if [[ -z "${DOWNSTREAM_SYNC_PID}" ]]; then
  echo "==> Starting genesis-to-observer downstream sync worker"
  (
    export NODE1_API="${NODE1_API}"
    export NODE2_API="${NODE2_API}"
    export WEALL_STATE_SYNC_OPERATOR_TOKEN="${SYNC_TOKEN}"
    export WEALL_OBSERVER_EDGE_OPERATOR_TOKEN="${OBSERVER_TOKEN}"
    export WEALL_DEVNET_SYNC_MAX_ROUNDS="${WEALL_LOCAL_REHEARSAL_DOWNSTREAM_SYNC_MAX_ROUNDS:-2}"
    export WEALL_DEVNET_SYNC_SLEEP="${WEALL_LOCAL_REHEARSAL_DOWNSTREAM_SYNC_SLEEP:-0.25}"
    interval="${WEALL_LOCAL_REHEARSAL_DOWNSTREAM_SYNC_INTERVAL_S:-2}"
    echo "==> downstream sync loop source=${NODE1_API} target=${NODE2_API} interval=${interval}s"
    while true; do
      bash scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}" || true
      sleep "${interval}"
    done
  ) >"${DOWNSTREAM_SYNC_LOG}" 2>&1 &
  DOWNSTREAM_SYNC_PID="$!"
fi

OBSERVER_REGISTER_TX_ID=""
if ! _account_exists "${NODE2_API}" "${OBSERVER_ACCOUNT}"; then
  echo "==> Creating ${OBSERVER_ACCOUNT} through observer frontend path backend"
  python3 scripts/devnet_tx.py --api "${NODE2_API}" create-account \
    --account "${OBSERVER_ACCOUNT}" \
    --keyfile "${OBSERVER_KEYFILE}" \
    --reuse-keyfile \
    | tee "${GENERATED_DIR}/observer-account-register.json"
fi
if [[ -f "${GENERATED_DIR}/observer-account-register.json" ]]; then
  OBSERVER_REGISTER_TX_ID="$(_json_field "${GENERATED_DIR}/observer-account-register.json" tx_id || true)"
fi

# Keep the browser bootstrap secret/manifest bound to the same key material that
# the observer account registration actually used. devnet_tx.py defaults to a
# fresh account key unless --reuse-keyfile is explicit, and stale bootstrap
# manifests surface in the UI as a misleading "signature verification failed".
_write_secret_and_manifest "${OBSERVER_ACCOUNT}" "${OBSERVER_KEYFILE}" "${OBSERVER_SECRET}" "${OBSERVER_MANIFEST}" "local-controlled-devnet-observer" "1"

# Wait until the account is confirmed upstream and then explicitly reconciled
# into the observer's local state. The browser signs subsequent onboarding
# transactions against the observer backend; starting the UI while the observer
# only has an upstream-reconciled status can surface as a misleading 403
# "signature verification failed" because local signature admission cannot yet
# see the account's active key.
_wait_account_nonce "${NODE1_API}" "${OBSERVER_ACCOUNT}" 1 75
if [[ -n "${OBSERVER_REGISTER_TX_ID}" ]]; then
  if ! _wait_tx_local_state_synced "${NODE2_API}" "${OBSERVER_REGISTER_TX_ID}" 90; then
    echo "==> Observer account-registration tx status has not proven upstream confirmation yet."
    echo "==> Falling back only for this setup account to state proof on both nodes."
    echo "==> Live/async verification txs still require confirmed-and-synced tx/case visibility."
    _wait_account_nonce "${NODE1_API}" "${OBSERVER_ACCOUNT}" 1 30
    _wait_account_nonce "${NODE2_API}" "${OBSERVER_ACCOUNT}" 1 30
  fi
fi
_wait_account_nonce "${NODE2_API}" "${OBSERVER_ACCOUNT}" 1 75

if [[ ! -d "${WEB_ROOT}/node_modules" ]]; then
  if _bool_true "${NPM_INSTALL}"; then
    echo "==> Installing frontend dependencies with npm ci"
    (cd "${WEB_ROOT}" && npm ci)
  else
    echo "ERROR: ${WEB_ROOT}/node_modules is missing. Run npm ci or set WEALL_LOCAL_REHEARSAL_NPM_INSTALL=1." >&2
    exit 2
  fi
fi

rm -rf "${WEB_ROOT}/node_modules/.vite" "${WEB_ROOT}/dist"

echo "==> Starting observer frontend on http://${FRONTEND_PUBLIC_HOST}:${OBSERVER_FRONTEND_PORT}"
(
  cd "${WEB_ROOT}"
  export VITE_WEALL_API_BASE="/"
  export VITE_WEALL_DEV_PROXY_TARGET="${NODE2_API}"
  export VITE_WEALL_ENABLE_DEV_BOOTSTRAP=1
  export VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/dev-bootstrap-observer.json"
  export VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE="${LIVE_ROOM_TRANSPORT_MODE}"
  export VITE_WEALL_LIVE_ROOM_BASE_URL="${LIVE_ROOM_BASE_URL}"
  export VITE_WEALL_LIVE_ROOM_EMBED="${LIVE_ROOM_EMBED}"
  exec npm run dev -- --host "${FRONTEND_BIND_HOST}" --port "${OBSERVER_FRONTEND_PORT}" --strictPort --force
) >"${FRONTEND_OBSERVER_LOG}" 2>&1 &
FRONTEND_OBSERVER_PID="$!"

echo "==> Starting genesis frontend on http://${FRONTEND_PUBLIC_HOST}:${GENESIS_FRONTEND_PORT}"
(
  cd "${WEB_ROOT}"
  export VITE_WEALL_API_BASE="/"
  export VITE_WEALL_DEV_PROXY_TARGET="${NODE1_API}"
  export VITE_WEALL_ENABLE_DEV_BOOTSTRAP=1
  export VITE_WEALL_DEV_BOOTSTRAP_MANIFEST="/dev-bootstrap-genesis.json"
  export VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE="${LIVE_ROOM_TRANSPORT_MODE}"
  export VITE_WEALL_LIVE_ROOM_BASE_URL="${LIVE_ROOM_BASE_URL}"
  export VITE_WEALL_LIVE_ROOM_EMBED="${LIVE_ROOM_EMBED}"
  exec npm run dev -- --host "${FRONTEND_BIND_HOST}" --port "${GENESIS_FRONTEND_PORT}" --strictPort --force
) >"${FRONTEND_GENESIS_LOG}" 2>&1 &
FRONTEND_GENESIS_PID="$!"

# Readiness must prove both the frontend shell and proxied backend route.
# A proxied /v1/status alone can pass while the browser still cannot load the app.
_wait_frontend_root "http://${FRONTEND_PUBLIC_HOST}:${OBSERVER_FRONTEND_PORT}" 90 "${FRONTEND_OBSERVER_LOG}"
_wait_frontend_root "http://${FRONTEND_PUBLIC_HOST}:${GENESIS_FRONTEND_PORT}" 90 "${FRONTEND_GENESIS_LOG}"
_wait_http "http://${FRONTEND_PUBLIC_HOST}:${OBSERVER_FRONTEND_PORT}/v1/status" 90 "${FRONTEND_OBSERVER_LOG}"
_wait_http "http://${FRONTEND_PUBLIC_HOST}:${GENESIS_FRONTEND_PORT}/v1/status" 90 "${FRONTEND_GENESIS_LOG}"

cat <<EOF3

==> Local two-frontend rehearsal ready
frontend_bind_host=${FRONTEND_BIND_HOST}
observer_ui=http://${FRONTEND_PUBLIC_HOST}:${OBSERVER_FRONTEND_PORT}/#/verification
observer_account=${OBSERVER_ACCOUNT}
observer_backend=${NODE2_API}
genesis_ui=http://${FRONTEND_PUBLIC_HOST}:${GENESIS_FRONTEND_PORT}/#/reviews
genesis_account=${GENESIS_ACCOUNT}
genesis_backend=${NODE1_API}
reconcile_worker_log=${RECONCILE_LOG}
downstream_sync_log=${DOWNSTREAM_SYNC_LOG}
ipfs_api=${IPFS_API_BASE}
ipfs_gateway=${IPFS_GATEWAY_BASE}
live_room_transport=${LIVE_ROOM_TRANSPORT_MODE}
live_room_base_url=${LIVE_ROOM_BASE_URL}
webrtc_signal_bridge=enabled
live_room_embed=${LIVE_ROOM_EMBED}

Use the observer UI for evidence submission and the genesis UI for review.
No manual recovery-file import or localStorage session injection should be needed.
Press Ctrl+C to stop, or set WEALL_LOCAL_REHEARSAL_KEEP_RUNNING=1 to leave processes running.
EOF3

if _bool_true "${KEEP_RUNNING}"; then
  wait
fi
