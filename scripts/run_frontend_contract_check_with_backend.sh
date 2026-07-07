#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/Weall-Protocol"
WEB_DIR="${ROOT_DIR}/web"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-18080}"
API_BASE="http://${API_HOST}:${API_PORT}"
LOG_FILE="${TMPDIR:-/tmp}/weall_frontend_contract_backend_${API_PORT}.log"
RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/weall_frontend_contract_runtime_${API_PORT}_XXXXXX")"

if [ ! -f "${BACKEND_DIR}/src/weall/api/__main__.py" ]; then
  echo "ERROR: backend API entrypoint not found at ${BACKEND_DIR}" >&2
  exit 1
fi
if [ ! -f "${WEB_DIR}/package.json" ]; then
  echo "ERROR: frontend package.json not found at ${WEB_DIR}" >&2
  exit 1
fi

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [ "${WEALL_KEEP_CONTRACT_RUNTIME:-0}" != "1" ] && [ -n "${RUNTIME_DIR:-}" ]; then
    rm -rf "${RUNTIME_DIR}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "${RUNTIME_DIR}/runtime" "${RUNTIME_DIR}/helper_lanes" "${RUNTIME_DIR}/media_cache" "${RUNTIME_DIR}/reviewer_artifacts" "${RUNTIME_DIR}/failpoints"

cd "${BACKEND_DIR}"
PYTHONPATH="${BACKEND_DIR}/src" \
WEALL_MODE="${WEALL_MODE:-dev}" \
WEALL_API_BOOT_RUNTIME="${WEALL_API_BOOT_RUNTIME:-1}" \
WEALL_API_HOST="${API_HOST}" \
WEALL_API_PORT="${API_PORT}" \
WEALL_NODE_ID="${WEALL_NODE_ID:-frontend-contract-check-node}" \
WEALL_DB_PATH="${WEALL_DB_PATH:-${RUNTIME_DIR}/weall.db}" \
WEALL_AUX_DB_PATH="${WEALL_AUX_DB_PATH:-${RUNTIME_DIR}/weall_aux.db}" \
WEALL_RUNTIME_DIR="${WEALL_RUNTIME_DIR:-${RUNTIME_DIR}/runtime}" \
WEALL_HELPER_LANE_JOURNAL_DIR="${WEALL_HELPER_LANE_JOURNAL_DIR:-${RUNTIME_DIR}/helper_lanes}" \
WEALL_MEDIA_CACHE_DIR="${WEALL_MEDIA_CACHE_DIR:-${RUNTIME_DIR}/media_cache}" \
WEALL_REVIEWER_ARTIFACTS_DIR="${WEALL_REVIEWER_ARTIFACTS_DIR:-${RUNTIME_DIR}/reviewer_artifacts}" \
WEALL_TEST_FAILPOINT_MARKER_DIR="${WEALL_TEST_FAILPOINT_MARKER_DIR:-${RUNTIME_DIR}/failpoints}" \
WEALL_TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-${BACKEND_DIR}/generated/tx_index.json}" \
python3 -m weall.api >"${LOG_FILE}" 2>&1 &
SERVER_PID="$!"

python3 - "${API_BASE}" "${LOG_FILE}" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys
import time
import urllib.request

base = sys.argv[1].rstrip("/")
log_path = pathlib.Path(sys.argv[2])
deadline = time.time() + 20
last_error = ""
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/v1/status", timeout=1.5) as resp:
            body = resp.read().decode("utf-8")
        obj = json.loads(body)
        if isinstance(obj, dict) and obj.get("ok") is True:
            print(f"OK: temporary backend API reachable at {base}")
            raise SystemExit(0)
        last_error = f"status_not_ok:{obj}"
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        last_error = str(exc)
    time.sleep(0.35)

log_tail = ""
try:
    log_tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-40:])
except Exception:
    pass
raise SystemExit(f"backend_api_start_timeout:{base}:{last_error}\n--- backend log tail ---\n{log_tail}")
PY

cd "${WEB_DIR}"
if [ ! -d node_modules ]; then
  npm ci
fi
API_BASE="${API_BASE}" npm run contract-check
