#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/Weall-Protocol"
WEB_DIR="${ROOT_DIR}/web"
API_HOST="${WEALL_M2_CONTRACT_API_HOST:-127.0.0.1}"
API_PORT="${WEALL_M2_CONTRACT_API_PORT:-18082}"
API_BASE="http://${API_HOST}:${API_PORT}"
ARTIFACT_DIR="${WEALL_M2_ARTIFACT_DIR:-${ROOT_DIR}/artifacts/m2-closure/frontend/contract-check}"
RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/weall_m2_contract_XXXXXX")"
BACKEND_LOG="${ARTIFACT_DIR}/backend.log"
CONTRACT_LOG="${ARTIFACT_DIR}/contract-check.txt"

mkdir -p \
  "${ARTIFACT_DIR}" \
  "${RUNTIME_DIR}/runtime" \
  "${RUNTIME_DIR}/helper_lanes" \
  "${RUNTIME_DIR}/media_cache" \
  "${RUNTIME_DIR}/reviewer_artifacts" \
  "${RUNTIME_DIR}/failpoints"

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill "${BACKEND_PID}" 2>/dev/null || true
    wait "${BACKEND_PID}" 2>/dev/null || true
  fi
  if [[ "${WEALL_KEEP_M2_CONTRACT_RUNTIME:-0}" != "1" ]]; then
    rm -rf "${RUNTIME_DIR}" >/dev/null 2>&1 || true
  else
    echo "Kept M2 contract-check runtime: ${RUNTIME_DIR}"
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -d "${WEB_DIR}/node_modules" ]]; then
  (cd "${WEB_DIR}" && npm ci)
fi

cd "${BACKEND_DIR}"
PYTHONPATH="${BACKEND_DIR}/src" \
WEALL_MODE="${WEALL_M2_CONTRACT_MODE:-dev}" \
WEALL_API_BOOT_RUNTIME=1 \
WEALL_BLOCK_LOOP_AUTOSTART=0 \
WEALL_API_HOST="${API_HOST}" \
WEALL_API_PORT="${API_PORT}" \
WEALL_NODE_ID="m2-contract-check-node" \
WEALL_DB_PATH="${RUNTIME_DIR}/weall.db" \
WEALL_AUX_DB_PATH="${RUNTIME_DIR}/weall_aux.db" \
WEALL_RUNTIME_DIR="${RUNTIME_DIR}/runtime" \
WEALL_HELPER_LANE_JOURNAL_DIR="${RUNTIME_DIR}/helper_lanes" \
WEALL_MEDIA_CACHE_DIR="${RUNTIME_DIR}/media_cache" \
WEALL_REVIEWER_ARTIFACTS_DIR="${RUNTIME_DIR}/reviewer_artifacts" \
WEALL_TEST_FAILPOINT_MARKER_DIR="${RUNTIME_DIR}/failpoints" \
WEALL_TX_INDEX_PATH="${BACKEND_DIR}/generated/tx_index.json" \
python3 -m weall.api >"${BACKEND_LOG}" 2>&1 &
BACKEND_PID="$!"

python3 - "${API_BASE}" "${BACKEND_LOG}" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys
import time
import urllib.request

base = sys.argv[1].rstrip("/")
log_path = pathlib.Path(sys.argv[2])
deadline = time.time() + 30
last_error = ""
while time.time() < deadline:
    try:
        with urllib.request.urlopen(base + "/v1/readyz", timeout=1.5) as response:
            body = json.loads(response.read().decode("utf-8"))
        if isinstance(body, dict) and body.get("ok") is True:
            print(f"OK: real M2 contract backend reachable at {base}")
            raise SystemExit(0)
        last_error = f"readyz_not_ok:{body}"
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        last_error = str(exc)
    time.sleep(0.35)
try:
    tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-80:])
except Exception:
    tail = ""
raise SystemExit(f"backend_api_start_timeout:{last_error}\n--- backend log ---\n{tail}")
PY

cd "${WEB_DIR}"
set -o pipefail
API_BASE="${API_BASE}" npm run contract-check 2>&1 | tee "${CONTRACT_LOG}"

echo "OK: frontend/backend real-stack contract check passed"
