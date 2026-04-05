#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${ROOT_DIR}/web"
PROTO_DIR="${ROOT_DIR}/Weall-Protocol"
VENV_DIR="${PROTO_DIR}/.venv_e2e"
PY_BIN="${VENV_DIR}/bin/python"
PORT="${PORT:-18090}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${PORT}}"
CHAIN_ID="${WEALL_CHAIN_ID:-weall-dev}"
DB_PATH="${WEALL_DB_PATH:-${ROOT_DIR}/.e2e_weall.db}"
TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-${PROTO_DIR}/generated/tx_index.json}"
REQ_DEV_LOCK="${PROTO_DIR}/requirements-dev.lock"
IPFS_COMPOSE_FILE="${PROTO_DIR}/docker-compose.ipfs.yml"
IPFS_API_URL="${WEALL_IPFS_API_URL:-http://127.0.0.1:5001}"
IPFS_API_BASE="${IPFS_API_URL%/}"
IPFS_STARTED_BY_SCRIPT=0

say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
have() { command -v "$1" >/dev/null 2>&1; }
need python3
need node
need npm

if [[ ! -f "${TX_INDEX_PATH}" ]]; then
  echo "Missing tx index: ${TX_INDEX_PATH}" >&2
  exit 2
fi

if [[ ! -f "${REQ_DEV_LOCK}" ]]; then
  echo "Missing dev lockfile: ${REQ_DEV_LOCK}" >&2
  exit 2
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

"${PY_BIN}" -m pip install -U pip wheel >/dev/null
"${PY_BIN}" -m pip install -r "${REQ_DEV_LOCK}" >/dev/null
"${PY_BIN}" -m pip install -e "${PROTO_DIR}" >/dev/null

pushd "${WEB_DIR}" >/dev/null
npm ci >/dev/null
popd >/dev/null

export WEALL_MODE="${WEALL_MODE:-dev}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_CHAIN_ID="${CHAIN_ID}"
export WEALL_NODE_ID="${WEALL_NODE_ID:-@e2e-node}"
export WEALL_DB_PATH="${DB_PATH}"
export WEALL_TX_INDEX_PATH="${TX_INDEX_PATH}"
export WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-1}"
export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
export WEALL_PRODUCER_INTERVAL_MS="${WEALL_PRODUCER_INTERVAL_MS:-300}"
export WEALL_PRODUCER_MAX_TXS="${WEALL_PRODUCER_MAX_TXS:-1000}"
export WEALL_PRODUCER_ALLOW_EMPTY="${WEALL_PRODUCER_ALLOW_EMPTY:-1}"
export PYTHONPATH="${PROTO_DIR}/src:${PYTHONPATH:-}"

API_LOG="${ROOT_DIR}/.golden_e2e_api.log"
PRODUCER_LOG="${ROOT_DIR}/.golden_e2e_producer.log"
API_PID=""
PRODUCER_PID=""

cleanup() {
  set +e
  [[ -n "${PRODUCER_PID}" ]] && kill "${PRODUCER_PID}" >/dev/null 2>&1
  [[ -n "${API_PID}" ]] && kill "${API_PID}" >/dev/null 2>&1
  if [[ "${IPFS_STARTED_BY_SCRIPT}" == "1" ]] && have docker; then
    docker compose -f "${IPFS_COMPOSE_FILE}" down >/dev/null 2>&1 || true
  fi
  wait >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ipfs_ready() {
  "${PY_BIN}" - <<PY
import sys, urllib.request
url = "${IPFS_API_BASE}/api/v0/version"
try:
    req = urllib.request.Request(url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=3) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

ensure_ipfs() {
  if ipfs_ready; then
    return 0
  fi

  if [[ ! -f "${IPFS_COMPOSE_FILE}" ]]; then
    echo "IPFS is not reachable at ${IPFS_API_URL} and compose file is missing: ${IPFS_COMPOSE_FILE}" >&2
    exit 2
  fi

  if ! have docker; then
    echo "IPFS is not reachable at ${IPFS_API_URL} and docker is not installed or not on PATH." >&2
    echo "Start Kubo/IPFS manually or install Docker and retry." >&2
    exit 2
  fi

  say "[0/5] Starting IPFS"
  docker compose -f "${IPFS_COMPOSE_FILE}" up -d >/dev/null
  IPFS_STARTED_BY_SCRIPT=1

  for _ in $(seq 1 120); do
    if ipfs_ready; then
      return 0
    fi
    sleep 0.5
  done

  echo "IPFS did not become ready in time at ${IPFS_API_URL}" >&2
  exit 2
}

ensure_ipfs

say "[1/5] Starting API"
(
  cd "${PROTO_DIR}"
  exec "${PY_BIN}" -m gunicorn weall.api.app:app \
    -k uvicorn.workers.UvicornWorker \
    --bind "127.0.0.1:${PORT}" \
    --workers 1 \
    --timeout 60 \
    --graceful-timeout 30 \
    --keep-alive 5
) >"${API_LOG}" 2>&1 &
API_PID="$!"

say "[2/5] Starting producer"
(
  cd "${PROTO_DIR}"
  exec "${PY_BIN}" -m weall.services.block_producer
) >"${PRODUCER_LOG}" 2>&1 &
PRODUCER_PID="$!"

say "[3/5] Waiting for readiness"
"${PY_BIN}" - <<PY
import json, time, urllib.request
base = "${BASE_URL}"
for _ in range(120):
    try:
        with urllib.request.urlopen(base + "/v1/readyz", timeout=5) as r:
            data = json.loads(r.read().decode())
            if data.get("ok") is True:
                print("ready")
                break
    except Exception:
        pass
    time.sleep(0.5)
else:
    raise SystemExit("API did not become ready in time")
PY

say "[4/5] Frontend contract-check"
pushd "${WEB_DIR}" >/dev/null
API_BASE="${BASE_URL}" npm run contract-check
popd >/dev/null

say "[5/5] Full stack golden path"
(
  cd "${PROTO_DIR}"
  WEALL_API="${BASE_URL}" WEALL_CHAIN_ID="${CHAIN_ID}" "${PY_BIN}" scripts/golden_path_full_stack.py
)

say "✅ golden path e2e gate complete"
