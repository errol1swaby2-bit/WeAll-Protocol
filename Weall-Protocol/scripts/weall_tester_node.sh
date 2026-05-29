#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
WEB_ROOT="${REPO_ROOT}/web"
RUNTIME_DIR="${WEALL_TESTER_RUNTIME_DIR:-${HOME}/.weall/tester-node}"
BUNDLE_ARG=""
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
MODE="observer"
ALLOW_PRIVATE="0"
START_FRONTEND="1"
RUN_NODE="1"
API_HOST="${WEALL_API_HOST:-127.0.0.1}"
API_PORT="${WEALL_API_PORT:-8000}"
FRONTEND_PORT="${WEALL_FRONTEND_PORT:-5173}"

usage() {
  cat <<'USAGE'
Usage: scripts/weall_tester_node.sh --bundle <path-or-url> [options]

One-command external tester boot path. Installs a public observer bundle,
starts a safe observer/onboarding node, and optionally starts the frontend.

Options:
  --bundle <path-or-url>          Public node/operator onboarding bundle JSON.
  --genesis-api-base <url>        Remote Genesis API base advertised by the bundle.
  --manifest <path>               Chain manifest; default configs/chains/weall-genesis.json.
  --mode observer                 Normal tester path; the only default mode.
  --mode private-rehearsal        Allows private Genesis API only with --allow-private-genesis-api.
  --allow-private-genesis-api     Explicitly allow private/LAN Genesis API for rehearsal.
  --runtime-dir <dir>             Runtime directory outside the repo.
  --api-host <host>               Local node bind host; default 127.0.0.1.
  --api-port <port>               Local node API port; default 8000.
  --frontend-port <port>          Frontend dev-server port; default 5173.
  --skip-frontend                 Do not start the frontend helper.
  --no-run                        Verify/install only; do not start the node.
  -h, --help                      Show this help.

Safety boundary:
  Observer mode refuses node private keys, validator signing, BFT, helper
  authority, block production, and external authority/oracle secrets.
USAGE
}

fail() { echo "ERROR: $*" >&2; exit 1; }
truthy() { case "${1:-0}" in 1|true|TRUE|yes|YES|on|ON) return 0 ;; *) return 1 ;; esac; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE_ARG="${2:-}"; shift 2 ;;
    --genesis-api-base) GENESIS_API_BASE="${2:-}"; shift 2 ;;
    --manifest) MANIFEST_PATH="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --allow-private-genesis-api) ALLOW_PRIVATE="1"; shift ;;
    --runtime-dir) RUNTIME_DIR="${2:-}"; shift 2 ;;
    --api-host) API_HOST="${2:-}"; shift 2 ;;
    --api-port) API_PORT="${2:-}"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="${2:-}"; shift 2 ;;
    --skip-frontend) START_FRONTEND="0"; shift ;;
    --no-run) RUN_NODE="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${BUNDLE_ARG}" ]] || fail "--bundle is required"
[[ -f "${MANIFEST_PATH}" ]] || fail "manifest not found: ${MANIFEST_PATH}"
case "${MODE}" in observer|private-rehearsal) ;; *) fail "unsupported tester mode: ${MODE}" ;; esac

# Keep tester onboarding free of validator/authority secrets.
# shellcheck disable=SC1091
. "${ROOT_DIR}/scripts/lib/observer_secret_boundary.sh"
weall_check_observer_secret_boundary || exit $?

mkdir -p "${RUNTIME_DIR}"
chmod 700 "${RUNTIME_DIR}"

BUNDLE_PATH="${BUNDLE_ARG}"
case "${BUNDLE_ARG}" in
  http://*|https://*)
    command -v curl >/dev/null 2>&1 || fail "curl is required to download bundle URLs"
    BUNDLE_PATH="${RUNTIME_DIR}/weall-external-observer-bundle.json"
    curl -fsSL "${BUNDLE_ARG}" -o "${BUNDLE_PATH}"
    ;;
esac
[[ -f "${BUNDLE_PATH}" ]] || fail "bundle not found: ${BUNDLE_PATH}"

if [[ -n "${GENESIS_API_BASE}" ]]; then
  export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE}"
fi
if [[ "${ALLOW_PRIVATE}" == "1" ]]; then
  export WEALL_ALLOW_PRIVATE_GENESIS_API=1
fi

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

# Verify the public bundle before writing any local env file.
python3 "${ROOT_DIR}/scripts/verify_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --json >/tmp/weall-tester-bundle-check.json
rm -f /tmp/weall-tester-bundle-check.json

ENV_FILE="${RUNTIME_DIR}/node-operator.env"
python3 "${ROOT_DIR}/scripts/install_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --out "${ENV_FILE}" \
  --force >/tmp/weall-tester-install.out
rm -f /tmp/weall-tester-install.out

# shellcheck disable=SC1090
source "${ENV_FILE}"

# Batch 471: tester node boot intentionally clears bundle authority profile.
# Private rehearsal bundles may carry authority.profile="rehearsal" so the bundle
# verifier can allow private HTTP/non-public URLs, but a normal observer node
# must still boot under production/unset authority profile. Authority is granted
# only by committed chain state, never by the onboarding bundle.
unset WEALL_AUTHORITY_PROFILE


export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="${BUNDLE_PATH}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_REQUIRE_CHAIN_MANIFEST=1
export WEALL_MODE=prod
export WEALL_NODE_LIFECYCLE_STATE=observer_onboarding
export WEALL_OBSERVER_MODE=1
export WEALL_VALIDATOR_SIGNING_ENABLED=0
export WEALL_BFT_ENABLED=0
export WEALL_HELPER_MODE_ENABLED=0
export WEALL_BLOCK_LOOP_AUTOSTART=0
export WEALL_OBSERVER_EDGE_MODE=1
export WEALL_RUNTIME_DIR="${RUNTIME_DIR}"
export WEALL_DB_PATH="${RUNTIME_DIR}/observer.db"
export WEALL_TX_OUTBOX_PATH="${RUNTIME_DIR}/observer_tx_outbox.json"
export WEALL_API_HOST="${API_HOST}"
export WEALL_API_PORT="${API_PORT}"
if [[ -n "${GENESIS_API_BASE}" ]]; then
  export WEALL_TX_UPSTREAM_URLS="${GENESIS_API_BASE}"
fi

WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API="${WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API:-0}" \
  bash "${ROOT_DIR}/scripts/external_observer_onboarding_smoke.sh" "${BUNDLE_PATH}" >/tmp/weall-tester-smoke.out
rm -f /tmp/weall-tester-smoke.out
bash "${ROOT_DIR}/scripts/external_observer_authority_lock_gate.sh" >/tmp/weall-tester-authority-lock.out
rm -f /tmp/weall-tester-authority-lock.out

if [[ "${START_FRONTEND}" == "1" && -d "${WEB_ROOT}" && -f "${WEB_ROOT}/package.json" && -x "$(command -v npm || true)" ]]; then
  mkdir -p "${RUNTIME_DIR}/logs"
  if [[ ! -d "${WEB_ROOT}/node_modules" ]]; then
    (cd "${WEB_ROOT}" && npm ci) >"${RUNTIME_DIR}/logs/frontend-npm-ci.log" 2>&1 || fail "frontend npm ci failed; see ${RUNTIME_DIR}/logs/frontend-npm-ci.log"
  fi
  if ! pgrep -f "vite.*--port ${FRONTEND_PORT}" >/dev/null 2>&1; then
    (cd "${WEB_ROOT}" && nohup npm run dev -- --host 127.0.0.1 --port "${FRONTEND_PORT}" >"${RUNTIME_DIR}/logs/frontend.log" 2>&1 & echo $! >"${RUNTIME_DIR}/frontend.pid")
  fi
fi

cat <<MSG
OK: WeAll tester observer node environment is installed.
- mode: observer onboarding
- bundle: ${BUNDLE_PATH}
- env file: ${ENV_FILE}
- runtime dir: ${RUNTIME_DIR}
- local API: http://${API_HOST}:${API_PORT}
- frontend: http://127.0.0.1:${FRONTEND_PORT} $([[ "${START_FRONTEND}" == "1" ]] || printf '(skipped)')
- validator signing: disabled
- BFT/helper/block production: disabled

Next frontend flow:
1. Open the frontend.
2. Create or restore an account.
3. Save and verify the recovery file.
4. Continue to verification/onboarding.
MSG

if [[ "${RUN_NODE}" != "1" ]]; then
  echo "[weall-tester-node] --no-run set; not starting node."
  exit 0
fi

exec bash "${ROOT_DIR}/scripts/boot_onboarding_node.sh"
