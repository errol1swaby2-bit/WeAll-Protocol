#!/usr/bin/env bash
set -euo pipefail

# Boot a second devnet node from empty local state.
# The joining node derives the same genesis profile/anchor as node 1 using the
# same explicit genesis bootstrap profile, but it keeps its own node_id and does
# not receive validator signing authority unless the operator explicitly sets it.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"
mkdir -p "${DEVNET_DIR}/node2" "${DEVNET_DIR}/accounts"

OPERATOR_ACCOUNT="${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-@devnet-genesis}"
OPERATOR_KEYFILE="${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}"

cd "${REPO_ROOT}"
activate_repo_venv() {
  if [[ "${WEALL_DEVNET_AUTO_VENV:-1}" =~ ^(0|false|FALSE|no|NO|off|OFF)$ ]]; then
    return 0
  fi
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

activate_repo_venv
python3 scripts/devnet_tx.py ensure-keyfile --account "${OPERATOR_ACCOUNT}" --keyfile "${OPERATOR_KEYFILE}" >/dev/null

_read_key_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
print(str(data.get(field) or '').strip())
PY
}

OPERATOR_PUBKEY="$(_read_key_field "${OPERATOR_KEYFILE}" public_key_hex)"

export WEALL_MODE="${WEALL_MODE:-devnet}"
export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-controlled_devnet}"
export WEALL_CHAIN_ID="${WEALL_CHAIN_ID:-weall-controlled-devnet}"
export WEALL_CHAIN_MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${REPO_ROOT}/configs/chains/weall-controlled-devnet.json}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-0}"
export WEALL_NODE_ID="${WEALL_NODE_ID:-@devnet-joiner}"
export WEALL_DB_PATH="${WEALL_DB_PATH:-${DEVNET_DIR}/node2/weall.db}"
export WEALL_TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-${REPO_ROOT}/generated/tx_index.json}"
export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-0}"
export WEALL_PRODUCE_EMPTY_BLOCKS="${WEALL_PRODUCE_EMPTY_BLOCKS:-1}"
export WEALL_BLOCK_LOOP_LOCK_PATH="${WEALL_BLOCK_LOOP_LOCK_PATH:-${DEVNET_DIR}/node2/block_loop.lock}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-0}"
export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-0}"
export WEALL_ENABLE_OPERATOR_POH="${WEALL_ENABLE_OPERATOR_POH:-0}"
export WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE="${WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE:-0}"
export WEALL_ALLOW_DIRECT_SESSION_MUTATION="${WEALL_ALLOW_DIRECT_SESSION_MUTATION:-0}"
export WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"
export WEALL_GENESIS_MODE="${WEALL_GENESIS_MODE:-0}"
export WEALL_GENESIS_BOOTSTRAP_ENABLE="${WEALL_GENESIS_BOOTSTRAP_ENABLE:-1}"
export WEALL_GENESIS_BOOTSTRAP_ACCOUNT="${OPERATOR_ACCOUNT}"
export WEALL_GENESIS_BOOTSTRAP_PUBKEY="${OPERATOR_PUBKEY}"
export WEALL_GENESIS_BOOTSTRAP_REPUTATION="${WEALL_GENESIS_BOOTSTRAP_REPUTATION:-1.0}"
export WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE="${WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE:-1}"
export WEALL_POH_BOOTSTRAP_MAX_HEIGHT="${WEALL_POH_BOOTSTRAP_MAX_HEIGHT:-500}"
export WEALL_POH_TIER2_N_JURORS="${WEALL_POH_TIER2_N_JURORS:-1}"
export WEALL_POH_TIER2_MIN_TOTAL_REVIEWS="${WEALL_POH_TIER2_MIN_TOTAL_REVIEWS:-1}"
export WEALL_POH_TIER2_PASS_THRESHOLD="${WEALL_POH_TIER2_PASS_THRESHOLD:-1}"
export WEALL_POH_TIER2_FAIL_MAX="${WEALL_POH_TIER2_FAIL_MAX:-0}"
export WEALL_POH_TIER2_MIN_REP_MILLI="${WEALL_POH_TIER2_MIN_REP_MILLI:-0}"
export WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}"
export WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}"
export WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}"
export WEALL_POH_ASYNC_REJECTION_THRESHOLD="${WEALL_POH_ASYNC_REJECTION_THRESHOLD:-1}"
export WEALL_POH_ASYNC_MIN_REP_MILLI="${WEALL_POH_ASYNC_MIN_REP_MILLI:-0}"
export WEALL_POH_LIVE_PASS_THRESHOLD_NUM="${WEALL_POH_LIVE_PASS_THRESHOLD_NUM:-1}"
export WEALL_POH_LIVE_PASS_THRESHOLD_DEN="${WEALL_POH_LIVE_PASS_THRESHOLD_DEN:-1}"
export WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED="${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED:-1}"
export WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT="${WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT:-500}"
unset WEALL_VALIDATOR_ACCOUNT || true
unset WEALL_NODE_PUBKEY || true
unset WEALL_NODE_PRIVKEY || true
export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE="${WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE:-1}"
export GUNICORN_BIND="${GUNICORN_BIND:-127.0.0.1:8002}"

JOIN_ANCHOR_PATH="${WEALL_JOIN_ANCHOR_PATH:-}"
REQUIRE_JOIN_ANCHOR="${WEALL_DEVNET_REQUIRE_JOIN_ANCHOR:-0}"
_bool_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

if command -v curl >/dev/null 2>&1; then
  echo "==> Expected peer identity from ${NODE1_API}/v1/chain/genesis"
  curl -fsS "${NODE1_API}/v1/chain/genesis" || true
  echo
fi

if [[ -n "${JOIN_ANCHOR_PATH}" && -f "${JOIN_ANCHOR_PATH}" ]]; then
  echo "==> Verifying expected peer against pinned join anchor: ${JOIN_ANCHOR_PATH}"
  bash ./scripts/devnet_verify_join_anchor.sh "${NODE1_API}" "${JOIN_ANCHOR_PATH}"
elif _bool_true "${REQUIRE_JOIN_ANCHOR}"; then
  echo "ERROR: WEALL_DEVNET_REQUIRE_JOIN_ANCHOR=1 but WEALL_JOIN_ANCHOR_PATH is missing or unreadable: ${JOIN_ANCHOR_PATH:-<unset>}" >&2
  exit 2
fi

cat <<EOF
==> Booting joining devnet node
mode=${WEALL_MODE}
runtime_profile=${WEALL_RUNTIME_PROFILE}
chain_id=${WEALL_CHAIN_ID}
node_id=${WEALL_NODE_ID}
bootstrap_operator=${WEALL_GENESIS_BOOTSTRAP_ACCOUNT}
bootstrap_juror=${WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE}
poh_bootstrap_open=${WEALL_POH_BOOTSTRAP_OPEN}
poh_bootstrap_max_height=${WEALL_POH_BOOTSTRAP_MAX_HEIGHT}
tier2_jurors=${WEALL_POH_TIER2_N_JURORS}
tier2_min_reviews=${WEALL_POH_TIER2_MIN_TOTAL_REVIEWS}
async_jurors=${WEALL_POH_ASYNC_N_JURORS}
async_min_reviews=${WEALL_POH_ASYNC_MIN_REVIEWS}
live_partial_panels=${WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED}
live_partial_until_height=${WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT}
operator_keyfile=${OPERATOR_KEYFILE}
db=${WEALL_DB_PATH}
block_loop_lock=${WEALL_BLOCK_LOOP_LOCK_PATH}
chain_manifest=${WEALL_CHAIN_MANIFEST_PATH}
produce_empty_blocks=${WEALL_PRODUCE_EMPTY_BLOCKS}
bind=${GUNICORN_BIND}
identity=http://${GUNICORN_BIND}/v1/chain/identity
EOF

exec bash ./scripts/run_node.sh
