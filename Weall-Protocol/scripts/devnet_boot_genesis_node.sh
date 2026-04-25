#!/usr/bin/env bash
set -euo pipefail

# Boot a clean genesis/devnet node using explicit non-production settings.
# This script runs in the foreground so operators can see logs directly.
# It creates a genesis operator key and a devnet email relay key if missing.
# Those keys only establish controlled-devnet authority; they do not call demo
# seed routes and they do not bypass tx execution.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
mkdir -p "${DEVNET_DIR}/node1" "${DEVNET_DIR}/accounts"

OPERATOR_ACCOUNT="${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-@devnet-genesis}}"
OPERATOR_KEYFILE="${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}"
RELAY_ACCOUNT="${WEALL_EMAIL_RELAY_ACCOUNT_ID:-@devnet-email-relay}"
RELAY_KEYFILE="${WEALL_EMAIL_RELAY_KEYFILE:-${DEVNET_DIR}/email-relay.json}"

cd "${REPO_ROOT}"
python3 scripts/devnet_tx.py ensure-keyfile --account "${OPERATOR_ACCOUNT}" --keyfile "${OPERATOR_KEYFILE}" >/dev/null
python3 scripts/devnet_tx.py ensure-keyfile --account "${RELAY_ACCOUNT}" --keyfile "${RELAY_KEYFILE}" >/dev/null

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
OPERATOR_PRIVKEY="$(_read_key_field "${OPERATOR_KEYFILE}" private_key_hex)"
RELAY_PUBKEY="$(_read_key_field "${RELAY_KEYFILE}" public_key_hex)"

export WEALL_MODE="${WEALL_MODE:-dev}"
export WEALL_CHAIN_ID="${WEALL_CHAIN_ID:-weall-controlled-devnet}"
export WEALL_NODE_ID="${WEALL_NODE_ID:-${OPERATOR_ACCOUNT}}"
export WEALL_DB_PATH="${WEALL_DB_PATH:-${DEVNET_DIR}/node1/weall.db}"
export WEALL_TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-${REPO_ROOT}/generated/tx_index.json}"
export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-1}"
export WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-1000}"
export WEALL_MAX_TXS_PER_BLOCK="${WEALL_MAX_TXS_PER_BLOCK:-100}"
export WEALL_PRODUCE_EMPTY_BLOCKS="${WEALL_PRODUCE_EMPTY_BLOCKS:-0}"
export WEALL_BLOCK_LOOP_LOCK_PATH="${WEALL_BLOCK_LOOP_LOCK_PATH:-${DEVNET_DIR}/node1/block_loop.lock}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_GENESIS_MODE="${WEALL_GENESIS_MODE:-0}"
export WEALL_GENESIS_BOOTSTRAP_ENABLE="${WEALL_GENESIS_BOOTSTRAP_ENABLE:-1}"
export WEALL_GENESIS_BOOTSTRAP_ACCOUNT="${OPERATOR_ACCOUNT}"
export WEALL_GENESIS_BOOTSTRAP_PUBKEY="${OPERATOR_PUBKEY}"
export WEALL_GENESIS_BOOTSTRAP_REPUTATION="${WEALL_GENESIS_BOOTSTRAP_REPUTATION:-1.0}"
export WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE="${WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE:-1}"
export WEALL_POH_TIER2_N_JURORS="${WEALL_POH_TIER2_N_JURORS:-1}"
export WEALL_POH_TIER2_MIN_TOTAL_REVIEWS="${WEALL_POH_TIER2_MIN_TOTAL_REVIEWS:-1}"
export WEALL_POH_TIER2_PASS_THRESHOLD="${WEALL_POH_TIER2_PASS_THRESHOLD:-1}"
export WEALL_POH_TIER2_FAIL_MAX="${WEALL_POH_TIER2_FAIL_MAX:-0}"
export WEALL_POH_TIER2_MIN_REP_MILLI="${WEALL_POH_TIER2_MIN_REP_MILLI:-0}"
export WEALL_VALIDATOR_ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-${OPERATOR_ACCOUNT}}"
export WEALL_NODE_PUBKEY="${WEALL_NODE_PUBKEY:-${OPERATOR_PUBKEY}}"
export WEALL_NODE_PRIVKEY="${WEALL_NODE_PRIVKEY:-${OPERATOR_PRIVKEY}}"
export WEALL_ORACLE_OPERATOR_ACCOUNT="${WEALL_ORACLE_OPERATOR_ACCOUNT:-${OPERATOR_ACCOUNT}}"
export WEALL_EMAIL_RELAY_ACCOUNT_ID="${RELAY_ACCOUNT}"
export WEALL_EMAIL_RELAY_PUBKEY="${RELAY_PUBKEY}"
export WEALL_POH_EMAIL_SECRET="${WEALL_POH_EMAIL_SECRET:-devnet-local-only-secret}"
export GUNICORN_BIND="${GUNICORN_BIND:-127.0.0.1:8001}"

cat <<EOF
==> Booting genesis devnet node
mode=${WEALL_MODE}
chain_id=${WEALL_CHAIN_ID}
node_id=${WEALL_NODE_ID}
bootstrap_operator=${WEALL_GENESIS_BOOTSTRAP_ACCOUNT}
bootstrap_juror=${WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE}
tier2_jurors=${WEALL_POH_TIER2_N_JURORS}
tier2_min_reviews=${WEALL_POH_TIER2_MIN_TOTAL_REVIEWS}
operator_keyfile=${OPERATOR_KEYFILE}
email_relay_account=${WEALL_EMAIL_RELAY_ACCOUNT_ID}
email_relay_keyfile=${RELAY_KEYFILE}
db=${WEALL_DB_PATH}
block_loop_lock=${WEALL_BLOCK_LOOP_LOCK_PATH}
bind=${GUNICORN_BIND}
identity=http://${GUNICORN_BIND}/v1/chain/identity
EOF

exec bash ./scripts/run_node.sh
