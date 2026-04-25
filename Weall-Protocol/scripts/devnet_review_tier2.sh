#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
cd "${REPO_ROOT}"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
CASE_ID="${WEALL_TIER2_CASE_ID:-}"
JUROR_ACCOUNT="${WEALL_TIER2_JUROR_ACCOUNT:-${WEALL_ORACLE_OPERATOR_ACCOUNT:-${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-@devnet-genesis}}}"
JUROR_KEYFILE="${WEALL_TIER2_JUROR_KEYFILE:-${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}}"
VERDICT="${WEALL_TIER2_VERDICT:-pass}"

if [[ -z "${CASE_ID}" ]]; then
  echo "ERROR: WEALL_TIER2_CASE_ID is required" >&2
  exit 2
fi

python3 scripts/devnet_tx.py --api "${API}" tier2-review \
  --account "${JUROR_ACCOUNT}" \
  --keyfile "${JUROR_KEYFILE}" \
  --case-id "${CASE_ID}" \
  --verdict "${VERDICT}" \
  --accept \
  --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}" \
  --poll "${WEALL_TX_WAIT_POLL:-0.5}"
