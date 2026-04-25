#!/usr/bin/env bash
set -euo pipefail

# Submit a bounded Tier-1 email oracle attestation through the normal tx path.
# This script signs a relay token with the devnet relay key, signs an operator
# receipt with the genesis operator key, signs the user tx with the subject
# account key, and submits POH_EMAIL_RECEIPT_SUBMIT. It never calls demo seed
# routes and never mutates local state directly.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
OPERATOR_KEYFILE="${WEALL_GENESIS_OPERATOR_KEYFILE:-${REPO_ROOT}/.weall-devnet/genesis-operator.json}"
RELAY_KEYFILE="${WEALL_EMAIL_RELAY_KEYFILE:-${REPO_ROOT}/.weall-devnet/email-relay.json}"
EMAIL="${WEALL_EMAIL:-}"
REQUEST_FILE="${WEALL_EMAIL_REQUEST_FILE:-${REPO_ROOT}/.weall-devnet/email-request.json}"
RECEIPT_OUT="${WEALL_EMAIL_RECEIPT_FILE:-${REPO_ROOT}/.weall-devnet/email-receipt.json}"
REQUEST_ID="${WEALL_EMAIL_REQUEST_ID:-}"
ACCOUNT="${WEALL_ACCOUNT:-}"

if [[ -z "${EMAIL}" ]]; then
  echo "ERROR: set WEALL_EMAIL to the address being verified." >&2
  exit 2
fi

cd "${REPO_ROOT}"
if [[ -z "${REQUEST_ID}" && -f "${REQUEST_FILE}" ]]; then
  REQUEST_ID="$(python3 - "${REQUEST_FILE}" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
print(str(data.get('request_id') or '').strip())
PY
)"
fi

ARGS=(--api "${API}" email-tier1 --keyfile "${KEYFILE}" --email "${EMAIL}" --operator-keyfile "${OPERATOR_KEYFILE}" --relay-keyfile "${RELAY_KEYFILE}" --receipt-out "${RECEIPT_OUT}")
if [[ -n "${ACCOUNT}" ]]; then
  ARGS+=(--account "${ACCOUNT}")
fi
if [[ -n "${REQUEST_ID}" ]]; then
  ARGS+=(--request-id "${REQUEST_ID}")
fi
python3 scripts/devnet_tx.py "${ARGS[@]}" "$@"
