#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"

python3 scripts/devnet_tx.py --api "${API}" tier2-request \
  --keyfile "${KEYFILE}" \
  --wait \
  --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}" \
  --poll "${WEALL_TX_WAIT_POLL:-0.5}"
