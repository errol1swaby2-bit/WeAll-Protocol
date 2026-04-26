#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"

args=(
  --api "${API}"
  tier3-request
  --keyfile "${KEYFILE}"
  --wait
  --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}"
  --poll "${WEALL_TX_WAIT_POLL:-0.5}"
)

if [[ -n "${WEALL_ACCOUNT:-}" ]]; then
  args+=(--account "${WEALL_ACCOUNT}")
fi
if [[ -n "${WEALL_POH_TIER3_SESSION_COMMITMENT:-}" ]]; then
  args+=(--session-commitment "${WEALL_POH_TIER3_SESSION_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_TIER3_ROOM_COMMITMENT:-}" ]]; then
  args+=(--room-commitment "${WEALL_POH_TIER3_ROOM_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_TIER3_PROMPT_COMMITMENT:-}" ]]; then
  args+=(--prompt-commitment "${WEALL_POH_TIER3_PROMPT_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_TIER3_DEVICE_PAIRING_COMMITMENT:-}" ]]; then
  args+=(--device-pairing-commitment "${WEALL_POH_TIER3_DEVICE_PAIRING_COMMITMENT}")
fi

python3 scripts/devnet_tx.py "${args[@]}"
