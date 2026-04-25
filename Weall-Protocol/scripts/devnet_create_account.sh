#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"

cd "${REPO_ROOT}"
ARGS=(--api "${API}" create-account --keyfile "${KEYFILE}")
if [[ -n "${ACCOUNT}" ]]; then
  ARGS+=(--account "${ACCOUNT}")
fi
python3 scripts/devnet_tx.py "${ARGS[@]}" "$@"
