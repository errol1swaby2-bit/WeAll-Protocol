#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet helper to submit a bounded open-bootstrap Tier-3 grant.
# This uses normal signed public transaction submission. It never calls demo
# seed routes and only works while the chain's consensus-visible bootstrap
# policy is open and height-bounded.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
ACCOUNT="${WEALL_ACCOUNT:-}"
KEYFILE="${WEALL_KEYFILE:-$ROOT/.weall-devnet/accounts/devnet-account.json}"

args=(--api "$API" bootstrap-tier3 --keyfile "$KEYFILE")
if [[ -n "$ACCOUNT" ]]; then
  args+=(--account "$ACCOUNT")
fi

python3 "$ROOT/scripts/devnet_tx.py" "${args[@]}" "$@"
