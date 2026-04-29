#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet Tier-3 reviewer helper.
# Uses normal public tx skeleton routes and /v1/tx/submit only.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
ACCOUNT="${WEALL_TIER3_JUROR_ACCOUNT:-${WEALL_ACCOUNT:-}}"
KEYFILE="${WEALL_TIER3_JUROR_KEYFILE:-${WEALL_KEYFILE:-$ROOT/.weall-devnet/accounts/tier3-juror.json}}"
CASE_ID="${WEALL_TIER3_CASE_ID:-}"
VERDICT="${WEALL_TIER3_VERDICT:-pass}"

args=(--api "$API" tier3-review --keyfile "$KEYFILE" --verdict "$VERDICT")
if [[ -n "$ACCOUNT" ]]; then
  args+=(--account "$ACCOUNT")
fi
if [[ -n "$CASE_ID" ]]; then
  args+=(--case-id "$CASE_ID")
fi
if [[ "${WEALL_TIER3_ACCEPT:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-accept)
fi
if [[ "${WEALL_TIER3_ATTENDANCE:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-attendance)
fi
if [[ "${WEALL_TIER3_SUBMIT_VERDICT:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-verdict)
fi

python "$ROOT/scripts/devnet_tx.py" "${args[@]}"
