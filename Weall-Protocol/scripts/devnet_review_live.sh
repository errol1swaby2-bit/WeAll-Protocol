#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet Live reviewer helper.
# Uses normal public tx skeleton routes and /v1/tx/submit only.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
ACCOUNT="${WEALL_LIVE_JUROR_ACCOUNT:-${WEALL_ACCOUNT:-}}"
KEYFILE="${WEALL_LIVE_JUROR_KEYFILE:-${WEALL_KEYFILE:-$ROOT/.weall-devnet/accounts/live-juror.json}}"
CASE_ID="${WEALL_LIVE_CASE_ID:-}"
VERDICT="${WEALL_LIVE_VERDICT:-pass}"

args=(--api "$API" live-review --keyfile "$KEYFILE" --verdict "$VERDICT")
if [[ -n "$ACCOUNT" ]]; then
  args+=(--account "$ACCOUNT")
fi
if [[ -n "$CASE_ID" ]]; then
  args+=(--case-id "$CASE_ID")
fi
if [[ "${WEALL_LIVE_ACCEPT:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-accept)
fi
if [[ "${WEALL_LIVE_ATTENDANCE:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-attendance)
fi
if [[ "${WEALL_LIVE_SUBMIT_VERDICT:-1}" =~ ^(0|false|False|no|off)$ ]]; then
  args+=(--no-verdict)
fi

python "$ROOT/scripts/devnet_tx.py" "${args[@]}"
