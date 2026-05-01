#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
SESSION_ID="${1:-${WEALL_LIVE_SESSION_ID:-}}"
CASE_ID="${WEALL_LIVE_CASE_ID:-}"

if [[ -z "$SESSION_ID" && -n "$CASE_ID" ]]; then
  SESSION_ID="session:$CASE_ID"
fi
if [[ -z "$SESSION_ID" ]]; then
  echo "missing session id: pass one argument or set WEALL_LIVE_SESSION_ID / WEALL_LIVE_CASE_ID" >&2
  exit 2
fi

python "$ROOT/scripts/devnet_tx.py" --api "$API" live-session "$SESSION_ID"
python "$ROOT/scripts/devnet_tx.py" --api "$API" live-participants "$SESSION_ID"
