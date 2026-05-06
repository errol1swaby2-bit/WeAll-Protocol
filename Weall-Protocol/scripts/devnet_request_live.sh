#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"


_resolve_live_account() {
  python3 - "${KEYFILE}" "${WEALL_ACCOUNT:-}" <<'PY_RESOLVE_LIVE_ACCOUNT'
import json, sys
path, explicit = sys.argv[1], sys.argv[2]
if explicit.strip():
    print(explicit.strip())
    raise SystemExit(0)
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
print(str(data.get('account') or '').strip())
PY_RESOLVE_LIVE_ACCOUNT
}

_default_live_commitment() {
  local kind="$1"
  local account="$2"
  python3 - "${kind}" "${account}" "${KEYFILE}" "${WEALL_POH_LIVE_COMMITMENT_SALT:-controlled-devnet}" <<'PY_DEFAULT_LIVE_COMMITMENT'
import hashlib, sys
kind, account, keyfile, salt = sys.argv[1:]
seed = f"weall-controlled-devnet-live|v1|{kind}|{account}|{keyfile}|{salt}"
print(hashlib.sha256(seed.encode('utf-8')).hexdigest())
PY_DEFAULT_LIVE_COMMITMENT
}

LIVE_ACCOUNT="$(_resolve_live_account)"
if [[ -z "${LIVE_ACCOUNT}" ]]; then
  echo "ERROR: could not resolve account for live verification request" >&2
  exit 2
fi

: "${WEALL_POH_LIVE_SESSION_COMMITMENT:=$(_default_live_commitment session "${LIVE_ACCOUNT}")}"
: "${WEALL_POH_LIVE_ROOM_COMMITMENT:=$(_default_live_commitment room "${LIVE_ACCOUNT}")}"
: "${WEALL_POH_LIVE_PROMPT_COMMITMENT:=$(_default_live_commitment prompt "${LIVE_ACCOUNT}")}"
: "${WEALL_POH_LIVE_DEVICE_PAIRING_COMMITMENT:=$(_default_live_commitment device-pairing "${LIVE_ACCOUNT}")}"

args=(
  --api "${API}"
  live-request
  --keyfile "${KEYFILE}"
  --wait
  --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}"
  --poll "${WEALL_TX_WAIT_POLL:-0.5}"
)

if [[ -n "${WEALL_ACCOUNT:-}" ]]; then
  args+=(--account "${WEALL_ACCOUNT}")
fi
if [[ -n "${WEALL_POH_LIVE_SESSION_COMMITMENT:-}" ]]; then
  args+=(--session-commitment "${WEALL_POH_LIVE_SESSION_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_LIVE_ROOM_COMMITMENT:-}" ]]; then
  args+=(--room-commitment "${WEALL_POH_LIVE_ROOM_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_LIVE_PROMPT_COMMITMENT:-}" ]]; then
  args+=(--prompt-commitment "${WEALL_POH_LIVE_PROMPT_COMMITMENT}")
fi
if [[ -n "${WEALL_POH_LIVE_DEVICE_PAIRING_COMMITMENT:-}" ]]; then
  args+=(--device-pairing-commitment "${WEALL_POH_LIVE_DEVICE_PAIRING_COMMITMENT}")
fi

python3 scripts/devnet_tx.py "${args[@]}"
