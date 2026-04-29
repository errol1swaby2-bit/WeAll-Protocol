#!/usr/bin/env bash
set -euo pipefail

# Prepare controlled-devnet Tier-3 reviewer accounts for live PoH testing.
# Each reviewer is created through ACCOUNT_REGISTER and elevated through the
# bounded POH_BOOTSTRAP_TIER3_GRANT open-bootstrap tx. This is not a demo seed:
# every mutation goes through /v1/tx/submit and normal block execution.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${ROOT}/.weall-devnet}"
COUNT="${WEALL_TIER3_JUROR_COUNT:-10}"
PREFIX="${WEALL_TIER3_JUROR_PREFIX:-@devnet-tier3-juror-}"
KEY_PREFIX="${WEALL_TIER3_JUROR_KEY_PREFIX:-tier3-juror-}"
mkdir -p "${DEVNET_DIR}/accounts"

_account_tier() {
  local account="$1"
  /usr/bin/env python3 - "$API" "$account" <<'PY'
import json, sys, urllib.parse, urllib.error, urllib.request
api, account = sys.argv[1].rstrip('/'), sys.argv[2]
url = api + '/v1/accounts/' + urllib.parse.quote(account, safe='')
try:
    with urllib.request.urlopen(url, timeout=15) as resp:
        out = json.loads(resp.read().decode('utf-8'))
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        print('missing')
        raise SystemExit(0)
    raise
state = out.get('state') if isinstance(out, dict) else {}
if not isinstance(state, dict) or not state:
    print('missing')
    raise SystemExit(0)

# GET /v1/accounts/{account} intentionally returns a harmless Tier-0
# placeholder for unknown accounts so read clients can render a stable shape.
# Reviewer preparation needs a stricter existence check: a real account must
# have canonical key material recorded in state.  Treat placeholder-only shapes
# as missing so the script registers the reviewer before submitting the
# self-signed POH_BOOTSTRAP_TIER3_GRANT transaction.
has_key_material = False
if str(state.get('pubkey') or '').strip():
    has_key_material = True
pubkeys = state.get('pubkeys')
if isinstance(pubkeys, list) and any(str(x or '').strip() for x in pubkeys):
    has_key_material = True
active_keys = state.get('active_keys')
if isinstance(active_keys, list) and any(str(x or '').strip() for x in active_keys):
    has_key_material = True
keys = state.get('keys')
if isinstance(keys, dict) and keys:
    has_key_material = True
if not has_key_material:
    print('missing')
    raise SystemExit(0)

try:
    print(int(state.get('poh_tier') or 0))
except Exception:
    print('0')
PY
}

for i in $(seq 1 "$COUNT"); do
  suffix="$(printf '%02d' "$i")"
  account="${PREFIX}${suffix}"
  keyfile="${DEVNET_DIR}/accounts/${KEY_PREFIX}${suffix}.json"
  tier="$(_account_tier "$account")"

  if [[ "$tier" == "missing" ]]; then
    echo "==> Creating Tier-3 reviewer account ${account}"
    WEALL_API="$API" WEALL_ACCOUNT="$account" WEALL_KEYFILE="$keyfile" \
      bash "$ROOT/scripts/devnet_create_account.sh" --fresh >/dev/null
    tier="$(_account_tier "$account")"
  fi

  if [[ "$tier" =~ ^[0-9]+$ && "$tier" -ge 3 ]]; then
    echo "==> Tier-3 reviewer already ready: ${account} tier=${tier} keyfile=${keyfile}"
    continue
  fi

  echo "==> Bootstrap-granting controlled-devnet Tier-3 reviewer ${account}"
  WEALL_API="$API" WEALL_ACCOUNT="$account" WEALL_KEYFILE="$keyfile" \
    bash "$ROOT/scripts/devnet_bootstrap_tier3.sh" >/dev/null
  tier="$(_account_tier "$account")"
  if [[ ! "$tier" =~ ^[0-9]+$ || "$tier" -lt 3 ]]; then
    echo "ERROR: Tier-3 reviewer did not reach Tier 3: ${account} tier=${tier}" >&2
    exit 1
  fi
  echo "==> Tier-3 reviewer ready: ${account} tier=${tier} keyfile=${keyfile}"
done
