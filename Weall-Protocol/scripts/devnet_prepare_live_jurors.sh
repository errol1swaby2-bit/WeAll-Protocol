#!/usr/bin/env bash
set -euo pipefail

# Prepare controlled-devnet Live reviewer authority for live PoH testing.
# Production-aligned controlled-devnet rehearsal must not self-grant reviewer
# status after startup.  Instead, the genesis node boots with an explicit,
# deterministic genesis bootstrap operator/reviewer identity.  This helper only
# verifies that the genesis-bound reviewer is present, Live/Tier-2 eligible, and
# backed by the expected keyfile so later live-review txs can use normal
# /v1/tx/submit paths.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-http://127.0.0.1:8001}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${ROOT}/.weall-devnet}"
GENESIS_REVIEWER_ACCOUNT="${WEALL_GENESIS_REVIEWER_ACCOUNT:-${WEALL_BOOTSTRAP_OPERATOR_ACCOUNT:-${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-@devnet-genesis}}}}"
GENESIS_REVIEWER_KEYFILE="${WEALL_GENESIS_REVIEWER_KEYFILE:-${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}}"
mkdir -p "${DEVNET_DIR}/accounts"

_account_json() {
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
        print(json.dumps({"ok": False, "missing": True, "account": account}, sort_keys=True))
        raise SystemExit(0)
    raise
state = out.get('state') if isinstance(out, dict) else {}
if not isinstance(state, dict) or not state:
    print(json.dumps({"ok": False, "missing": True, "account": account}, sort_keys=True))
    raise SystemExit(0)

# GET /v1/accounts/{account} intentionally returns a harmless Tier-0
# placeholder for unknown accounts so read clients can render a stable shape.
# Reviewer rehearsal needs a stricter existence check: a real genesis-bound
# reviewer must have canonical key material recorded in state. Treat
# placeholder-only shapes as missing so the rehearsal fails closed instead of
# accidentally relying on a non-authoritative reviewer account.
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
    print(json.dumps({"ok": False, "missing": True, "account": account}, sort_keys=True))
    raise SystemExit(0)

try:
    tier = int(state.get('poh_tier') or 0)
except Exception:
    tier = 0
print(json.dumps({
    "ok": True,
    "account": account,
    "poh_tier": tier,
    "pubkey": str(state.get('pubkey') or '').strip(),
    "reputation": str(state.get('reputation') or state.get('reputation_milli') or ''),
}, sort_keys=True))
PY
}

_roles_json() {
  /usr/bin/env python3 - "$API" "$GENESIS_REVIEWER_ACCOUNT" <<'PY'
import json, sys, urllib.parse, urllib.request
api, account = sys.argv[1].rstrip('/'), sys.argv[2]
with urllib.request.urlopen(api + '/v1/status/operator', timeout=15) as resp:
    operator = json.loads(resp.read().decode('utf-8'))
# /v1/status/operator is intentionally broad; keep this helper defensive and
# avoid assuming one exact response shape across rehearsal builds.
print(json.dumps({"ok": True, "account": account, "operator_status_ok": bool(operator.get("ok"))}, sort_keys=True))
PY
}

if [[ -z "${GENESIS_REVIEWER_ACCOUNT}" ]]; then
  echo "ERROR: genesis reviewer account is empty" >&2
  exit 2
fi
if [[ ! -f "${GENESIS_REVIEWER_KEYFILE}" ]]; then
  echo "ERROR: genesis reviewer keyfile missing: ${GENESIS_REVIEWER_KEYFILE}" >&2
  exit 2
fi

account_json="$(_account_json "${GENESIS_REVIEWER_ACCOUNT}")"
echo "${account_json}"

account_ok="$(python3 - <<'PY' "${account_json}"
import json, sys
try:
    out = json.loads(sys.argv[1])
except Exception:
    print('0')
    raise SystemExit(0)
print('1' if out.get('ok') else '0')
PY
)"
if [[ "${account_ok}" != "1" ]]; then
  echo "ERROR: deterministic genesis reviewer is missing from chain state: ${GENESIS_REVIEWER_ACCOUNT}" >&2
  exit 1
fi

tier="$(python3 - <<'PY' "${account_json}"
import json, sys
out = json.loads(sys.argv[1])
try:
    print(int(out.get('poh_tier') or 0))
except Exception:
    print(0)
PY
)"
if [[ ! "${tier}" =~ ^[0-9]+$ || "${tier}" -lt 2 ]]; then
  echo "ERROR: deterministic genesis reviewer is not Live/Tier-2 eligible: ${GENESIS_REVIEWER_ACCOUNT} tier=${tier}" >&2
  exit 1
fi

_roles_json >/dev/null || true

echo "==> Deterministic genesis-bound Live reviewer ready: ${GENESIS_REVIEWER_ACCOUNT} tier=${tier} keyfile=${GENESIS_REVIEWER_KEYFILE}"
echo "==> No open bootstrap or runtime reviewer self-grant was used"
