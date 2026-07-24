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

if [[ ! -d "${ROOT}/../web/node_modules" ]]; then
  echo "ERROR: web dependencies are required to prepare the genesis reviewer ML-KEM authority. Run: cd ${ROOT}/../web && npm ci" >&2
  exit 2
fi

# The genesis bootstrap account predates normal ACCOUNT_REGISTER and therefore
# does not automatically receive an evidence-encryption authority. Generate the
# controlled reviewer authority in its operator-only keyfile, then register the
# public ML-KEM key through the normal signed account-security transaction path.
node "${ROOT}/../web/scripts/generate_m2_actor_keys.mjs" "${GENESIS_REVIEWER_KEYFILE}" >/dev/null

_keyfile_field() {
  local field="$1"
  python3 - "${GENESIS_REVIEWER_KEYFILE}" "${field}" <<'PY_KEYFILE_FIELD'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
print(str(data.get(field) or '').strip())
PY_KEYFILE_FIELD
}

_account_evidence_kem_pubkey() {
  /usr/bin/env python3 - "$API" "$GENESIS_REVIEWER_ACCOUNT" <<'PY_EVIDENCE_KEM'
import json, sys, urllib.parse, urllib.request
api, account = sys.argv[1].rstrip('/'), sys.argv[2]
with urllib.request.urlopen(api + '/v1/accounts/' + urllib.parse.quote(account, safe=''), timeout=15) as resp:
    out = json.loads(resp.read().decode('utf-8'))
state = out.get('state') if isinstance(out, dict) else {}
evidence = state.get('evidence_encryption') if isinstance(state, dict) else {}
print(str((evidence or {}).get('public_key') or '').strip())
PY_EVIDENCE_KEM
}

_register_genesis_evidence_kem_if_needed() {
  local expected current payload out_file status after
  expected="$(_keyfile_field evidence_kem_public_key_b64)"
  if [[ -z "${expected}" ]]; then
    echo "ERROR: genesis reviewer ML-KEM public key was not generated" >&2
    exit 2
  fi
  current="$(_account_evidence_kem_pubkey)"
  if [[ "${current}" == "${expected}" ]]; then
    echo "==> Genesis reviewer ML-KEM evidence authority already current"
    return 0
  fi

  payload="$(python3 - "${expected}" <<'PY_EVIDENCE_PAYLOAD'
import json, sys
print(json.dumps({
    "evidence_kem_pubkey": sys.argv[1],
    "evidence_kem_algorithm": "ml-kem-768",
}, sort_keys=True, separators=(",", ":")))
PY_EVIDENCE_PAYLOAD
)"
  out_file="${DEVNET_DIR}/genesis-evidence-kem-register.json"
  python3 scripts/devnet_tx.py --api "${API}" submit-tx \
    --account "${GENESIS_REVIEWER_ACCOUNT}" \
    --keyfile "${GENESIS_REVIEWER_KEYFILE}" \
    --tx-type ACCOUNT_SECURITY_POLICY_SET \
    --payload-json "${payload}" \
    --wait > "${out_file}"
  status="$(python3 - "${out_file}" <<'PY_EVIDENCE_STATUS'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    out = json.load(f)
print(str((out.get('tx_status') or {}).get('status') or '').strip().lower())
PY_EVIDENCE_STATUS
)"
  if [[ "${status}" != "confirmed" ]]; then
    echo "ERROR: genesis reviewer ML-KEM registration transaction did not confirm" >&2
    cat "${out_file}" >&2
    exit 1
  fi
  after="$(_account_evidence_kem_pubkey)"
  if [[ "${after}" != "${expected}" ]]; then
    echo "ERROR: genesis reviewer ML-KEM public key is not canonical after confirmation" >&2
    exit 1
  fi
  echo "==> Genesis reviewer ML-KEM evidence authority registered through normal tx flow"
}

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

_register_genesis_evidence_kem_if_needed

_roles_json >/dev/null || true

echo "==> Deterministic genesis-bound Live reviewer ready: ${GENESIS_REVIEWER_ACCOUNT} tier=${tier} keyfile=${GENESIS_REVIEWER_KEYFILE}"
echo "==> No open bootstrap or runtime reviewer self-grant was used"
