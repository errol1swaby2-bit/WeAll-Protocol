#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
PEER_ENDPOINT="${WEALL_OBSERVER_PEER_ENDPOINT:-relay://external-observer-live-gate}"
TARGET_PEER_ID="${WEALL_GENESIS_PEER_ID:-genesis}"
KEEP_WORK_DIR="${WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR:-1}"
TIMEOUT="${WEALL_TX_WAIT_TIMEOUT:-60}"
POLL="${WEALL_TX_WAIT_POLL:-1}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json> with WEALL_GENESIS_API_BASE set"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"
[ -n "${GENESIS_API_BASE}" ] || fail "WEALL_GENESIS_API_BASE or WEALL_API_BASE is required"
GENESIS_API_BASE="${GENESIS_API_BASE%/}"

case "${GENESIS_API_BASE}" in
  http://127.0.0.1*|http://localhost*|https://127.0.0.1*|https://localhost*)
    fail "external observer live gate requires a remote non-local genesis API base, not ${GENESIS_API_BASE}"
    ;;
esac

# External observers must not carry genesis authority, validator, or external identity-provider secrets.
[ -z "${WEALL_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority signer private key must not be present on observer node"
[ -z "${WEALL_AUTHORITY_PRIVKEY:-}" ] || fail "authority private key must not be present on observer node"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "legacy oracle/identity signer private key must not be present on observer node"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "legacy oracle/identity private key must not be present on observer node"
[ -z "${WEALL_CLOUDFLARE_API_TOKEN:-}" ] || fail "Cloudflare token must not be present for observer onboarding"
SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD"
[ -z "${!SMTP_SECRET_VAR:-}" ] || fail "external message-transport credential must not be present for observer onboarding"

export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE}"
export WEALL_API_BASE="${GENESIS_API_BASE}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="${BUNDLE_PATH}"
export WEALL_MODE="prod"
export WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"
export WEALL_SERVICE_ROLES=""
export WEALL_OBSERVER_MODE="1"
export WEALL_VALIDATOR_SIGNING_ENABLED="0"
export WEALL_BFT_ENABLED="0"
export WEALL_HELPER_MODE_ENABLED="0"
export WEALL_BLOCK_LOOP_AUTOSTART="0"
export WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API="1"

bash "${ROOT_DIR}/scripts/external_observer_onboarding_smoke.sh" "${BUNDLE_PATH}"

WORK_DIR="${WEALL_EXTERNAL_OBSERVER_WORK_DIR:-}"
if [ -z "${WORK_DIR}" ]; then
  WORK_DIR="$(mktemp -d /tmp/weall-external-observer-live-gate.XXXXXX)"
fi
mkdir -p "${WORK_DIR}"
chmod 700 "${WORK_DIR}" || true

ACCOUNT_SUFFIX="$(python3 - <<'PY_ACCOUNT_SUFFIX'
import secrets
print(secrets.token_hex(6))
PY_ACCOUNT_SUFFIX
)"
ACCOUNT_ID="${WEALL_EXTERNAL_OBSERVER_ACCOUNT:-@external-observer-${ACCOUNT_SUFFIX}}"
ACCOUNT_KEYFILE="${WORK_DIR}/observer-account.json"
NODE_KEYFILE="${WORK_DIR}/observer-node-key.json"
RESULTS_JSONL="${WORK_DIR}/live-gate-results.jsonl"
: > "${RESULTS_JSONL}"

python3 - "${NODE_KEYFILE}" <<'PY_NODE_KEY'
from __future__ import annotations
import json
import sys
from pathlib import Path
from nacl.signing import SigningKey
path = Path(sys.argv[1])
sk = SigningKey.generate()
out = {
    "key_type": "ed25519",
    "purpose": "external_observer_node_identity",
    "private_key_hex": sk.encode().hex(),
    "public_key_hex": sk.verify_key.encode().hex(),
}
path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
print(out["public_key_hex"])
PY_NODE_KEY
NODE_PUBKEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key_hex"])' "${NODE_KEYFILE}")"
DEVICE_ID="node:${ACCOUNT_ID}:${NODE_PUBKEY:0:16}"
ASYNC_CASE_ID="pohasync:${ACCOUNT_ID}:external-observer-live-gate"
ASYNC_EVIDENCE_ID="async-evidence:${ACCOUNT_SUFFIX}"
ASYNC_COMMITMENT="sha256:$(printf '%s' "weall-external-observer-live-gate|${ACCOUNT_ID}|${NODE_PUBKEY}|${ASYNC_CASE_ID}" | sha256sum | awk '{print $1}')"

python3 - "${WORK_DIR}" "${ACCOUNT_ID}" "${NODE_PUBKEY}" "${DEVICE_ID}" "${PEER_ENDPOINT}" "${TARGET_PEER_ID}" "${GENESIS_API_BASE}" "${ASYNC_CASE_ID}" "${ASYNC_EVIDENCE_ID}" "${ASYNC_COMMITMENT}" <<'PY_PAYLOADS'
from __future__ import annotations
import json
import sys
from pathlib import Path
(
    work_dir,
    account_id,
    node_pubkey,
    device_id,
    peer_endpoint,
    target_peer_id,
    genesis_api_base,
    async_case_id,
    async_evidence_id,
    async_commitment,
) = sys.argv[1:11]
root = Path(work_dir)
payloads = {
    "payload-device.json": {
        "device_id": device_id,
        "device_type": "node",
        "label": "External observer node",
        "pubkey": node_pubkey,
    },
    "payload-peer-advertise.json": {"peer_id": account_id, "endpoint": peer_endpoint},
    "payload-peer-request-connect.json": {"peer_id": target_peer_id, "endpoint": genesis_api_base},
    "payload-poh-async-request.json": {
        "account_id": account_id,
        "case_id": async_case_id,
        "challenge_id": "external-observer-live-gate",
        "response_commitment": async_commitment,
    },
    "payload-poh-async-evidence-declare.json": {
        "case_id": async_case_id,
        "evidence_id": async_evidence_id,
        "evidence_commitment": async_commitment,
        "kind": "observer-onboarding-commitment",
    },
    "payload-poh-async-evidence-bind.json": {
        "case_id": async_case_id,
        "evidence_id": async_evidence_id,
        "target_id": async_case_id,
    },
}
for name, obj in payloads.items():
    (root / name).write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")
PY_PAYLOADS

run_json() {
  local label="$1"
  shift
  echo "[live-gate] ${label}"
  local out
  if ! out="$($@)"; then
    echo "${out}" >&2
    fail "${label} failed"
  fi
  printf '%s\n' "${out}" | python3 - "${label}" "${RESULTS_JSONL}" <<'PY_CHECK_RESULT'
from __future__ import annotations
import json
import sys
label, path = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
try:
    obj = json.loads(raw)
except Exception as exc:
    raise SystemExit(f"{label}: non-json output: {exc}: {raw[:500]}")
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"label": label, "result": obj}, sort_keys=True) + "\n")
if obj.get("ok") is not True:
    raise SystemExit(f"{label}: ok flag false: {json.dumps(obj, sort_keys=True)}")
status = obj.get("tx_status") if isinstance(obj.get("tx_status"), dict) else None
if status is not None and str(status.get("status") or "").lower() != "confirmed":
    raise SystemExit(f"{label}: tx not confirmed: {json.dumps(status, sort_keys=True)}")
PY_CHECK_RESULT
}

run_json "ACCOUNT_REGISTER" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" create-account \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --fresh --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "ACCOUNT_DEVICE_REGISTER node key binding" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type ACCOUNT_DEVICE_REGISTER \
    --payload-json "$(cat "${WORK_DIR}/payload-device.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "PEER_ADVERTISE" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type PEER_ADVERTISE \
    --payload-json "$(cat "${WORK_DIR}/payload-peer-advertise.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "PEER_REQUEST_CONNECT" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type PEER_REQUEST_CONNECT \
    --payload-json "$(cat "${WORK_DIR}/payload-peer-request-connect.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "POH_ASYNC_REQUEST_OPEN" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type POH_ASYNC_REQUEST_OPEN \
    --payload-json "$(cat "${WORK_DIR}/payload-poh-async-request.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "POH_ASYNC_EVIDENCE_DECLARE" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type POH_ASYNC_EVIDENCE_DECLARE \
    --payload-json "$(cat "${WORK_DIR}/payload-poh-async-evidence-declare.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

run_json "POH_ASYNC_EVIDENCE_BIND" \
  python3 "${ROOT_DIR}/scripts/devnet_tx.py" --api "${GENESIS_API_BASE}" submit-tx \
    --account "${ACCOUNT_ID}" --keyfile "${ACCOUNT_KEYFILE}" --tx-type POH_ASYNC_EVIDENCE_BIND \
    --payload-json "$(cat "${WORK_DIR}/payload-poh-async-evidence-bind.json")" \
    --wait --timeout "${TIMEOUT}" --poll "${POLL}"

python3 - "${GENESIS_API_BASE}" "${ACCOUNT_ID}" "${ASYNC_CASE_ID}" "${RESULTS_JSONL}" <<'PY_FINAL_CHECK'
from __future__ import annotations
import json
import sys
import urllib.parse
import urllib.request
api, account, case_id, results_path = sys.argv[1:5]

def fetch(path: str) -> dict:
    with urllib.request.urlopen(api.rstrip('/') + path, timeout=20) as resp:
        if resp.status >= 400:
            raise SystemExit(f"endpoint_failed:{path}:{resp.status}")
        obj = json.loads(resp.read().decode('utf-8'))
    if not isinstance(obj, dict):
        raise SystemExit(f"endpoint_non_object:{path}")
    return obj
acct = fetch('/v1/accounts/' + urllib.parse.quote(account, safe=''))
state = acct.get('state') if isinstance(acct.get('state'), dict) else acct
if not isinstance(state, dict):
    raise SystemExit('account_state_missing')
if state.get('validator') is True or state.get('bft_enabled') is True:
    raise SystemExit('observer_account_unexpected_validator_authority')
case = fetch('/v1/poh/async/case/' + urllib.parse.quote(case_id, safe=''))
case_obj = case.get('case') if isinstance(case.get('case'), dict) else {}
if str(case_obj.get('case_id') or '') != case_id:
    raise SystemExit('async_case_not_visible_after_commit')
labels = []
with open(results_path, 'r', encoding='utf-8') as fh:
    for line in fh:
        rec = json.loads(line)
        labels.append(str(rec.get('label') or ''))
expected = [
    'ACCOUNT_REGISTER',
    'ACCOUNT_DEVICE_REGISTER node key binding',
    'PEER_ADVERTISE',
    'PEER_REQUEST_CONNECT',
    'POH_ASYNC_REQUEST_OPEN',
    'POH_ASYNC_EVIDENCE_DECLARE',
    'POH_ASYNC_EVIDENCE_BIND',
]
missing = [x for x in expected if x not in labels]
if missing:
    raise SystemExit(f'missing_live_gate_results:{missing}')
print(json.dumps({'ok': True, 'account': account, 'case_id': case_id, 'confirmed_steps': labels}, indent=2, sort_keys=True))
PY_FINAL_CHECK

cat <<MSG
OK: trusted external observer live gate passed
- remote non-local genesis API was required: ${GENESIS_API_BASE}
- fresh observer account key was generated locally: ${ACCOUNT_KEYFILE}
- fresh observer node key was generated locally and registered: ${NODE_KEYFILE}
- submitted and confirmed ACCOUNT_REGISTER, ACCOUNT_DEVICE_REGISTER, PEER_ADVERTISE, PEER_REQUEST_CONNECT, POH_ASYNC_REQUEST_OPEN, POH_ASYNC_EVIDENCE_DECLARE, POH_ASYNC_EVIDENCE_BIND
- observer env kept validator signing/BFT/helper/block-loop disabled
- no genesis authority secret or external identity-provider credential was required
- results: ${RESULTS_JSONL}
MSG

if [ "${KEEP_WORK_DIR}" != "1" ]; then
  rm -rf "${WORK_DIR}"
else
  echo "[live-gate] work dir retained: ${WORK_DIR}"
fi
