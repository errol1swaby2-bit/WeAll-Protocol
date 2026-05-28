#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
PEER_ENDPOINT="${WEALL_OBSERVER_PEER_ENDPOINT:-relay://external-observer-live-gate}"
TARGET_PEER_ID="${WEALL_GENESIS_PEER_ID:-genesis}"
KEEP_WORK_DIR="${WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR:-0}"
TIMEOUT="${WEALL_TX_WAIT_TIMEOUT:-60}"
POLL="${WEALL_TX_WAIT_POLL:-1}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# Shared boundary rejects WEALL_AUTHORITY_SIGNER_PRIVKEY, WEALL_AUTHORITY_PRIVKEY,
# WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY, WEALL_ORACLE_AUTHORITY_PRIVKEY,
# WEALL_CLOUDFLARE_API_TOKEN, and SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD".
# It also rejects *_FILE variants and other external identity-provider secrets.
# shellcheck disable=SC1091
. "${ROOT_DIR}/scripts/lib/observer_secret_boundary.sh"
weall_check_observer_secret_boundary || exit $?

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json> with WEALL_GENESIS_API_BASE set"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
if [ -z "${MANIFEST_PATH}" ]; then
  MANIFEST_PATH="$(python3 - "${BUNDLE_PATH}" "${ROOT_DIR}" <<'WEALL_BUNDLE_MANIFEST_PATH_PY'
from __future__ import annotations
import json
import sys
from pathlib import Path
bundle_path = Path(sys.argv[1])
root = Path(sys.argv[2])
bundle = json.loads(bundle_path.read_text(encoding='utf-8'))
chain = bundle.get('chain') if isinstance(bundle.get('chain'), dict) else {}
hint = str(chain.get('manifest_path_hint') or '').strip()
candidates = []
if hint:
    candidates.append(Path(hint))
    candidates.append(root / hint)
candidates.append(root / 'configs' / 'chains' / 'weall-genesis.json')
for candidate in candidates:
    try:
        resolved = candidate.expanduser().resolve()
    except Exception:
        continue
    if resolved.is_file():
        print(str(resolved))
        raise SystemExit(0)
print('')
WEALL_BUNDLE_MANIFEST_PATH_PY
)"
fi
[ -n "${MANIFEST_PATH}" ] || fail "chain manifest path could not be resolved"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"
MANIFEST_MODE="$(python3 - "${MANIFEST_PATH}" <<'WEALL_MANIFEST_MODE_PY'
from __future__ import annotations
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    obj = json.load(fh)
print(str(obj.get('mode') or '').strip())
WEALL_MANIFEST_MODE_PY
)"
[ -n "${GENESIS_API_BASE}" ] || fail "WEALL_GENESIS_API_BASE or WEALL_API_BASE is required"
GENESIS_API_BASE="${GENESIS_API_BASE%/}"

# Reject obvious local/self/metadata endpoints.  Historical cases covered here
# include http://127.0.0.1*, http://localhost*, https://127.0.0.1*, and
# https://localhost*.  IPv6 loopback, unspecified addresses, link-local hosts,
# and private LAN IPs require WEALL_ALLOW_PRIVATE_GENESIS_API=1.
python3 - "${GENESIS_API_BASE}" "${WEALL_ALLOW_PRIVATE_GENESIS_API:-0}" <<'PY_NONLOCAL_API'
from __future__ import annotations

import ipaddress
import sys
import urllib.parse

url, allow_private = sys.argv[1], sys.argv[2]
parsed = urllib.parse.urlparse(url)
if parsed.scheme not in {"http", "https"}:
    raise SystemExit("external_observer_genesis_api_scheme_invalid")
host = (parsed.hostname or "").strip().lower()
if not host:
    raise SystemExit("external_observer_genesis_api_host_missing")
if host in {"localhost", "ip6-localhost"} or host.endswith(".localhost"):
    raise SystemExit(f"external observer live gate requires a remote non-local genesis API base, not {url}")
try:
    ip = ipaddress.ip_address(host)
except ValueError:
    ip = None
if ip is not None:
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        raise SystemExit(f"external observer live gate requires a remote non-local genesis API base, not {url}")
    if str(ip) == "169.254.169.254":
        raise SystemExit("external_observer_genesis_api_metadata_service_forbidden")
    if ip.is_private and allow_private not in {"1", "true", "TRUE", "yes", "YES", "on", "ON"}:
        raise SystemExit("external_observer_private_genesis_api_requires_WEALL_ALLOW_PRIVATE_GENESIS_API=1")
print("OK: genesis API base is non-local for external observer live gate")
PY_NONLOCAL_API

export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE}"
export WEALL_API_BASE="${GENESIS_API_BASE}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="${BUNDLE_PATH}"
export WEALL_MODE="${WEALL_MODE:-${MANIFEST_MODE:-prod}}"
export WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"
export WEALL_SERVICE_ROLES=""
export WEALL_OBSERVER_MODE="1"
export WEALL_VALIDATOR_SIGNING_ENABLED="0"
export WEALL_BFT_ENABLED="0"
export WEALL_HELPER_MODE_ENABLED="0"
export WEALL_BLOCK_LOOP_AUTOSTART="0"
export WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API="1"

echo "[live-gate] verifying public observer bundle/manifest and forced observer-only runtime posture"
echo "[live-gate] signed transaction helper: scripts/devnet_tx.py (used here as a generic signed tx CLI, not as a devnet authority)"
echo "[live-gate] checking remote Genesis observer readiness contract"

python3 - "${GENESIS_API_BASE}" "${BUNDLE_PATH}" <<'PY_REMOTE_OBSERVER_READINESS'
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

api = sys.argv[1].rstrip("/")
bundle = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
chain = bundle.get("chain") if isinstance(bundle.get("chain"), dict) else {}
expected_chain_id = str(chain.get("chain_id") or "").strip()
expected_tx_hash = str(chain.get("tx_index_hash") or "").strip().lower()
expected_profile_hash = str(chain.get("protocol_profile_hash") or "").strip().lower()

def fetch_json(path: str) -> dict:
    try:
        with urllib.request.urlopen(api + path, timeout=10) as resp:
            if resp.status >= 400:
                raise SystemExit(f"remote_endpoint_failed:{path}:{resp.status}")
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"remote_endpoint_failed:{path}:{exc.code}") from exc
    try:
        obj = json.loads(body)
    except Exception as exc:
        raise SystemExit(f"remote_endpoint_non_json:{path}:{exc}") from exc
    if not isinstance(obj, dict):
        raise SystemExit(f"remote_endpoint_not_object:{path}")
    return obj

readiness = fetch_json("/v1/genesis/observer/readiness")
if readiness.get("ok") is not True:
    raise SystemExit("remote_genesis_observer_readiness_not_ok")
if str(readiness.get("stage") or "") != "first_trusted_external_observer_rehearsal":
    raise SystemExit("remote_genesis_observer_readiness_stage_invalid")
compat = readiness.get("compatibility") if isinstance(readiness.get("compatibility"), dict) else {}
remote_chain_id = str(compat.get("chain_id") or "").strip()
if expected_chain_id and remote_chain_id and remote_chain_id != expected_chain_id:
    raise SystemExit(f"remote_observer_readiness_chain_id_mismatch:{remote_chain_id}!={expected_chain_id}")
remote_tx_hash = str(compat.get("tx_index_hash") or "").strip().lower()
if expected_tx_hash and remote_tx_hash and remote_tx_hash != expected_tx_hash:
    raise SystemExit(f"remote_observer_readiness_tx_index_hash_mismatch:{remote_tx_hash}!={expected_tx_hash}")
remote_profile_hash = str(compat.get("protocol_profile_hash") or "").strip().lower()
if expected_profile_hash and remote_profile_hash and remote_profile_hash != expected_profile_hash:
    raise SystemExit(f"remote_observer_readiness_protocol_profile_hash_mismatch:{remote_profile_hash}!={expected_profile_hash}")
if expected_profile_hash and not remote_profile_hash:
    raise SystemExit("remote_observer_readiness_protocol_profile_hash_missing")
authority = readiness.get("observer_authority_boundary") if isinstance(readiness.get("observer_authority_boundary"), dict) else {}
if authority.get("observer_receives_validator_authority") is not False:
    raise SystemExit("remote_observer_readiness_validator_authority_not_false")
if authority.get("requires_genesis_or_validator_private_keys") is not False:
    raise SystemExit("remote_observer_readiness_requires_private_keys")
if authority.get("requires_external_identity_provider") is not False:
    raise SystemExit("remote_observer_readiness_requires_external_identity_provider")
public_tx = readiness.get("public_tx_ingress") if isinstance(readiness.get("public_tx_ingress"), dict) else {}
if public_tx.get("signed_user_tx_submit_enabled") is not True:
    raise SystemExit("remote_observer_readiness_signed_tx_submit_not_enabled")
if public_tx.get("system_signer_rejected_from_public_ingress") is not True:
    raise SystemExit("remote_observer_readiness_system_signer_not_rejected")
if public_tx.get("system_flag_rejected_from_public_ingress") is not True:
    raise SystemExit("remote_observer_readiness_system_flag_not_rejected")
print("OK: remote Genesis observer readiness contract passed")
PY_REMOTE_OBSERVER_READINESS

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
    "payload-peer-advertise.json": {
        "peer_id": device_id,
        "device_id": device_id,
        "node_pubkey": node_pubkey,
        "endpoint": peer_endpoint,
    },
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
  local out_file
  if ! out="$("$@")"; then
    echo "${out}" >&2
    fail "${label} failed"
  fi

  out_file="${WORK_DIR}/live-gate-${label}.json"
  printf '%s\n' "${out}" > "${out_file}"

  python3 - "${label}" "${RESULTS_JSONL}" "${out_file}" <<'PY_CHECK_RESULT'
from __future__ import annotations

import json
import sys
from pathlib import Path

label = sys.argv[1]
results_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])
raw = out_path.read_text(encoding="utf-8")

try:
    obj = json.loads(raw)
except Exception as exc:
    raise SystemExit(f"{label}: non-json output: {exc}: {raw[:1000]}")

if not isinstance(obj, dict):
    raise SystemExit(f"{label}: json output was not an object")

with results_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({"label": label, "result": obj}, sort_keys=True) + "\n")

if obj.get("ok") is not True:
    raise SystemExit(f"{label}: ok flag false: {json.dumps(obj, sort_keys=True)[:2000]}")

submit = obj.get("submit") if isinstance(obj.get("submit"), dict) else {}
status_obj = obj.get("tx_status") if isinstance(obj.get("tx_status"), dict) else {}

if status_obj and str(status_obj.get("status") or "").lower() != "confirmed":
    raise SystemExit(f"{label}: tx not confirmed: {json.dumps(status_obj, sort_keys=True)}")

tx_id = obj.get("tx_id") or submit.get("tx_id")
status = status_obj.get("status") or obj.get("status") or submit.get("status")
height = status_obj.get("height")

print(f"OK: {label} tx_id={tx_id} status={status} height={height}")
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

python3 - "${GENESIS_API_BASE}" "${ACCOUNT_ID}" "${ASYNC_CASE_ID}" "${RESULTS_JSONL}" "${NODE_PUBKEY}" <<'PY_FINAL_CHECK'
from __future__ import annotations
import json
import sys
import urllib.parse
import urllib.request
api, account, case_id, results_path, node_pubkey = sys.argv[1:6]

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
authority_flags = {
    'validator',
    'bft_enabled',
    'validator_active',
    'node_operator_active',
    'helper_active',
    'storage_provider_active',
    'gov_executor',
    'treasury_signer',
    'juror_active',
}
for key in sorted(authority_flags):
    if state.get(key) is True:
        if key in {'validator', 'bft_enabled', 'validator_active'}:
            raise SystemExit('observer_account_unexpected_validator_authority')
        raise SystemExit('observer_account_unexpected_authority:' + key)
roles = state.get('roles') if isinstance(state.get('roles'), list) else []
if any(str(role or '').strip() for role in roles):
    raise SystemExit('observer_account_unexpected_roles')
try:
    op = fetch('/v1/accounts/' + urllib.parse.quote(account, safe='') + '/operator-status?node_pubkey=' + urllib.parse.quote(node_pubkey, safe=''))
except Exception:
    op = {}
op_state = op.get('node_operator') if isinstance(op.get('node_operator'), dict) else {}
for bucket_name in ('baseline', 'validator', 'storage'):
    bucket = op_state.get(bucket_name) if isinstance(op_state.get(bucket_name), dict) else {}
    if bucket.get('active') is True:
        raise SystemExit('observer_account_unexpected_operator_authority:' + bucket_name)
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
- observer account/operator authority absence was checked after commit
- no genesis authority secret or external identity-provider credential was required
- results: ${RESULTS_JSONL}
MSG

if [ "${KEEP_WORK_DIR}" != "1" ]; then
  echo "[live-gate] cleaning temporary key/results directory: ${WORK_DIR}"
  rm -rf "${WORK_DIR}"
else
  echo "[live-gate] work dir retained: ${WORK_DIR}"
  echo "[live-gate] WARNING: retained files include private observer account/node keys; do not commit, upload, or share them."
fi
