#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-${WEALL_BOUND_ACCOUNT:-}}"
NODE_PUBKEY="${WEALL_NODE_PUBKEY:-}"
NODE_PUBKEY_FILE="${WEALL_NODE_PUBKEY_FILE:-}"
REPORT_OUT="${WEALL_PROMOTED_VALIDATOR_PREFLIGHT_REPORT:-}"
MIN_ACTIVE_VALIDATORS="${WEALL_PROMOTED_VALIDATOR_MIN_ACTIVE_VALIDATORS:-}"

fail() { echo "ERROR: $*" >&2; exit 2; }
env_is_true() { case "${1:-0}" in 1|true|TRUE|yes|YES|on|ON) return 0 ;; *) return 1 ;; esac; }

[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"
[ -n "${GENESIS_API_BASE}" ] || fail "WEALL_GENESIS_API_BASE or WEALL_API_BASE is required"
[ -n "${ACCOUNT}" ] || fail "WEALL_VALIDATOR_ACCOUNT or WEALL_BOUND_ACCOUNT is required"
[ -n "${WEALL_NODE_PRIVKEY_FILE:-${WEALL_NODE_PRIVKEY:-}}" ] || fail "WEALL_NODE_PRIVKEY_FILE or WEALL_NODE_PRIVKEY is required"

if [ -z "${NODE_PUBKEY}" ] && [ -n "${NODE_PUBKEY_FILE}" ]; then
  NODE_PUBKEY="$(python3 -S - "${NODE_PUBKEY_FILE}" <<'PY'
from __future__ import annotations
import json, sys
from pathlib import Path
path = Path(sys.argv[1]).expanduser()
obj = json.loads(path.read_text(encoding='utf-8'))
print(str(obj.get('public_key_hex') or obj.get('pubkey') or obj.get('public_key') or '').strip())
PY
)"
fi
[ -n "${NODE_PUBKEY}" ] || fail "WEALL_NODE_PUBKEY or WEALL_NODE_PUBKEY_FILE with public key is required"

if env_is_true "${WEALL_OBSERVER_MODE:-0}"; then
  fail "observer mode must be cleared before promoted validator preflight"
fi
if [ "${WEALL_NODE_LIFECYCLE_STATE:-production_service}" = "observer_onboarding" ]; then
  fail "WEALL_NODE_LIFECYCLE_STATE=observer_onboarding must be cleared before validator promotion"
fi
if [ -n "${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}" ]; then
  fail "WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE must not remain set for validator promotion"
fi

export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
bash "${ROOT_DIR}/scripts/prod_chain_manifest_check.sh" "${MANIFEST_PATH}" >/tmp/weall_promoted_validator_manifest_check.json
rm -f /tmp/weall_promoted_validator_manifest_check.json

python3 -S - "${GENESIS_API_BASE%/}" "${MANIFEST_PATH}" "${ACCOUNT}" "${NODE_PUBKEY}" "${MIN_ACTIVE_VALIDATORS}" "${REPORT_OUT}" "${ROOT_DIR}" <<'PY'
from __future__ import annotations
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

api, manifest_path, account, node_pubkey, min_active_raw, report_out, root_dir = sys.argv[1:8]
def _bft_min_validators(repo_root: str) -> int:
    try:
        text = (Path(repo_root) / 'src' / 'weall' / 'runtime' / 'bft_hotstuff.py').read_text(encoding='utf-8')
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('BFT_MIN_VALIDATORS') and '=' in line:
                return int(line.split('=', 1)[1].strip())
    except Exception:
        pass
    return 4

min_active = int(min_active_raw or _bft_min_validators(root_dir))
manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
issues: list[str] = []

def _norm(value) -> str:
    return str(value or '').strip()

def _norm_lower(value) -> str:
    return _norm(value).lower()

def _local_protocol_version() -> str:
    try:
        tx_index = json.loads((Path(root_dir) / 'generated' / 'tx_index.json').read_text(encoding='utf-8'))
        meta = tx_index.get('meta') if isinstance(tx_index.get('meta'), dict) else {}
        return _norm(meta.get('version'))
    except Exception:
        return ''

def _check_bound_detail(details: dict, key: str, expected: str, *, lower: bool = False, required: bool = True) -> None:
    actual = _norm(details.get(key))
    exp = _norm(expected)
    if lower:
        actual, exp = actual.lower(), exp.lower()
    if required and not actual:
        issues.append(f'validator_readiness_{key}_missing')
        return
    if actual and exp and actual != exp:
        issues.append(f'validator_readiness_{key}_mismatch:{actual}!={exp}')

def fetch(path: str) -> dict:
    with urllib.request.urlopen(api.rstrip('/') + path, timeout=15) as resp:
        if resp.status >= 400:
            raise SystemExit(f'remote_endpoint_failed:{path}:{resp.status}')
        obj = json.loads(resp.read().decode('utf-8'))
    if not isinstance(obj, dict):
        raise SystemExit(f'remote_endpoint_not_object:{path}')
    return obj

ident = fetch('/v1/chain/identity')
remote_chain_id = str(ident.get('chain_id') or ident.get('chain', {}).get('chain_id') or '').strip()
expected_chain_id = str(manifest.get('chain_id') or manifest.get('chain', {}).get('chain_id') or '').strip()
if expected_chain_id and remote_chain_id and expected_chain_id != remote_chain_id:
    issues.append(f'chain_id_mismatch:{remote_chain_id}!={expected_chain_id}')
manifest_obj = ident.get('chain_manifest') if isinstance(ident.get('chain_manifest'), dict) else {}
remote_tx_index_hash = str(manifest_obj.get('tx_index_hash') or ident.get('tx_index_hash') or '').strip().lower()
expected_tx_index_hash = str(manifest.get('tx_index_hash') or manifest.get('chain', {}).get('tx_index_hash') or '').strip().lower()
if expected_tx_index_hash and remote_tx_index_hash and expected_tx_index_hash != remote_tx_index_hash:
    issues.append(f'tx_index_hash_mismatch:{remote_tx_index_hash}!={expected_tx_index_hash}')

op_path = '/v1/accounts/' + urllib.parse.quote(account, safe='') + '/operator-status?node_pubkey=' + urllib.parse.quote(node_pubkey, safe='')
op = fetch(op_path)
op_state = op.get('node_operator') if isinstance(op.get('node_operator'), dict) else {}
baseline = op_state.get('baseline') if isinstance(op_state.get('baseline'), dict) else {}
validator = op_state.get('validator') if isinstance(op_state.get('validator'), dict) else {}
if baseline.get('active') is not True:
    issues.append('baseline_node_operator_not_active:' + ','.join(str(x) for x in baseline.get('reasons', []) if x))
if validator.get('active') is not True:
    issues.append('validator_responsibility_not_active:' + ','.join(str(x) for x in validator.get('reasons', []) if x))
validator_details = validator.get('details') if isinstance(validator.get('details'), dict) else {}
expected_profile_hash = _norm(manifest.get('protocol_profile_hash'))
expected_schema_version = _norm(manifest.get('schema_version'))
expected_protocol_version = _local_protocol_version()
_check_bound_detail(validator_details, 'chain_id', expected_chain_id, required=True)
_check_bound_detail(validator_details, 'tx_index_hash', expected_tx_index_hash, lower=True, required=True)
_check_bound_detail(validator_details, 'runtime_profile_hash', expected_profile_hash, lower=True, required=True)
_check_bound_detail(validator_details, 'schema_version', expected_schema_version, required=True)
_check_bound_detail(validator_details, 'protocol_version', expected_protocol_version, required=bool(expected_protocol_version))
_check_bound_detail(validator_details, 'bft_pubkey', _norm(validator_details.get('bft_pubkey')), required=True)
if _norm(validator_details.get('node_pubkey')) and _norm(validator_details.get('node_pubkey')) != node_pubkey:
    issues.append(f'validator_readiness_node_pubkey_mismatch:{_norm(validator_details.get("node_pubkey"))}!={node_pubkey}')
if not _norm(validator_details.get('readiness_receipt_hash')):
    issues.append('validator_readiness_receipt_hash_missing')

def _consensus_validator_set_hash(consensus: dict) -> str:
    direct = str(consensus.get('validator_set_hash') or '').strip()
    if direct:
        return direct
    current = str(consensus.get('current_validator_set_hash') or '').strip()
    if current:
        return current
    startup = consensus.get('startup_fingerprint') if isinstance(consensus.get('startup_fingerprint'), dict) else {}
    startup_hash = str(startup.get('validator_set_hash') or '').strip()
    if startup_hash:
        return startup_hash
    lifecycle = consensus.get('local_validator_lifecycle') if isinstance(consensus.get('local_validator_lifecycle'), dict) else {}
    return str(lifecycle.get('current_validator_set_hash') or '').strip()

consensus = fetch('/v1/status/consensus')
active_count = int(consensus.get('active_validator_count') or 0)
validator_set_hash = _consensus_validator_set_hash(consensus)
if active_count < min_active:
    issues.append(f'active_validator_count_below_required:{active_count}<{min_active}')
if not validator_set_hash:
    issues.append('validator_set_hash_missing')

payload = {
    'ok': not issues,
    'account': account,
    'node_pubkey': node_pubkey,
    'genesis_api_base': api,
    'chain_id': remote_chain_id,
    'tx_index_hash': remote_tx_index_hash,
    'operator_status': op_state,
    'consensus': {
        'active_validator_count': active_count,
        'validator_epoch': consensus.get('validator_epoch'),
        'validator_set_hash': validator_set_hash,
        'minimum_active_validators_required': int(min_active),
    },
    'readiness_binding': {
        'chain_id': validator_details.get('chain_id'),
        'tx_index_hash': validator_details.get('tx_index_hash'),
        'runtime_profile_hash': validator_details.get('runtime_profile_hash'),
        'schema_version': validator_details.get('schema_version'),
        'protocol_version': validator_details.get('protocol_version'),
        'bft_pubkey': validator_details.get('bft_pubkey'),
        'readiness_receipt_hash': validator_details.get('readiness_receipt_hash'),
    },
    'issues': issues,
}
if report_out:
    Path(report_out).expanduser().write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(payload, indent=2, sort_keys=True))
if issues:
    raise SystemExit(2)
PY

cat <<MSG
OK: promoted validator preflight passed
- observer onboarding env is cleared
- manifest/chain identity/tx_index_hash match genesis API when advertised
- node pubkey is bound to active node-operator state
- validator responsibility is active from protocol state
- validator readiness receipt is bound to the local chain_id/tx_index_hash/profile/schema/protocol fields
- consensus validator set is present and has at least ${MIN_ACTIVE_VALIDATORS:-BFT_MIN_VALIDATORS} active validators
MSG
