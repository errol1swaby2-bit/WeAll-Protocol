#!/usr/bin/env bash
set -euo pipefail

LOCAL_API_BASE="${WEALL_LOCAL_VALIDATOR_API_BASE:-${WEALL_API_BASE:-}}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-}"
ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-${WEALL_BOUND_ACCOUNT:-}}"
NODE_PUBKEY="${WEALL_NODE_PUBKEY:-}"
MIN_ACTIVE_VALIDATORS="${WEALL_PROMOTED_VALIDATOR_MIN_ACTIVE_VALIDATORS:-2}"

fail() { echo "ERROR: $*" >&2; exit 1; }
[ -n "${LOCAL_API_BASE}" ] || fail "WEALL_LOCAL_VALIDATOR_API_BASE or WEALL_API_BASE is required"
[ -n "${GENESIS_API_BASE}" ] || fail "WEALL_GENESIS_API_BASE is required"
[ -n "${ACCOUNT}" ] || fail "WEALL_VALIDATOR_ACCOUNT or WEALL_BOUND_ACCOUNT is required"
[ -n "${NODE_PUBKEY}" ] || fail "WEALL_NODE_PUBKEY is required"

python3 -S - "${LOCAL_API_BASE%/}" "${GENESIS_API_BASE%/}" "${ACCOUNT}" "${NODE_PUBKEY}" "${MIN_ACTIVE_VALIDATORS}" <<'PY'
from __future__ import annotations
import json
import sys
import urllib.parse
import urllib.request

local_api, genesis_api, account, node_pubkey, min_active_raw = sys.argv[1:6]
min_active = int(min_active_raw or 2)
issues: list[str] = []

def fetch(api: str, path: str) -> dict:
    with urllib.request.urlopen(api.rstrip('/') + path, timeout=15) as resp:
        if resp.status >= 400:
            raise SystemExit(f'endpoint_failed:{api}{path}:{resp.status}')
        obj = json.loads(resp.read().decode('utf-8'))
    if not isinstance(obj, dict):
        raise SystemExit(f'endpoint_not_object:{api}{path}')
    return obj

local_ident = fetch(local_api, '/v1/chain/identity')
genesis_ident = fetch(genesis_api, '/v1/chain/identity')
local_chain_id = str(local_ident.get('chain_id') or local_ident.get('chain', {}).get('chain_id') or '').strip()
genesis_chain_id = str(genesis_ident.get('chain_id') or genesis_ident.get('chain', {}).get('chain_id') or '').strip()
if local_chain_id and genesis_chain_id and local_chain_id != genesis_chain_id:
    issues.append(f'chain_id_mismatch:{local_chain_id}!={genesis_chain_id}')
local_tx_index_hash = str(local_ident.get('tx_index_hash') or local_ident.get('chain', {}).get('tx_index_hash') or '').strip().lower()
genesis_tx_index_hash = str(genesis_ident.get('tx_index_hash') or genesis_ident.get('chain', {}).get('tx_index_hash') or '').strip().lower()
if not genesis_tx_index_hash and isinstance(genesis_ident.get('chain_manifest'), dict):
    genesis_tx_index_hash = str(genesis_ident['chain_manifest'].get('tx_index_hash') or '').strip().lower()
if not local_tx_index_hash and isinstance(local_ident.get('chain_manifest'), dict):
    local_tx_index_hash = str(local_ident['chain_manifest'].get('tx_index_hash') or '').strip().lower()
if local_tx_index_hash and genesis_tx_index_hash and local_tx_index_hash != genesis_tx_index_hash:
    issues.append(f'tx_index_hash_mismatch:{local_tx_index_hash}!={genesis_tx_index_hash}')

op = fetch(local_api, '/v1/status/operator')
operator = op.get('operator') if isinstance(op.get('operator'), dict) else {}
auth = operator.get('authority_contract') if isinstance(operator.get('authority_contract'), dict) else {}
if auth.get('validator_effective') is not True:
    issues.append('local_validator_authority_not_effective')
if operator.get('signing_enabled_locally') is not True:
    issues.append('local_signing_not_enabled')
if operator.get('signing_allowed_by_consensus_state') is not True:
    issues.append('local_signing_not_allowed_by_consensus_state')
if str(operator.get('local_validator_account') or '').strip() not in {'', account}:
    issues.append('local_validator_account_mismatch')

consensus = fetch(local_api, '/v1/status/consensus')
if consensus.get('local_is_active_validator') is not True:
    issues.append('local_is_not_active_validator')
active_count = int(consensus.get('active_validator_count') or 0)
if active_count < min_active:
    issues.append(f'active_validator_count_below_required:{active_count}<{min_active}')
if not str(consensus.get('validator_set_hash') or '').strip():
    issues.append('validator_set_hash_missing')

account_status = fetch(local_api, '/v1/accounts/' + urllib.parse.quote(account, safe='') + '/operator-status?node_pubkey=' + urllib.parse.quote(node_pubkey, safe=''))
node_operator = account_status.get('node_operator') if isinstance(account_status.get('node_operator'), dict) else {}
for name in ('baseline', 'validator'):
    bucket = node_operator.get(name) if isinstance(node_operator.get(name), dict) else {}
    if bucket.get('active') is not True:
        issues.append(f'{name}_not_active:' + ','.join(str(x) for x in bucket.get('reasons', []) if x))

payload = {
    'ok': not issues,
    'account': account,
    'node_pubkey': node_pubkey,
    'local_api_base': local_api,
    'genesis_api_base': genesis_api,
    'operator': operator,
    'consensus': consensus,
    'node_operator': node_operator,
    'issues': issues,
}
print(json.dumps(payload, indent=2, sort_keys=True))
if issues:
    raise SystemExit(1)
PY

cat <<MSG
OK: promoted validator live gate passed
- local validator API matches genesis chain identity
- local runtime reports validator authority effective
- local runtime reports signing enabled and allowed by consensus state
- local validator is active in consensus status
- operator-status reports active baseline node operator and validator responsibility
MSG
