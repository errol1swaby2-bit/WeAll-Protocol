#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-demo.json}"

if [[ ! -f "${MANIFEST}" ]]; then
  echo "ERROR: demo chain manifest not found: ${MANIFEST}" >&2
  exit 2
fi

python3 -S - "${MANIFEST}" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    m = json.load(f)
errors = []
for key in ['chain_id', 'genesis_hash', 'genesis_state_root', 'tx_index_hash']:
    value = str(m.get(key) or '').strip()
    if not value or value.lower().startswith('replace'):
        errors.append(f'manifest {key} is not pinned')
if str(m.get('chain_id')) != 'weall-demo':
    errors.append('demo manifest chain_id must be weall-demo')
if str(m.get('mode')) != 'demo':
    errors.append('demo manifest mode must be demo')
trusted = m.get('trusted_authority_pubkeys') or []
if not trusted or any(str(x).lower().startswith('replace') for x in trusted):
    errors.append('demo trusted_authority_pubkeys must be pinned')
if errors:
    for err in errors:
        print('ERROR:', err, file=sys.stderr)
    sys.exit(2)
print(json.dumps({
    'ok': True,
    'manifest': path,
    'chain_id': m.get('chain_id'),
    'genesis_hash': m.get('genesis_hash'),
    'tx_index_hash': m.get('tx_index_hash'),
    'demo_authority_pubkeys': trusted,
}, indent=2, sort_keys=True))
PY

expected_chain_id="$(python3 -S - "${MANIFEST}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8')).get('chain_id',''))
PY
)"
expected_genesis="$(python3 -S - "${MANIFEST}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8')).get('genesis_hash',''))
PY
)"
expected_tx_index="$(python3 -S - "${MANIFEST}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8')).get('tx_index_hash',''))
PY
)"

if [[ -n "${WEALL_ORACLE_PROFILE:-}" && "${WEALL_ORACLE_PROFILE}" != "demo" ]]; then
  echo "ERROR: WEALL_ORACLE_PROFILE must be demo for demo oracle checks" >&2
  exit 2
fi
if [[ -n "${WEALL_EXPECTED_CHAIN_ID:-}" && "${WEALL_EXPECTED_CHAIN_ID}" != "${expected_chain_id}" ]]; then
  echo "ERROR: WEALL_EXPECTED_CHAIN_ID does not match demo manifest" >&2
  exit 2
fi
if [[ -n "${WEALL_EXPECTED_GENESIS_HASH:-}" && "${WEALL_EXPECTED_GENESIS_HASH}" != "${expected_genesis}" ]]; then
  echo "ERROR: WEALL_EXPECTED_GENESIS_HASH does not match demo manifest" >&2
  exit 2
fi
if [[ -n "${WEALL_EXPECTED_TX_INDEX_HASH:-}" && "${WEALL_EXPECTED_TX_INDEX_HASH}" != "${expected_tx_index}" ]]; then
  echo "ERROR: WEALL_EXPECTED_TX_INDEX_HASH does not match demo manifest" >&2
  exit 2
fi

cat <<MSG
Demo oracle env check passed.
Export these for external provider demo env or local smoke tests:
  WEALL_ORACLE_PROFILE=demo
  WEALL_EXPECTED_CHAIN_ID=${expected_chain_id}
  WEALL_EXPECTED_GENESIS_HASH=${expected_genesis}
  WEALL_EXPECTED_TX_INDEX_HASH=${expected_tx_index}
MSG
