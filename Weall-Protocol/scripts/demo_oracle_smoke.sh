#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_URL="${WEALL_DEMO_ORACLE_URL:-${WEALL_POH_EMAIL_ORACLE_URL:-}}"
if [[ -z "${ORACLE_URL}" ]]; then
  echo "ERROR: set WEALL_DEMO_ORACLE_URL or WEALL_POH_EMAIL_ORACLE_URL to the demo oracle base URL" >&2
  exit 2
fi
ORACLE_URL="${ORACLE_URL%/}"

bash "${ROOT_DIR}/scripts/demo_oracle_env_check.sh" >/dev/null

python3 -S - "${ORACLE_URL}" "${ROOT_DIR}/configs/chains/weall-demo.json" <<'PY'
import json, sys, urllib.request
url, manifest_path = sys.argv[1:3]
with open(manifest_path, 'r', encoding='utf-8') as f:
    manifest = json.load(f)
with urllib.request.urlopen(url.rstrip('/') + '/healthz', timeout=15) as resp:
    body = json.loads(resp.read().decode('utf-8'))
errors = []
if not body.get('ok'):
    errors.append('healthz not ok')
if body.get('profile') != 'demo':
    errors.append(f"profile mismatch: {body.get('profile')!r}")
if body.get('chain_id') != manifest.get('chain_id'):
    errors.append('chain_id mismatch')
if body.get('expected_genesis_hash') != manifest.get('genesis_hash'):
    errors.append('genesis hash mismatch')
if body.get('expected_tx_index_hash') != manifest.get('tx_index_hash'):
    errors.append('tx index hash mismatch')
if errors:
    for err in errors:
        print('ERROR:', err, file=sys.stderr)
    print(json.dumps(body, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(2)
print(json.dumps({'ok': True, 'oracle_url': url, 'healthz': body}, indent=2, sort_keys=True))
PY
