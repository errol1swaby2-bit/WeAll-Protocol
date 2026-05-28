#!/usr/bin/env bash
set -euo pipefail

API_BASE="${WEALL_API_BASE:-${1:-http://127.0.0.1:8001}}"
API_BASE="${API_BASE%/}"

echo "[block-proof] api_base=$API_BASE"

python3 - <<'PY' "$API_BASE"
import json
import sys
import urllib.request

base = sys.argv[1].rstrip('/')

def get(path):
    with urllib.request.urlopen(base + path, timeout=8) as res:
        return json.loads(res.read().decode('utf-8'))

status = get('/v1/status')
ready = get('/v1/readyz')
proof = get('/v1/consensus/block-production/readiness')

print('[block-proof] status height:', status.get('height'))
print('[block-proof] ready ok:', ready.get('ok'))
print('[block-proof] proof:', json.dumps(proof, indent=2, sort_keys=True))

if not proof.get('ok'):
    raise SystemExit('block_production_readiness_not_ok')
if proof.get('observer_mode') and proof.get('can_locally_produce'):
    raise SystemExit('observer_reported_as_producer')
if proof.get('block_loop', {}).get('unhealthy'):
    raise SystemExit('block_loop_unhealthy')
PY

echo "[block-proof] OK: block production posture endpoint is reachable and fail-closed for observer authority"
