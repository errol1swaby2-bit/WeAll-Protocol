#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${ROOT_DIR}/web"
API_BASE="${API_BASE:-${VITE_WEALL_API_BASE:-http://127.0.0.1:8000}}"

if [ ! -f "${WEB_DIR}/package.json" ]; then
  echo "ERROR: frontend package.json not found at ${WEB_DIR}" >&2
  exit 1
fi

python3 - "${API_BASE}" <<'PY'
from __future__ import annotations
import json
import sys
import urllib.request
base = sys.argv[1].rstrip('/')
try:
    with urllib.request.urlopen(base + '/v1/status', timeout=5) as resp:
        body = resp.read().decode('utf-8')
except Exception as exc:
    raise SystemExit(
        f"backend_api_unreachable:{base}: {exc}\n"
        "Start the WeAll backend API first, then rerun this script."
    )
try:
    obj = json.loads(body)
except Exception:
    raise SystemExit(f"backend_status_not_json:{base}")
if not isinstance(obj, dict) or obj.get('ok') is not True:
    raise SystemExit(f"backend_status_not_ok:{base}:{obj}")
print(f"OK: backend API reachable at {base}")
PY

cd "${WEB_DIR}"
if [ ! -d node_modules ]; then
  npm ci
fi
API_BASE="${API_BASE}" npm run contract-check
