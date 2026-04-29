#!/usr/bin/env bash
set -euo pipefail

# Smoke-check a deployed production WeAll-hosted email oracle. This only queries
# /healthz and validates non-secret chain/profile anchors against the pinned
# production chain manifest.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_URL="${WEALL_PROD_ORACLE_URL:-${WEALL_POH_EMAIL_ORACLE_URL:-}}"
MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"

if [ -z "${ORACLE_URL}" ]; then
  echo "ERROR: set WEALL_PROD_ORACLE_URL or WEALL_POH_EMAIL_ORACLE_URL to the production oracle base URL" >&2
  exit 2
fi
if [ ! -f "${MANIFEST}" ]; then
  echo "ERROR: production chain manifest not found: ${MANIFEST}" >&2
  exit 2
fi

ORACLE_URL="${ORACLE_URL%/}"

python3 -S - "${ORACLE_URL}" "${MANIFEST}" <<'PY'
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

url = sys.argv[1].rstrip("/")
manifest_path = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
try:
    with urllib.request.urlopen(url + "/healthz", timeout=15) as resp:
        status = int(resp.status)
        body = json.loads(resp.read().decode("utf-8"))
except urllib.error.URLError as exc:
    print(f"ERROR: oracle_healthz_fetch_failed:{exc}", file=sys.stderr)
    sys.exit(2)

issues: list[str] = []
if status >= 400:
    issues.append(f"healthz_http_status:{status}")
if not isinstance(body, dict):
    issues.append("healthz_not_object")
    body = {}
if not bool(body.get("ok")):
    issues.append("healthz_not_ok")
if body.get("profile") != "production":
    issues.append("profile_not_production")
if body.get("chain_id") != manifest.get("chain_id"):
    issues.append("chain_id_mismatch")
if body.get("expected_genesis_hash") != manifest.get("genesis_hash"):
    issues.append("genesis_hash_mismatch")
if body.get("expected_tx_index_hash") != manifest.get("tx_index_hash"):
    issues.append("tx_index_hash_mismatch")

serialized = json.dumps(body, sort_keys=True).lower()
for forbidden in ("smtp_password", "relay_signing_secret", "api_key", "private", "privkey", "secret"):
    if forbidden in serialized:
        issues.append(f"healthz_may_expose_sensitive_label:{forbidden}")

payload = {
    "ok": not issues,
    "issues": issues,
    "oracle_url": url,
    "manifest": str(manifest_path),
    "healthz": body if not issues else {k: body.get(k) for k in sorted(body) if k in {"ok", "profile", "chain_id", "expected_genesis_hash", "expected_tx_index_hash"}},
}
print(json.dumps(payload, indent=2, sort_keys=True))
if issues:
    sys.exit(2)
PY
