#!/usr/bin/env bash
set -euo pipefail

NODE1_API="${1:-${NODE1_API:-http://127.0.0.1:8001}}"
NODE2_API="${2:-${NODE2_API:-http://127.0.0.1:8002}}"
TMP_DIR="${TMPDIR:-/tmp}/weall-devnet-compare.$$"
mkdir -p "${TMP_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need curl
need python3

curl -fsS "${NODE1_API}/v1/chain/identity" > "${TMP_DIR}/node1.json"
curl -fsS "${NODE2_API}/v1/chain/identity" > "${TMP_DIR}/node2.json"

python3 - "$TMP_DIR/node1.json" "$TMP_DIR/node2.json" <<'PY'
import json
import sys
from pathlib import Path

left = json.loads(Path(sys.argv[1]).read_text())
right = json.loads(Path(sys.argv[2]).read_text())
keys = [
    "chain_id",
    "height",
    "tip_hash",
    "state_root",
    "schema_version",
    "tx_index_hash",
    "protocol_profile_hash",
]
print("==> Node 1")
print(json.dumps({k: left.get(k) for k in keys}, indent=2, sort_keys=True))
print("==> Node 2")
print(json.dumps({k: right.get(k) for k in keys}, indent=2, sort_keys=True))

manifest_failures = []
for node, identity in (("node1", left), ("node2", right)):
    manifest = identity.get("chain_manifest")
    if not isinstance(manifest, dict):
        manifest_failures.append({"node": node, "failure": "chain_manifest_status_missing"})
        continue
    if manifest.get("ok") is not True:
        manifest_failures.append({
            "node": node,
            "failure": "chain_manifest_not_ok",
            "issues": list(manifest.get("issues") or []),
        })
    if str(manifest.get("mode") or "").strip().lower() != "controlled_devnet":
        manifest_failures.append({
            "node": node,
            "failure": "chain_manifest_mode_not_controlled_devnet",
            "actual": manifest.get("mode"),
        })
    if manifest.get("tx_index_hash_matches") is not True:
        manifest_failures.append({
            "node": node,
            "failure": "chain_manifest_tx_index_hash_not_current",
            "expected": manifest.get("tx_index_hash"),
            "actual": manifest.get("actual_tx_index_hash"),
        })

if manifest_failures:
    print("==> CHAIN MANIFEST INVALID")
    print(json.dumps(manifest_failures, indent=2, sort_keys=True))
    sys.exit(1)

print("==> OK: node chain manifests are valid and current")

mismatches = []
for key in keys:
    if left.get(key) != right.get(key):
        mismatches.append({"field": key, "node1": left.get(key), "node2": right.get(key)})

if mismatches:
    print("==> MISMATCH")
    print(json.dumps(mismatches, indent=2, sort_keys=True))
    sys.exit(1)

print("==> OK: node identities, tips, and state roots match")
PY
