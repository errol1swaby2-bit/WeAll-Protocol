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
