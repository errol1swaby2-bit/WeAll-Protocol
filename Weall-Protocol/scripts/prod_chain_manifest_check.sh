#!/usr/bin/env sh
set -eu

MANIFEST_PATH="${1:-${WEALL_CHAIN_MANIFEST_PATH:-./configs/chains/weall-genesis.json}}"
TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-./generated/tx_index.json}"
GENESIS_PATH="${WEALL_GENESIS_LEDGER_PATH:-./configs/genesis.ledger.prod.json}"

PYTHONPATH="${PYTHONPATH:-./src}" python3 - "$MANIFEST_PATH" "$TX_INDEX_PATH" <<'PY'
import json
import sys

from weall.runtime.chain_manifest import chain_manifest_status, load_chain_manifest

manifest_path = sys.argv[1]
tx_index_path = sys.argv[2]
manifest = load_chain_manifest(manifest_path, required=True)
status = chain_manifest_status(
    manifest=manifest,
    chain_id=manifest.chain_id,
    mode=manifest.mode,
    tx_index_path=tx_index_path,
    strict=True,
)
print(json.dumps(status, sort_keys=True, indent=2))
if not status.get("ok"):
    raise SystemExit(2)
print("ok: chain manifest is pinned and matches local tx index")
PY

PYTHONPATH="${PYTHONPATH:-./src}" python3 scripts/assert_production_genesis_artifacts.py \
  --manifest "$MANIFEST_PATH" \
  --genesis "$GENESIS_PATH" \
  --tx-index "$TX_INDEX_PATH"
