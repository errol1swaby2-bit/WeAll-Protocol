# src/weall/runtime/block_id.py

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

Json = Dict[str, Any]


def _json_canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_block_id(
    *,
    chain_id: str,
    height: int,
    prev_block_id: Optional[str],
    ts_ms: int,
    node_id: str,
    tx_ids: List[str],
) -> str:
    """Compute a deterministic block_id.

    Contract:
      - includes chain_id and height
      - includes prev_block_id (or "" for genesis)
      - includes ordered tx_ids
      - excludes receipts (derived) and any non-deterministic mempool metadata
    """
    obj: Json = {
        "chain_id": str(chain_id),
        "height": int(height),
        "prev_block_id": str(prev_block_id or ""),
        "ts_ms": int(ts_ms),
        "node_id": str(node_id),
        "tx_ids": [str(x) for x in (tx_ids or [])],
    }
    return _sha256_hex(_json_canonical(obj))
