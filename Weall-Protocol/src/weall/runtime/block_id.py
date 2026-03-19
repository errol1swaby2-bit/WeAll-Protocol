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
    node_id: str = "",
    tx_ids: Optional[List[str]] = None,
    prev_block_hash: str = "",
    receipts_root: str = "",
) -> str:
    """Compute a deterministic, content-addressed block id.

    Safety contract:
      - must not depend on wall-clock local-only metadata beyond the block's
        committed timestamp
      - must be stable for the same ordered tx set and same parent linkage
      - must be strong enough that two distinct blocks at the same height cannot
        alias merely because they share (height, ts_ms, tx_count)

    IMPORTANT:
      We intentionally do *not* include state_root here because the current
      state_root commits to tip/block ancestry metadata that itself contains the
      block_id. Including state_root would create a circular dependency.
    """
    obj: Json = {
        "chain_id": str(chain_id),
        "height": int(height),
        "prev_block_id": str(prev_block_id or ""),
        "prev_block_hash": str(prev_block_hash or ""),
        "ts_ms": int(ts_ms),
        "node_id": str(node_id or ""),
        "tx_ids": [str(x) for x in (tx_ids or [])],
        "receipts_root": str(receipts_root or ""),
    }
    return _sha256_hex(_json_canonical(obj))
