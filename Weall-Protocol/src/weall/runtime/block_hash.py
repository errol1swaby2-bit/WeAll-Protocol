# src/weall/runtime/block_hash.py

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

from weall.runtime.sqlite_db import _canon_json

Json = Dict[str, Any]


def compute_block_hash(*, header: Json) -> str:
    """Compute a deterministic block hash.

    The hash is defined over the canonical JSON encoding of a minimal block
    header structure (see make_block_header).

    Returns:
      sha256 hex digest
    """

    payload = _canon_json(header).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def make_block_header(
    *,
    chain_id: str,
    height: int,
    prev_block_hash: str,
    block_ts_ms: int,
    tx_ids: List[str],
) -> Json:
    """Create the canonical header structure used for hashing."""

    return {
        "chain_id": str(chain_id),
        "height": int(height),
        "prev_block_hash": str(prev_block_hash or ""),
        "block_ts_ms": int(block_ts_ms),
        "tx_ids": list(map(str, tx_ids)),
    }


def ensure_block_hash(block: Json) -> Tuple[Json, str]:
    """Return (block_with_hash, block_hash).

    - If block already includes `block_hash`, it is returned unchanged.
    - Else we compute the hash from `block["header"]` if present, or reconstruct
      a header from legacy block fields.
    """

    existing = block.get("block_hash")
    if isinstance(existing, str) and existing:
        return block, existing

    header = block.get("header")
    if isinstance(header, dict):
        bh = compute_block_hash(header=header)
        block["block_hash"] = bh
        return block, bh

    # Back-compat: reconstruct header from legacy block shape.
    chain_id = str(block.get("chain_id") or "")
    height = int(block.get("height") or 0)
    prev_bh = str(block.get("prev_block_hash") or "")
    ts_ms = int(block.get("block_ts_ms") or block.get("created_ms") or block.get("ts_ms") or 0)

    tx_ids: List[str] = []
    txs = block.get("txs")
    if isinstance(txs, list):
        for env in txs:
            if not isinstance(env, dict):
                continue
            tid = env.get("tx_id") or env.get("_tx_id") or env.get("id")
            if isinstance(tid, str) and tid:
                tx_ids.append(tid)

    hdr = make_block_header(
        chain_id=chain_id,
        height=height,
        prev_block_hash=prev_bh,
        block_ts_ms=ts_ms,
        tx_ids=tx_ids,
    )
    bh = compute_block_hash(header=hdr)

    block["header"] = hdr
    block["block_hash"] = bh
    return block, bh
