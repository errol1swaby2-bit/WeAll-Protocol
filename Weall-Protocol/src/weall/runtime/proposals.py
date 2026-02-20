# src/weall/runtime/proposals.py
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

Json = Dict[str, Any]


def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def commitment_hash(tx_ids: List[str]) -> str:
    """Deterministic sha256 commitment over ordered tx_ids."""
    arr = [str(x) for x in tx_ids]
    raw = json.dumps(arr, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _sha256(raw)


def compute_proposal_id(
    *,
    chain_id: str,
    height: int,
    round: int,
    prev_block_id: Optional[str],
    ts_ms: int,
    proposer: str,
    body_commitment: str,
) -> str:
    """Deterministic proposal_id for a proposed block body."""
    obj: Json = {
        "chain_id": str(chain_id),
        "height": int(height),
        "round": int(round),
        "prev_block_id": str(prev_block_id) if prev_block_id else None,
        "ts_ms": int(ts_ms),
        "proposer": str(proposer),
        "body_commitment": str(body_commitment),
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _sha256(raw)
