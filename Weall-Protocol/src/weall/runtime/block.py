# src/weall/runtime/block.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Block:
    """Minimal block container used by the runtime executor and API."""

    block_id: str
    height: int
    ts_ms: int
    node_id: str
    chain_id: str
    prev_block_id: Optional[str]
    txs: List[Dict[str, Any]]
    receipts: List[Dict[str, Any]]

    def dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "block_id": self.block_id,
            "height": int(self.height),
            "ts_ms": int(self.ts_ms),
            "node_id": self.node_id,
            "chain_id": self.chain_id,
            "txs": self.txs,
            "receipts": self.receipts,
        }
        if self.prev_block_id is not None and str(self.prev_block_id).strip():
            out["prev_block_id"] = str(self.prev_block_id).strip()
        return out

    # Back-compat for older callers that expect a "to_json" method.
    def to_json(self) -> Dict[str, Any]:
        return self.dict()
