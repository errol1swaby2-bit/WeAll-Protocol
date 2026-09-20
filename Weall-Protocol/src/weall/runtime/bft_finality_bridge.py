from __future__ import annotations

"""Deterministic HotStuff -> canonical finality bridge.

A HotStuff QC is node-local/network evidence until it is carried by the next
proposal as ``justify_qc``.  At that point every honest node replaying the block
has the same proof object and ancestry, so the 3-chain finalized grandparent can
be turned into a canonical SYSTEM receipt without depending on message arrival
order.
"""

from typing import Any

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


class BftFinalityBridgeError(RuntimeError):
    pass


def _s(v: Any) -> str:
    return str(v or "").strip()


def _i(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _blocks(state: Json) -> Json:
    raw = state.get("blocks")
    return raw if isinstance(raw, dict) else {}


def _parent(blocks: Json, block_id: str) -> str:
    rec = blocks.get(block_id)
    if not isinstance(rec, dict):
        return ""
    return _s(rec.get("prev_block_id") or rec.get("prev"))


def _height(blocks: Json, block_id: str) -> int:
    rec = blocks.get(block_id)
    return _i(rec.get("height"), 0) if isinstance(rec, dict) else 0


def _is_descendant(blocks: Json, *, candidate: str, ancestor: str) -> bool:
    cur = _s(candidate)
    want = _s(ancestor)
    seen: set[str] = set()
    while cur and cur not in seen:
        if cur == want:
            return True
        seen.add(cur)
        cur = _parent(blocks, cur)
    return False


def finalized_target_from_justify_qc(
    state: Json, justify_qc: Json | None
) -> tuple[str, int] | None:
    """Return the HotStuff 3-chain finalized grandparent encoded by ``justify_qc``.

    Cryptographic QC verification belongs to proposal/commit admission.  This
    bridge is intentionally structural and is only called with the locally
    verified best QC on the leader or after follower BFT admission succeeds.
    """

    if not isinstance(justify_qc, dict):
        return None
    qbid = _s(justify_qc.get("block_id"))
    if not qbid:
        return None

    blocks = _blocks(state)
    rec3 = blocks.get(qbid)
    if not isinstance(rec3, dict):
        return None
    b2 = _parent(blocks, qbid)
    if not b2:
        return None
    declared_parent = _s(justify_qc.get("parent_id"))
    if declared_parent and declared_parent != b2:
        raise BftFinalityBridgeError("justify_qc_parent_mismatch")
    if not isinstance(blocks.get(b2), dict):
        return None
    b1 = _parent(blocks, b2)
    if not b1 or not isinstance(blocks.get(b1), dict):
        return None
    h1 = _height(blocks, b1)
    if h1 <= 0:
        return None
    return b1, h1


def schedule_bft_finality_receipt(
    state: Json,
    *,
    justify_qc: Json | None,
    next_height: int,
) -> str | None:
    """Queue the canonical BLOCK_FINALIZE receipt implied by a proposal QC."""

    target = finalized_target_from_justify_qc(state, justify_qc)
    if target is None:
        return None
    block_id, height = target
    blocks = _blocks(state)

    finalized = state.get("finalized") if isinstance(state.get("finalized"), dict) else {}
    current_id = _s(finalized.get("block_id"))
    current_height = _i(finalized.get("height"), 0)
    if height < current_height:
        return None
    if height == current_height:
        if not current_id or current_id == block_id:
            return None
        raise BftFinalityBridgeError("conflicting_finalized_block_at_same_height")
    if current_id and not _is_descendant(blocks, candidate=block_id, ancestor=current_id):
        raise BftFinalityBridgeError("finalized_branch_regression")

    qbid = _s((justify_qc or {}).get("block_id"))
    return enqueue_system_tx(
        state,
        tx_type="BLOCK_FINALIZE",
        payload={"block_id": block_id, "height": int(height)},
        due_height=int(next_height),
        signer="SYSTEM",
        once=True,
        parent=qbid,
        phase="pre",
    )


__all__ = [
    "BftFinalityBridgeError",
    "finalized_target_from_justify_qc",
    "schedule_bft_finality_receipt",
]
