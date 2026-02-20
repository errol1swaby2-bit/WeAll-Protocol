from __future__ import annotations

"""Fork choice / chain selection.

Default (legacy) behavior
------------------------
If the runtime is not running BFT consensus, we select a deterministic best head
using a pragmatic longest-chain + attestations tie-break (see below).

BFT behavior
------------
If state["bft"] is present and contains a "high_qc" and/or a "finalized_block_id",
we prefer a BFT-oriented fork choice:
  1) Never select a head that is not a descendant of finalized_block_id.
  2) Prefer the block referenced by high_qc (highest known quorum certificate).
  3) If the QC block is missing, fall back to selecting the highest-height
     descendant of finalized.

This keeps backward compatibility while allowing incremental rollout of
HotStuff-style BFT finality.

NOTE: This module only *selects* a best head. Full BFT production readiness
also requires block admission rules that enforce the locked rule and QC validity.
"""

from typing import Any, Dict, Optional, Tuple

Json = Dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _parent_of(block_rec: Any) -> str:
    if not isinstance(block_rec, dict):
        return ""
    return _as_str(block_rec.get("prev_block_id") or block_rec.get("prev") or "")


def _height_of(block_rec: Any) -> int:
    if not isinstance(block_rec, dict):
        return 0
    return _as_int(block_rec.get("height"), 0)


def _att_count(state: Json, block_id: str) -> int:
    atts = state.get("block_attestations")
    if not isinstance(atts, dict):
        return 0
    per = atts.get(str(block_id))
    return len(per) if isinstance(per, dict) else 0


def _is_descendant(blocks: Dict[str, Any], *, candidate: str, ancestor: str, max_hops: int = 50_000) -> bool:
    """Return True if candidate descends from ancestor.

    max_hops prevents infinite loops if state is corrupted.
    """
    cand = str(candidate).strip()
    anc = str(ancestor).strip()
    if not cand or not anc:
        return False
    if cand == anc:
        return True

    cur = cand
    hops = 0
    while hops < int(max_hops):
        hops += 1
        rec = blocks.get(cur)
        if not isinstance(rec, dict):
            return False
        parent = _parent_of(rec)
        if not parent:
            return False
        if parent == anc:
            return True
        cur = parent
    return False


def _bft_choose_head(state: Json, blocks: Dict[str, Any]) -> Optional[str]:
    bft = state.get("bft")
    if not isinstance(bft, dict):
        return None

    finalized_block_id = _as_str(bft.get("finalized_block_id") or "")
    high_qc = bft.get("high_qc")

    qc_bid = ""
    if isinstance(high_qc, dict):
        qc_bid = _as_str(high_qc.get("block_id") or "")

    # Prefer QC block if it exists and respects finality.
    if qc_bid and qc_bid in blocks:
        if finalized_block_id:
            if _is_descendant(blocks, candidate=qc_bid, ancestor=finalized_block_id):
                return qc_bid
        else:
            return qc_bid

    # If QC not available, fall back to best descendant of finalized.
    if not finalized_block_id:
        return None

    best: Optional[Tuple[int, int, str]] = None
    for bid, rec in blocks.items():
        bid_s = _as_str(bid)
        if not bid_s:
            continue
        if not _is_descendant(blocks, candidate=bid_s, ancestor=finalized_block_id):
            continue
        h = _height_of(rec)
        ac = _att_count(state, bid_s)
        cand = (int(h), int(ac), bid_s)
        if best is None:
            best = cand
            continue
        if cand[0] > best[0]:
            best = cand
            continue
        if cand[0] == best[0] and cand[1] > best[1]:
            best = cand
            continue
        if cand[0] == best[0] and cand[1] == best[1] and cand[2] > best[2]:
            best = cand
            continue

    return best[2] if best is not None else None


def choose_head(state: Json) -> Optional[str]:
    """Choose the best head block_id from a ledger state snapshot."""
    blocks = state.get("blocks")
    if not isinstance(blocks, dict) or not blocks:
        tip = _as_str(state.get("tip") or "")
        return tip or None

    # If BFT state exists, prefer BFT-oriented head selection.
    bft_head = _bft_choose_head(state, blocks)
    if bft_head:
        return bft_head

    # --------------------------
    # Legacy deterministic choice
    # --------------------------

    finalized = state.get("finalized")
    f_height = 0
    f_block = ""
    if isinstance(finalized, dict):
        f_height = _as_int(finalized.get("height"), 0)
        f_block = _as_str(finalized.get("block_id") or "")

    best: Optional[Tuple[int, int, str]] = None  # (height, att_count, block_id)
    for bid, rec in blocks.items():
        bid_s = _as_str(bid)
        if not bid_s:
            continue
        h = _height_of(rec)
        if h <= int(f_height):
            continue
        if f_block:
            if not _is_descendant(blocks, candidate=bid_s, ancestor=f_block):
                continue

        ac = _att_count(state, bid_s)
        cand = (int(h), int(ac), bid_s)
        if best is None:
            best = cand
            continue
        if cand[0] > best[0]:
            best = cand
            continue
        if cand[0] == best[0] and cand[1] > best[1]:
            best = cand
            continue
        if cand[0] == best[0] and cand[1] == best[1] and cand[2] > best[2]:
            best = cand
            continue

    if best is None:
        tip = _as_str(state.get("tip") or "")
        return tip or None
    return best[2]
