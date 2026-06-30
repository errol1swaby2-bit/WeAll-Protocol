# src/weall/runtime/block_hash.py

from __future__ import annotations

import hashlib
from typing import Any

from weall.runtime.sqlite_db import _canon_json

Json = dict[str, Any]

RECENT_BLOCK_ANCHOR_VERSION = 1
RECENT_BLOCK_ANCHOR_WINDOW = 3


def compute_block_hash(*, header: Json) -> str:
    """Compute a deterministic block hash.

    The hash is defined over the canonical JSON encoding of a minimal block
    header structure (see make_block_header).

    Returns:
      sha256 hex digest
    """

    payload = _canon_json(header).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()



def compute_recent_block_anchor(*, block_ids: list[str], window_size: int = RECENT_BLOCK_ANCHOR_WINDOW) -> str:
    """Compute a deterministic commitment to recent canonical block context.

    The input order is newest-to-oldest: state tip first, then its parent, up to
    ``window_size`` block IDs.  Height-1/2/3 startup history is represented by a
    shorter list, so early-chain anchors are deterministic without synthetic
    genesis placeholders or full-chain scans.
    """

    cleaned: list[str] = []
    seen: set[str] = set()
    for bid in block_ids if isinstance(block_ids, list) else []:
        s = str(bid or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
        if len(cleaned) >= int(window_size):
            break

    payload: Json = {
        "version": int(RECENT_BLOCK_ANCHOR_VERSION),
        "window_size": int(window_size),
        "block_ids": cleaned,
    }
    return hashlib.sha256(_canon_json(payload).encode("utf-8")).hexdigest()


def recent_block_ids_from_state(*, state: Json, window_size: int = RECENT_BLOCK_ANCHOR_WINDOW) -> list[str]:
    """Return previous canonical block IDs from state without scanning history.

    State records a bounded ancestry map at ``state["blocks"][block_id]["prev_block_id"]``.
    Walking backward from ``state["tip"]`` for at most three links gives the
    deterministic recent-history context needed by the block header anchor.
    """

    out: list[str] = []
    blocks = state.get("blocks") if isinstance(state, dict) else None
    blocks = blocks if isinstance(blocks, dict) else {}
    cur = str(state.get("tip") or "").strip() if isinstance(state, dict) else ""
    seen: set[str] = set()

    while cur and cur not in seen and len(out) < int(window_size):
        seen.add(cur)
        out.append(cur)
        rec = blocks.get(cur)
        if not isinstance(rec, dict):
            break
        cur = str(rec.get("prev_block_id") or "").strip()

    return out


def compute_helper_execution_root(*, helper_execution: Json) -> str:
    """Compute a deterministic commitment for helper execution metadata."""
    payload = _canon_json(helper_execution if isinstance(helper_execution, dict) else {}).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def compute_receipts_root(*, receipts: list[Json]) -> str:
    """Compute a deterministic receipts root.

    We commit execution results into the block hash so all nodes, indexers,
    and light clients have a canonical record of tx success/failure.

    Defined as sha256(canonical_json(receipts)).
    """

    payload = _canon_json(receipts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def make_block_header(
    *,
    chain_id: str,
    height: int,
    prev_block_hash: str,
    block_ts_ms: int,
    tx_ids: list[str],
    receipts_root: str,
    state_root: str | None = None,
    helper_execution_root: str | None = None,
    vrf: Json | None = None,
    recent_block_anchor: str | None = None,
) -> Json:
    """Create the canonical header structure used for hashing."""

    hdr: Json = {
        "chain_id": str(chain_id),
        "height": int(height),
        "prev_block_hash": str(prev_block_hash or ""),
        "block_ts_ms": int(block_ts_ms),
        "tx_ids": list(map(str, tx_ids)),
        "receipts_root": str(receipts_root or ""),
    }

    # New in production hardening: state root commitment.
    # Back-compat: omit the key if not provided so legacy block hashes remain stable.
    if isinstance(state_root, str) and state_root:
        hdr["state_root"] = state_root

    if isinstance(helper_execution_root, str) and helper_execution_root:
        hdr["helper_execution_root"] = helper_execution_root

    if isinstance(recent_block_anchor, str) and recent_block_anchor:
        hdr["recent_block_anchor"] = recent_block_anchor

    # Optional: verifiable randomness proof (VRF-ish) for deterministic juror selection.
    # Back-compat: omit if not provided so legacy block hashes remain stable.
    if isinstance(vrf, dict) and vrf:
        hdr["vrf"] = vrf

    return hdr


def ensure_block_hash(block: Json) -> tuple[Json, str]:
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

    tx_ids: list[str] = []
    txs = block.get("txs")
    if isinstance(txs, list):
        for env in txs:
            if not isinstance(env, dict):
                continue
            tid = env.get("tx_id") or env.get("_tx_id") or env.get("id")
            if isinstance(tid, str) and tid:
                tx_ids.append(tid)

    receipts_root = ""
    receipts = block.get("receipts")
    if isinstance(receipts, list):
        receipts_root = compute_receipts_root(receipts=receipts)

    helper_execution_root = ""
    helper_execution = block.get("helper_execution")
    if isinstance(helper_execution, dict) and helper_execution:
        helper_execution_root = compute_helper_execution_root(helper_execution=helper_execution)

    hdr = make_block_header(
        chain_id=chain_id,
        height=height,
        prev_block_hash=prev_bh,
        block_ts_ms=ts_ms,
        tx_ids=tx_ids,
        receipts_root=receipts_root,
        helper_execution_root=helper_execution_root or None,
    )
    bh = compute_block_hash(header=hdr)

    block["header"] = hdr
    block["block_hash"] = bh
    return block, bh
