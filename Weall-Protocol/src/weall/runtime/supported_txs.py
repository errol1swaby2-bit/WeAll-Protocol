# src/weall/runtime/supported_txs.py
"""Build-time supported tx types.

Genesis migration goal:
  This node build should accept *canon* tx types at admission time, and then
  fail-closed at *apply* time for anything not implemented.

Practically:
  - Admission uses TxIndex + per-tx canon flags (context, receipt_only, etc.)
  - Apply router uses SUPPORTED_TX_TYPES as a coarse gate to reject tx types
    that are completely unknown to this build.

To keep the build aligned with the generated canon, we load the tx names from
generated/tx_index.json when available. If the file cannot be located (e.g.
embedded packaging), we fall back to a conservative hard-coded set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import AbstractSet, Iterable, Set


def _as_str(x: object) -> str:
    return str(x).strip() if x is not None else ""


def _iter_repo_roots(start: Path, *, max_up: int = 6) -> Iterable[Path]:
    """Yield candidate repo roots by walking upwards from start."""
    cur = start
    for _ in range(max_up):
        yield cur
        if cur.parent == cur:
            break
        cur = cur.parent


def _find_generated_tx_index() -> Path | None:
    here = Path(__file__).resolve()

    # Typical layout:
    #   repo/generated/tx_index.json
    #   repo/src/weall/runtime/supported_txs.py
    for root in _iter_repo_roots(here, max_up=10):
        cand = root / "generated" / "tx_index.json"
        if cand.exists():
            return cand
    return None


def _load_supported_from_tx_index(path: Path) -> Set[str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    out: Set[str] = set()

    # Newer TxIndex shape:
    #   {"by_id": {"1": {"name": ...}, ...}, "by_name": {"TX": {...}}, ...}
    by_name = raw.get("by_name")
    if isinstance(by_name, dict):
        for k in by_name.keys():
            name = _as_str(k).upper()
            if name:
                out.add(name)
        if out:
            return out

    by_id = raw.get("by_id")
    if isinstance(by_id, dict):
        for obj in by_id.values():
            if not isinstance(obj, dict):
                continue
            name = _as_str(obj.get("name")).upper()
            if name:
                out.add(name)

    return out


# Conservative fallback set (kept small on purpose).
_FALLBACK: AbstractSet[str] = frozenset(
    {
        "IDENTITY_CREATE",
        "POH_TIER1_MINT",
        "POST_CREATE",
        "GOV_PROPOSAL_CREATE",
        "TREASURY_CREATE",
        "BLOCK_PROPOSE",
        "BLOCK_ATTEST",
        "BLOCK_FINALIZE",
    }
)


_idx_path = _find_generated_tx_index()
if _idx_path is not None:
    _loaded = _load_supported_from_tx_index(_idx_path)
    SUPPORTED_TX_TYPES: AbstractSet[str] = frozenset(_loaded) if _loaded else _FALLBACK
else:
    SUPPORTED_TX_TYPES = _FALLBACK


__all__ = ["SUPPORTED_TX_TYPES"]
