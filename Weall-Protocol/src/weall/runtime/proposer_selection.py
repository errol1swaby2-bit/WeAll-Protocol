from __future__ import annotations

"""Deterministic proposer selection.

Goal: given the same inputs, every node selects the same proposer for a (height, round).

This module is intentionally simple (hash-based, no VRF). It is "good enough" for:
  - deterministic block proposer assignment
  - reducing multi-proposer contention on a single height/round

NOT a full BFT consensus implementation.
"""

import hashlib
from typing import List, Optional


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_int(v: object, default: int = 0) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except Exception:
        return int(default)


def _norm_set(active_set: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in active_set or []:
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def select_proposer(
    *,
    active_set: List[str],
    chain_id: str,
    height: int,
    round_n: int = 0,
    seed: Optional[str] = None,
) -> Optional[str]:
    """Return the deterministic proposer account for (height, round).

    - active_set: ordered list of active validator accounts.
    - chain_id: domain separation.
    - seed: optional extra entropy (e.g., finalized block id).

    If active_set is empty, returns None.
    """

    aset = _norm_set(active_set)
    if not aset:
        return None

    h = max(0, _as_int(height, 0))
    r = max(0, _as_int(round_n, 0))
    seed_s = str(seed or "").strip()

    material = f"weall:proposer:{chain_id}:{h}:{r}:{seed_s}".encode("utf-8")
    digest = _sha256_hex(material)
    # Use the first 16 hex chars as an integer for stable mapping.
    idx = int(digest[:16], 16) % len(aset)
    return aset[idx]


__all__ = ["select_proposer"]
