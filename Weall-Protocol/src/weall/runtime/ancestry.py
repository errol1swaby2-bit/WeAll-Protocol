from __future__ import annotations

from collections.abc import Callable
from typing import Any


def walk_ancestry(
    records: dict[str, Any],
    *,
    candidate: str,
    ancestor: str,
    parent_of: Callable[[Any], str],
) -> bool:
    """Return True iff ``candidate`` descends from ``ancestor``.

    This helper is consensus-critical and intentionally avoids arbitrary hop
    limits. A fixed traversal cap can cause honest nodes to disagree once the
    live chain grows past that bound. Instead we terminate only when:
      - the ancestor is reached,
      - the lineage ends,
      - a record is missing, or
      - a cycle is detected in corrupted state.

    The caller supplies ``parent_of`` so the same logic can be reused across
    block maps with slightly different record shapes.
    """

    cand = str(candidate).strip()
    anc = str(ancestor).strip()
    if not cand or not anc:
        return False
    if cand == anc:
        return True

    cur = cand
    seen: set[str] = set()
    while cur:
        if cur in seen:
            return False
        seen.add(cur)
        rec = records.get(cur)
        if not isinstance(rec, dict):
            return False
        parent = str(parent_of(rec)).strip()
        if not parent:
            return False
        if parent == anc:
            return True
        cur = parent
    return False
