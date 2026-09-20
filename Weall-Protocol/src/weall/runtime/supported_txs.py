# src/weall/runtime/supported_txs.py
"""Canonical transaction names derived from the generated tx index.

This module is retained for compatibility with tests/tools that inspect the
canon surface. It is not an apply-router authority gate. Missing or malformed
canon artifacts fail closed instead of silently selecting a stale hard-coded
transaction subset.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Set
from pathlib import Path


def _as_str(x: object) -> str:
    return str(x).strip() if x is not None else ""


def _iter_repo_roots(start: Path, *, max_up: int = 10) -> Iterable[Path]:
    cur = start
    for _ in range(max_up):
        yield cur
        if cur.parent == cur:
            break
        cur = cur.parent


def _find_generated_tx_index() -> Path | None:
    here = Path(__file__).resolve()
    for root in _iter_repo_roots(here):
        cand = root / "generated" / "tx_index.json"
        if cand.is_file():
            return cand
    return None


def _load_supported_from_tx_index(path: Path) -> set[str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("tx_index must be a JSON object")

    out: set[str] = set()
    by_name = raw.get("by_name")
    if isinstance(by_name, dict):
        out.update(_as_str(k).upper() for k in by_name if _as_str(k))

    if not out:
        by_id = raw.get("by_id")
        if isinstance(by_id, dict):
            for obj in by_id.values():
                if isinstance(obj, dict):
                    name = _as_str(obj.get("name")).upper()
                    if name:
                        out.add(name)

    if not out:
        raise ValueError(f"tx_index contains no canonical transaction names: {path}")
    return out


_idx_path = _find_generated_tx_index()
if _idx_path is None:
    raise RuntimeError("generated tx_index.json not found; canonical tx surface unavailable")
SUPPORTED_TX_TYPES: Set[str] = frozenset(_load_supported_from_tx_index(_idx_path))

__all__ = ["SUPPORTED_TX_TYPES"]
