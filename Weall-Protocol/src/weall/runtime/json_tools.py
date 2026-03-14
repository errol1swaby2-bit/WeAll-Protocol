"""JSON helpers used across the runtime.

These helpers are intentionally tiny and dependency-free.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence


def deep_get(obj: Any, path: Sequence[Any] | Iterable[Any], default: Any = None) -> Any:
    """Safely traverse nested dicts/lists.

    Args:
        obj: root object (usually a dict-like ledger state)
        path: keys/indices to traverse
        default: returned if any hop is missing or incompatible

    Examples:
        deep_get(state, ["params", "gates", "POST_CREATE"], default=None)
    """

    cur: Any = obj
    for key in list(path):
        if isinstance(cur, dict):
            if key in cur:
                cur = cur[key]
            else:
                return default
        elif isinstance(cur, list):
            try:
                idx = int(key)
            except Exception:
                return default
            if 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return default
        else:
            return default
    return cur
