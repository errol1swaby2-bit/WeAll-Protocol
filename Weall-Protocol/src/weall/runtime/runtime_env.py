from __future__ import annotations

"""Runtime environment and local resource-guard helpers.

This module intentionally contains no consensus state mutation. It centralizes
small parsing and bounded-cache primitives that were previously scattered inside
``executor.py`` so production fail-closed behavior can be audited in one place.
"""

import os
from collections import OrderedDict
from typing import Any


def safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        if mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}")
        return int(default)


def consensus_fail_closed() -> bool:
    return mode() == "prod"


def bounded_put(od: OrderedDict[str, Any], key: str, value: Any, *, cap: int) -> None:
    """Insert into a bounded local cache.

    The cache is a resource guard only. A failure here must not change consensus
    state, so the helper remains best-effort while all block/tx validation remains
    fail-closed at the caller boundary.
    """
    if cap <= 0:
        return
    try:
        if key in od:
            del od[key]
        od[key] = value
        while len(od) > cap:
            try:
                od.popitem(last=False)
            except TypeError:
                oldest = next(iter(od))
                del od[oldest]
    except Exception:
        return


def compact_error_text(value: Any, *, limit: int = 240) -> str:
    try:
        text = str(value)
    except Exception:
        text = repr(value)
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def format_commit_failure(exc: Exception) -> str:
    error_class = type(exc).__name__
    detail = compact_error_text(exc)
    if detail:
        return f"commit_failed:{error_class}:{detail}"
    return f"commit_failed:{error_class}"


# Backward-compatible private names used by the staged extraction modules.
_safe_int = safe_int
_env_bool = env_bool
_mode = mode
_env_int = env_int
_consensus_fail_closed = consensus_fail_closed
_bounded_put = bounded_put
_compact_error_text = compact_error_text
_format_commit_failure = format_commit_failure
