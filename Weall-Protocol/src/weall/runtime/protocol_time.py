from __future__ import annotations

"""Height-based protocol time helpers.

Protocol truth surfaces must not depend on local wall-clock timestamps.  The
only consensus-stable time signal exposed by those surfaces is the committed
chain height, plus deterministic next-height hints derived from that state.
Wall-clock milliseconds remain acceptable for transport diagnostics, logs, and
TTL caches, but not for protocol-readiness or source-of-truth payloads.
"""

from typing import Any, Mapping

Json = dict[str, Any]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or isinstance(value, bool):
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _as_str(value: Any, default: str = "") -> str:
    try:
        if value is None:
            return str(default)
        return str(value)
    except Exception:
        return str(default)


def protocol_height_from_state(state: Mapping[str, Any] | None = None) -> int:
    """Return the committed protocol height from state, never local time."""

    if not isinstance(state, Mapping):
        return 0
    return max(0, _as_int(state.get("height"), 0))


def protocol_time_height(
    state: Mapping[str, Any] | None = None,
    *,
    include_tip: bool = True,
) -> Json:
    """Return a deterministic block-height time object for truth surfaces."""

    height = protocol_height_from_state(state)
    payload: Json = {
        "clock": "block_height",
        "height": int(height),
        "current_height": int(height),
        "next_height": int(height) + 1,
        "wall_clock_ms_in_protocol_truth": False,
    }
    if include_tip and isinstance(state, Mapping):
        tip = _as_str(state.get("tip"), "")
        tip_hash = _as_str(state.get("tip_hash"), "")
        if tip:
            payload["tip"] = tip
        if tip_hash:
            payload["tip_hash"] = tip_hash
    return payload


__all__ = ["protocol_height_from_state", "protocol_time_height"]
