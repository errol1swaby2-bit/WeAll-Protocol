from __future__ import annotations

"""Canonical execution-lane identity helpers used by the active planner."""


def lane_base_id(lane_id: str) -> str:
    value = str(lane_id or "SERIAL")
    if "#" in value:
        return value.split("#", 1)[0]
    return value


__all__ = ["lane_base_id"]
