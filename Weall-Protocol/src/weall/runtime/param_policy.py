from __future__ import annotations

"""Governance parameter policy.

Production safety: governance-controlled parameter updates must be:
  - Explicitly whitelisted
  - Bounds-checked
  - Deterministic

This module is used by apply modules that accept parameter blobs.
"""

from collections.abc import Iterable
from typing import Any

# (min, max) bounds for numeric params.
Bounds = tuple[int, int]


# Whitelist + bounds.
# Keys not present here MUST be rejected when set via governance/system tx.
ALLOWED: dict[str, Any] = {
    "params": {
        "poh": {
            "tier2_n_jurors": (3, 100),
            "tier2_min_total_reviews": (1, 100),
            "tier2_pass_threshold": (1, 100),
            "tier2_fail_max": (0, 50),
            "tier3_n_jurors": (3, 100),
            "tier3_interacting_jurors": (1, 25),
            "tier3_pass_threshold": (1, 25),
        },
        "economics": {
            # basis points (0-1000 => up to 10%)
            "transfer_fee_bps": (0, 1000),
        },
        # Treasury defaults (domain apply stores under state["treasury"]["params"],
        # but we also allow mirroring under state["params"]["treasury"].
        "treasury": {
            # timelock delay expressed in blocks
            "timelock_blocks": (0, 100_000),
        },
    },
    "treasury": {
        "params": {
            "timelock_blocks": (0, 100_000),
        }
    },
}


def _as_int(v: Any) -> int:
    if isinstance(v, bool):
        # prevent True/False passing as 1/0 in param updates
        raise ValueError("param_must_be_int")
    try:
        return int(v)
    except Exception as e:
        raise ValueError("param_must_be_int") from e


def _walk(policy: dict[str, Any], path: Iterable[str]) -> Any:
    node: Any = policy
    for p in path:
        if not isinstance(node, dict) or p not in node:
            raise ValueError("param_not_allowed")
        node = node[p]
    return node


def validate_param(path: Iterable[str], value: Any) -> None:
    """Validate a single param at a specific path.

    Example paths:
      ("params","poh","tier2_n_jurors")
      ("treasury","params","timelock_blocks")
    """

    node = _walk(ALLOWED, tuple(path))

    if isinstance(node, tuple) and len(node) == 2:
        lo, hi = node  # type: ignore[misc]
        x = _as_int(value)
        if x < int(lo) or x > int(hi):
            raise ValueError("param_out_of_bounds")
        return

    # Non-leaf or unknown leaf type is not allowed.
    raise ValueError("param_not_allowed")


def validate_param_blob(*, base_path: Iterable[str], blob: dict[str, Any]) -> None:
    """Validate a dict of leaf params under base_path.

    Only leaf numeric values are permitted. Nested dicts are permitted if they are
    explicitly present in ALLOWED.
    """

    def _recurse(cur_path: tuple[str, ...], obj: Any) -> None:
        if isinstance(obj, dict):
            for k in sorted(obj.keys(), key=lambda x: str(x)):
                _recurse(cur_path + (str(k),), obj[k])
            return

        # Leaf value.
        validate_param(cur_path, obj)

    _recurse(tuple(base_path), blob)
