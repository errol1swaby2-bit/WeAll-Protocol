from __future__ import annotations

"""Pure deterministic WeCoin issuance helpers.

The v1.5 monetary model is epoch-based.  Blocks have a 20-second target
interval, but issuance is evaluated only once per 10-minute issuance epoch.
At the target interval, one issuance epoch is exactly 30 blocks.
"""

from typing import Any

from weall.ledger.constants import (
    HALVING_INTERVAL_ISSUANCE_EPOCHS,
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    MAX_SUPPLY,
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def issuance_epoch_index_for_height(height: int) -> int:
    """Return the issuance epoch containing a block height.

    Height 1 through height 30 are issuance epoch 0.  Height 31 through 60 are
    issuance epoch 1, and so on.  Non-positive heights are outside issuance and
    return -1.
    """

    h = _as_int(height, 0)
    if h <= 0:
        return -1
    return (h - 1) // int(ISSUANCE_EPOCH_BLOCKS)


def issuance_due_at_height(height: int) -> bool:
    """True when a block height closes an issuance epoch."""

    h = _as_int(height, 0)
    return h > 0 and h % int(ISSUANCE_EPOCH_BLOCKS) == 0


def issuance_epoch_index_for_due_height(height: int) -> int:
    """Return the epoch index emitted at a due height.

    Raises ValueError when the height is not an issuance boundary.  This helper
    is intentionally strict for scheduler/tests while apply code can still
    derive a legacy epoch for old system payloads.
    """

    h = _as_int(height, 0)
    if not issuance_due_at_height(h):
        raise ValueError("height is not an issuance epoch boundary")
    return (h // int(ISSUANCE_EPOCH_BLOCKS)) - 1


def issuance_height_for_epoch(epoch_index: int) -> int:
    """Return the block height that closes/emits an issuance epoch."""

    epoch = _as_int(epoch_index, 0)
    if epoch < 0:
        epoch = 0
    return (epoch + 1) * int(ISSUANCE_EPOCH_BLOCKS)


def next_issuance_height_after_height(height: int) -> int:
    """Return the next issuance boundary strictly after the current height."""

    h = max(0, _as_int(height, 0))
    return ((h // int(ISSUANCE_EPOCH_BLOCKS)) + 1) * int(ISSUANCE_EPOCH_BLOCKS)


def epoch_issuance_subsidy_atomic(epoch_index: int) -> int:
    """Return raw issuance for an issuance epoch in atomic WCN units."""

    epoch = _as_int(epoch_index, -1)
    if epoch < 0:
        return 0
    halvings = epoch // int(HALVING_INTERVAL_ISSUANCE_EPOCHS)
    return max(0, int(INITIAL_ISSUANCE_PER_EPOCH) >> int(halvings))


def issuance_subsidy_for_height(height: int) -> int:
    """Return raw issuance for a block height, or zero when not due."""

    if not issuance_due_at_height(height):
        return 0
    return epoch_issuance_subsidy_atomic(issuance_epoch_index_for_due_height(height))


def next_halving_issuance_epoch(epoch_index: int) -> int:
    epoch = max(0, _as_int(epoch_index, 0))
    current_window = epoch // int(HALVING_INTERVAL_ISSUANCE_EPOCHS)
    return (current_window + 1) * int(HALVING_INTERVAL_ISSUANCE_EPOCHS)


def cap_issuance_by_remaining_supply(issued: int, raw_amount: int, *, max_supply: int = MAX_SUPPLY) -> tuple[int, int]:
    """Cap issuance so total issued supply never exceeds max_supply.

    Returns ``(capped_amount, remaining_after)``.
    """

    issued_i = max(0, _as_int(issued, 0))
    max_i = max(0, _as_int(max_supply, int(MAX_SUPPLY)))
    raw_i = max(0, _as_int(raw_amount, 0))
    if issued_i >= max_i:
        return 0, 0
    remaining = max_i - issued_i
    capped = min(raw_i, remaining)
    return int(capped), int(remaining - capped)


__all__ = [
    "cap_issuance_by_remaining_supply",
    "epoch_issuance_subsidy_atomic",
    "issuance_due_at_height",
    "issuance_epoch_index_for_due_height",
    "issuance_epoch_index_for_height",
    "issuance_height_for_epoch",
    "issuance_subsidy_for_height",
    "next_halving_issuance_epoch",
    "next_issuance_height_after_height",
]
