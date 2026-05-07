from __future__ import annotations

from typing import Any

Json = dict[str, Any]

MAX_LIVE_JURORS = 10
MAX_LIVE_INTERACTING_JURORS = 3
DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR = 2
DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR = 3


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def normalize_live_threshold(*, numerator: Any = None, denominator: Any = None) -> tuple[int, int]:
    """Return a canonical rational pass threshold for Live PoH.

    The default is 2/3.  Store and compare this as an integer rational rather
    than a float so all nodes compute identical n-of-m thresholds.
    """

    num = as_int(numerator, DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR)
    den = as_int(denominator, DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR)
    if den <= 0:
        den = DEFAULT_LIVE_PASS_THRESHOLD_DENOMINATOR
    if num <= 0:
        num = DEFAULT_LIVE_PASS_THRESHOLD_NUMERATOR
    if num > den:
        num = den
    return int(num), int(den)


def live_active_reviewer_count(panel_size: int) -> int:
    size = max(0, min(int(panel_size), MAX_LIVE_JURORS))
    if size <= 0:
        return 0
    return min(MAX_LIVE_INTERACTING_JURORS, size)


def live_observer_count(panel_size: int) -> int:
    size = max(0, min(int(panel_size), MAX_LIVE_JURORS))
    return max(0, size - live_active_reviewer_count(size))


def required_live_passes(verdict_count: int, *, numerator: Any = None, denominator: Any = None) -> int:
    """Return deterministic n for an n-of-m percentile threshold.

    Example with the default 2/3 threshold:
      - 1 active reviewer => 1 pass required
      - 2 active reviewers => 2 passes required
      - 3 active reviewers => 2 passes required

    This lets the same logic bootstrap from a single genesis Live account and
    scale up to the full 3-active / 7-watching panel without changing code.
    """

    m = max(0, int(verdict_count))
    if m <= 0:
        return 0
    num, den = normalize_live_threshold(numerator=numerator, denominator=denominator)
    return max(1, (m * num + den - 1) // den)


def live_quorum_summary(
    *,
    panel_size: int,
    numerator: Any = None,
    denominator: Any = None,
) -> Json:
    active = live_active_reviewer_count(panel_size)
    observers = live_observer_count(panel_size)
    num, den = normalize_live_threshold(numerator=numerator, denominator=denominator)
    return {
        "max_jurors": MAX_LIVE_JURORS,
        "juror_count": max(0, min(int(panel_size), MAX_LIVE_JURORS)),
        "active_reviewers": active,
        "watching_observers": observers,
        "pass_threshold_num": num,
        "pass_threshold_den": den,
        "required_verdicts": active,
        "required_passes": required_live_passes(active, numerator=num, denominator=den),
    }
