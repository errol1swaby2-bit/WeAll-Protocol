from __future__ import annotations

"""Runtime time helpers and block timestamp policy surface.

This module owns the small wall-clock wrapper used by runtime code. Consensus
policy values still come from ``protocol_profile``; centralizing the wrapper keeps
future block timestamp policy changes out of the executor facade.
"""

import time
from typing import Any

from weall.runtime.protocol_profile import (
    runtime_clock_skew_warn_ms,
    runtime_max_block_future_drift_ms,
    runtime_startup_clock_hard_fail_ms,
)


def now_ms() -> int:
    return int(time.time() * 1000)


def max_block_future_drift_ms() -> int:
    return runtime_max_block_future_drift_ms()


def max_block_time_advance_ms() -> int:
    return max_block_future_drift_ms()


def clock_skew_warn_ms() -> int:
    return runtime_clock_skew_warn_ms()


def startup_clock_hard_fail_ms() -> int:
    return runtime_startup_clock_hard_fail_ms()


# Backward-compatible private name used by staged extraction modules.
_now_ms = now_ms
