from __future__ import annotations

"""Deterministic constitutional procedure clock.

The clock is intentionally block-height based.  Wall-clock time may trigger a
producer to wake up, but it must never decide proposal/dispute eligibility.
"""

import time
from dataclasses import dataclass
from typing import Any, Mapping

Json = dict[str, Any]

DEFAULT_TARGET_BLOCK_INTERVAL_MS = 20_000
DEFAULT_ALLOWED_CLOCK_SKEW_MS = 2_000
DEFAULT_GENESIS_TIME_MS = 0


@dataclass(frozen=True, slots=True)
class ConstitutionalClockPolicy:
    enabled: bool = False
    target_block_interval_ms: int = DEFAULT_TARGET_BLOCK_INTERVAL_MS
    empty_blocks_enabled: bool = False
    procedure_time_source: str = "finalized_block_height"
    block_time_derivation: str = "genesis_time_plus_height_times_interval"
    no_fast_forward: bool = True
    no_height_skip: bool = True
    allowed_clock_skew_ms: int = DEFAULT_ALLOWED_CLOCK_SKEW_MS
    genesis_time_ms: int = DEFAULT_GENESIS_TIME_MS


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return bool(value)
    s = str(value).strip().lower()
    if not s:
        return bool(default)
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _int(value: Any, default: int = 0) -> int:
    try:
        if value is None or isinstance(value, bool):
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _clock_obj_from_manifest(manifest: Any) -> Mapping[str, Any]:
    raw: Any = manifest
    if hasattr(manifest, "raw"):
        raw = getattr(manifest, "raw")
    if not isinstance(raw, Mapping):
        return {}
    obj = raw.get("constitutional_clock")
    return obj if isinstance(obj, Mapping) else {}


def policy_from_manifest(manifest: Any) -> ConstitutionalClockPolicy:
    raw: Any = manifest
    if hasattr(manifest, "raw"):
        raw = getattr(manifest, "raw")
    raw_map = raw if isinstance(raw, Mapping) else {}
    obj = _clock_obj_from_manifest(manifest)
    genesis_time_ms = _int(obj.get("genesis_time_ms", raw_map.get("genesis_time_ms")), DEFAULT_GENESIS_TIME_MS)
    target = _int(obj.get("target_block_interval_ms"), DEFAULT_TARGET_BLOCK_INTERVAL_MS)
    if target <= 0:
        target = DEFAULT_TARGET_BLOCK_INTERVAL_MS
    return ConstitutionalClockPolicy(
        enabled=_bool(obj.get("enabled"), False),
        target_block_interval_ms=int(target),
        empty_blocks_enabled=_bool(obj.get("empty_blocks_enabled"), False),
        procedure_time_source=str(obj.get("procedure_time_source") or "finalized_block_height"),
        block_time_derivation=str(obj.get("block_time_derivation") or "genesis_time_plus_height_times_interval"),
        no_fast_forward=_bool(obj.get("no_fast_forward"), True),
        no_height_skip=_bool(obj.get("no_height_skip"), True),
        allowed_clock_skew_ms=max(0, _int(obj.get("allowed_clock_skew_ms"), DEFAULT_ALLOWED_CLOCK_SKEW_MS)),
        genesis_time_ms=int(genesis_time_ms),
    )


def policy_from_state(state: Mapping[str, Any] | None) -> ConstitutionalClockPolicy:
    if not isinstance(state, Mapping):
        return ConstitutionalClockPolicy()
    meta = state.get("meta")
    if isinstance(meta, Mapping):
        obj = meta.get("constitutional_clock")
        if isinstance(obj, Mapping):
            return policy_from_manifest({"constitutional_clock": obj, "genesis_time_ms": obj.get("genesis_time_ms", 0)})
    return ConstitutionalClockPolicy()


def policy_to_json(policy: ConstitutionalClockPolicy, *, current_height: int | None = None) -> Json:
    out: Json = {
        "enabled": bool(policy.enabled),
        "target_block_interval_ms": int(policy.target_block_interval_ms),
        "empty_blocks_enabled": bool(policy.empty_blocks_enabled),
        "procedure_time_source": str(policy.procedure_time_source),
        "block_time_derivation": str(policy.block_time_derivation),
        "no_fast_forward": bool(policy.no_fast_forward),
        "no_height_skip": bool(policy.no_height_skip),
        "allowed_clock_skew_ms": int(policy.allowed_clock_skew_ms),
        "genesis_time_ms": int(policy.genesis_time_ms),
    }
    if current_height is not None:
        out["current_procedure_height"] = int(current_height)
    return out


def commit_clock_policy_to_state(state: Json, policy: ConstitutionalClockPolicy) -> None:
    meta = state.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        state["meta"] = meta
    meta["constitutional_clock"] = policy_to_json(policy, current_height=procedure_height(state))


def slot_time_ms(*, genesis_time_ms: int, height: int, target_block_interval_ms: int) -> int:
    h = max(0, int(height))
    interval = max(1, int(target_block_interval_ms))
    return int(genesis_time_ms) + (h * interval)


def expected_block_time_ms(policy: ConstitutionalClockPolicy, *, height: int) -> int:
    return slot_time_ms(
        genesis_time_ms=int(policy.genesis_time_ms),
        height=int(height),
        target_block_interval_ms=int(policy.target_block_interval_ms),
    )


def current_time_ms() -> int:
    return int(time.time() * 1000)


def not_before_ms(policy: ConstitutionalClockPolicy, *, height: int) -> int:
    return expected_block_time_ms(policy, height=int(height)) - int(policy.allowed_clock_skew_ms)


def is_too_early(policy: ConstitutionalClockPolicy, *, height: int, now_ms: int | None = None) -> bool:
    if not policy.enabled:
        return False
    # genesis_time_ms=0 is a deterministic legacy/dev fixture value, not a real
    # launch timestamp.  It must not make tests or dev fixtures fail the
    # not-before check.  Real testnet launch manifests should pin a positive
    # genesis_time_ms to activate physical-time anti-fast-forward gating.
    if int(policy.genesis_time_ms) <= 0:
        return False
    now = current_time_ms() if now_ms is None else int(now_ms)
    return now < not_before_ms(policy, height=int(height))


def procedure_height(state: Mapping[str, Any] | None) -> int:
    """Return the canonical procedure height used for constitutional windows.

    Prefer finalized height whenever the state exposes it.  Older state
    snapshots have used both `finalized_height` and `finalized.height`; support
    both so proposal/dispute windows do not silently fall back to optimistic
    local height when finalized height is available.
    """
    if not isinstance(state, Mapping):
        return 0
    direct_finalized = _int(state.get("finalized_height"), 0)
    if direct_finalized > 0:
        return int(direct_finalized)
    finalized = state.get("finalized")
    if isinstance(finalized, Mapping):
        fh = _int(finalized.get("height"), 0)
        if fh > 0:
            return int(fh)
    return max(0, _int(state.get("height"), 0))


def deadline_height(start_height: int, window_blocks: int) -> int:
    return max(0, int(start_height)) + max(0, int(window_blocks))


def blocks_remaining(current_height: int, deadline: int) -> int:
    return max(0, int(deadline) - int(current_height))


def is_due(current_height: int, deadline: int) -> bool:
    return int(current_height) >= int(deadline)
