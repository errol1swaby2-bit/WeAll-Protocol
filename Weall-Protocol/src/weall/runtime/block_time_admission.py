from __future__ import annotations

"""Shared block-time admission checks.

Leader construction, follower replay, and BFT proposal admission must enforce the
same timestamp policy.  In constitutional-clock mode, the block timestamp is a
pure function of height and the pinned manifest clock policy.  In legacy/dev
mode, timestamps remain bounded by the committed chain-time floor.
"""

from dataclasses import dataclass
from typing import Any, Mapping

import os

from weall.runtime.chain_manifest import load_chain_manifest
from weall.runtime.constitutional_clock import (
    ConstitutionalClockPolicy,
    expected_block_time_ms,
    is_too_early,
    policy_from_manifest,
    policy_from_state,
)

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class BlockTimeVerdict:
    ok: bool
    code: str = ""
    reason: str = ""
    details: Json | None = None


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_str(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def has_material_block_timestamp(block: Mapping[str, Any] | None) -> bool:
    """Return whether a block/proposal carries a real timestamp field.

    Several legacy/unit BFT tests use logical proposal stubs that deliberately
    omit block_ts_ms and only exercise leader/view/finality logic. Full block
    replay still requires a positive timestamp; this helper lets BFT admission
    avoid changing those older logical-test error surfaces while enforcing
    timestamp policy whenever a concrete block timestamp is present.
    """

    if not isinstance(block, Mapping):
        return False
    if _as_int(block.get("block_ts_ms"), 0) > 0:
        return True
    header = block.get("header")
    return isinstance(header, Mapping) and _as_int(header.get("block_ts_ms"), 0) > 0


def _state_clock_policy(state: Mapping[str, Any] | None) -> ConstitutionalClockPolicy:
    try:
        return policy_from_state(state)
    except Exception:
        return ConstitutionalClockPolicy()


def runtime_block_clock_policy(
    *,
    state: Mapping[str, Any] | None = None,
    mode: str = "",
) -> ConstitutionalClockPolicy:
    """Return the consensus clock policy used for block timestamp checks.

    Prefer the pinned chain manifest because fresh genesis/follower states may
    not have committed meta["constitutional_clock"] yet.  Fall back to committed
    state metadata so tests and replay of older snapshots remain deterministic
    when no manifest is configured.
    """

    # Unsafe/dev compatibility: legacy timestamp-policy tests construct fresh
    # local executors with no committed constitutional clock metadata but with a
    # production manifest available on disk. In that mode, keep the historical
    # chain-floor timestamp contract unless state explicitly pins the
    # constitutional clock on. Production/testnet replay still uses the manifest
    # fallback and therefore remains fail-closed.
    state_policy = _state_clock_policy(state)
    if _env_bool("WEALL_UNSAFE_DEV", False) and not bool(state_policy.enabled):
        return state_policy

    manifest_policy = ConstitutionalClockPolicy()
    try:
        manifest = load_chain_manifest(required=False, mode=str(mode or ""))
        manifest_policy = policy_from_manifest(manifest)
    except Exception:
        manifest_policy = ConstitutionalClockPolicy()
    if bool(manifest_policy.enabled):
        return manifest_policy

    if bool(state_policy.enabled):
        return state_policy
    return manifest_policy


def validate_block_timestamp(
    *,
    state: Mapping[str, Any] | None = None,
    height: int,
    block_ts_ms: int,
    chain_floor_ms: int,
    max_block_time_advance_ms: int,
    mode: str = "",
    enforce_not_before: bool = False,
    now_ms: int | None = None,
) -> BlockTimeVerdict:
    """Validate a block timestamp with the active runtime clock policy.

    The returned ``code`` is suffix-only (for example
    ``not_constitutional_slot``). Callers keep their existing public error
    namespaces such as ``invalid_block_ts:*`` or ``bad_block:*``.
    """

    h = _as_int(height, 0)
    ts = _as_int(block_ts_ms, 0)
    floor = _as_int(chain_floor_ms, 0)
    max_advance = _as_int(max_block_time_advance_ms, 0)

    if h <= 0:
        return BlockTimeVerdict(False, "height", "height_must_be_positive", {"height": h})

    policy = runtime_block_clock_policy(state=state, mode=str(mode or ""))
    if bool(policy.enabled):
        if ts <= 0:
            return BlockTimeVerdict(False, "ts", "block_ts_ms_must_be_positive", {"block_ts_ms": ts})
        expected = expected_block_time_ms(policy, height=h)
        if int(ts) != int(expected):
            return BlockTimeVerdict(
                False,
                "not_constitutional_slot",
                "block_timestamp_must_equal_constitutional_slot",
                {"height": h, "block_ts_ms": ts, "expected_block_ts_ms": int(expected)},
            )
        if (
            bool(enforce_not_before)
            and int(getattr(policy, "genesis_time_ms", 0) or 0) > 0
            and is_too_early(policy, height=h, now_ms=now_ms)
        ):
            return BlockTimeVerdict(
                False,
                "before_constitutional_slot",
                "local_clock_before_constitutional_slot",
                {"height": h, "block_ts_ms": ts, "expected_block_ts_ms": int(expected)},
            )
        return BlockTimeVerdict(True, details={"clock_policy": "constitutional", "expected_block_ts_ms": int(expected)})

    successor_ts_ms = max(1, int(floor) + 1)
    if int(ts) < int(successor_ts_ms):
        return BlockTimeVerdict(
            False,
            "ts_before_chain_floor",
            "block_timestamp_before_chain_floor",
            {"block_ts_ms": ts, "chain_floor_ms": int(floor), "minimum_block_ts_ms": int(successor_ts_ms)},
        )
    if int(ts) > int(floor) + int(max_advance):
        return BlockTimeVerdict(
            False,
            "ts_beyond_chain_time_window",
            "block_timestamp_beyond_chain_time_window",
            {"block_ts_ms": ts, "chain_floor_ms": int(floor), "max_block_time_advance_ms": int(max_advance)},
        )
    return BlockTimeVerdict(True, details={"clock_policy": "legacy", "minimum_block_ts_ms": int(successor_ts_ms)})


def block_height_from_header(block: Mapping[str, Any] | None) -> int:
    if not isinstance(block, Mapping):
        return 0
    header = block.get("header") if isinstance(block.get("header"), Mapping) else {}
    return _as_int(header.get("height") or block.get("height"), 0)


def block_ts_from_header(block: Mapping[str, Any] | None) -> int:
    if not isinstance(block, Mapping):
        return 0
    header = block.get("header") if isinstance(block.get("header"), Mapping) else {}
    return _as_int(header.get("block_ts_ms") or block.get("block_ts_ms"), 0)


def chain_time_floor_ms_from_state(state: Mapping[str, Any] | None) -> int:
    if not isinstance(state, Mapping):
        return 0
    tip_ts = _as_int(state.get("tip_ts_ms"), 0)
    blocks = state.get("blocks")
    latest = int(tip_ts)
    if isinstance(blocks, Mapping):
        for rec in blocks.values():
            if isinstance(rec, Mapping):
                latest = max(latest, _as_int(rec.get("block_ts_ms"), 0))
    return max(0, int(latest))


__all__ = [
    "BlockTimeVerdict",
    "block_height_from_header",
    "block_ts_from_header",
    "has_material_block_timestamp",
    "chain_time_floor_ms_from_state",
    "runtime_block_clock_policy",
    "validate_block_timestamp",
]
