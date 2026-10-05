from __future__ import annotations

import hashlib
import json
from typing import Any, Final

Json = dict[str, Any]

BLOCK_HISTORY_CHECKPOINT_VERSION: Final[int] = 1
BLOCK_HISTORY_CHECKPOINT_DOMAIN: Final[str] = "weall.consensus-block-history.v1"
BLOCK_HISTORY_CHECKPOINT_KEY: Final[str] = "block_history_checkpoint"
CONSENSUS_BLOCK_HISTORY_META_KEY: Final[str] = "consensus_block_history_max_records"
DEFAULT_CONSENSUS_BLOCK_HISTORY_MAX_RECORDS: Final[int] = 10_000
MIN_CONSENSUS_BLOCK_HISTORY_MAX_RECORDS: Final[int] = 3


class BlockHistoryRetentionError(RuntimeError):
    """Canonical ancestry cannot be compacted without a safe finalized boundary."""


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda x: str(x))}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def consensus_block_history_max_records(state: Json) -> int:
    """Return the root-bound live ancestry ceiling.

    The protocol ceiling is 10,000 records, matching the existing durable block
    history horizon. A committed meta selector may tighten this value for a future
    profile or deterministic test fixture, but cannot enlarge the protocol ceiling.
    """

    meta = state.get("meta") if isinstance(state, dict) else None
    raw = meta.get(CONSENSUS_BLOCK_HISTORY_META_KEY) if isinstance(meta, dict) else None
    if raw is None:
        return int(DEFAULT_CONSENSUS_BLOCK_HISTORY_MAX_RECORDS)
    try:
        value = int(raw)
    except Exception as exc:
        raise BlockHistoryRetentionError("block_history_limit_not_integer") from exc
    if value < int(MIN_CONSENSUS_BLOCK_HISTORY_MAX_RECORDS):
        raise BlockHistoryRetentionError("block_history_limit_below_safety_minimum")
    if value > int(DEFAULT_CONSENSUS_BLOCK_HISTORY_MAX_RECORDS):
        raise BlockHistoryRetentionError("block_history_limit_exceeds_protocol_ceiling")
    return int(value)


def _block_record_height(block_id: str, record: Any) -> int:
    if not isinstance(record, dict):
        raise BlockHistoryRetentionError(f"block_history_record_not_object:{block_id}")
    try:
        height = int(record.get("height") or 0)
    except Exception as exc:
        raise BlockHistoryRetentionError(f"block_history_height_invalid:{block_id}") from exc
    if height <= 0:
        raise BlockHistoryRetentionError(f"block_history_height_nonpositive:{block_id}")
    return int(height)


def _block_parent(record: Any) -> str:
    if not isinstance(record, dict):
        return ""
    return str(record.get("prev_block_id") or record.get("prev") or "").strip()


def _canonical_safety_anchor(state: Json) -> tuple[str, int] | None:
    """Return the root-visible finalized anchor, never node-local BFT metadata."""

    finalized = state.get("finalized")
    if not isinstance(finalized, dict):
        return None
    block_id = str(finalized.get("block_id") or "").strip()
    try:
        height = int(finalized.get("height") or 0)
    except Exception as exc:
        raise BlockHistoryRetentionError("block_history_finalized_height_invalid") from exc
    if not block_id and height <= 0:
        return None
    if not block_id or height <= 0:
        raise BlockHistoryRetentionError("block_history_finalized_anchor_incomplete")
    return block_id, int(height)


def _validated_checkpoint(state: Json) -> dict[str, Any] | None:
    raw = state.get(BLOCK_HISTORY_CHECKPOINT_KEY)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise BlockHistoryRetentionError("block_history_checkpoint_not_object")
    try:
        version = int(raw.get("version") or 0)
        records_committed = int(raw.get("records_committed") or 0)
        through_height = int(raw.get("through_height") or 0)
    except Exception as exc:
        raise BlockHistoryRetentionError("block_history_checkpoint_integer_invalid") from exc
    root = str(raw.get("root") or "").strip().lower()
    through_block_id = str(raw.get("through_block_id") or "").strip()
    if version != int(BLOCK_HISTORY_CHECKPOINT_VERSION):
        raise BlockHistoryRetentionError("block_history_checkpoint_version_invalid")
    if records_committed <= 0 or through_height <= 0 or not through_block_id:
        raise BlockHistoryRetentionError("block_history_checkpoint_position_invalid")
    if records_committed != through_height:
        raise BlockHistoryRetentionError("block_history_checkpoint_count_height_mismatch")
    if len(root) != 64:
        raise BlockHistoryRetentionError("block_history_checkpoint_root_invalid")
    try:
        int(root, 16)
    except Exception as exc:
        raise BlockHistoryRetentionError("block_history_checkpoint_root_invalid") from exc
    return {
        "version": int(version),
        "records_committed": int(records_committed),
        "through_height": int(through_height),
        "through_block_id": through_block_id,
        "root": root,
    }


def _ordered_linear_block_history(
    blocks: dict[str, Any],
    *,
    checkpoint: dict[str, Any] | None,
) -> list[tuple[str, dict[str, Any], int]]:
    ordered: list[tuple[str, dict[str, Any], int]] = []
    for raw_block_id, raw_record in blocks.items():
        block_id = str(raw_block_id or "").strip()
        if not block_id:
            raise BlockHistoryRetentionError("block_history_empty_block_id")
        if not isinstance(raw_record, dict):
            raise BlockHistoryRetentionError(f"block_history_record_not_object:{block_id}")
        ordered.append((block_id, raw_record, _block_record_height(block_id, raw_record)))
    ordered.sort(key=lambda item: (int(item[2]), str(item[0])))

    heights = [int(item[2]) for item in ordered]
    if len(set(heights)) != len(heights):
        raise BlockHistoryRetentionError("block_history_duplicate_height")

    if not ordered:
        return ordered

    if checkpoint is None:
        first_block_id, first_record, first_height = ordered[0]
        if int(first_height) != 1 or _block_parent(first_record):
            raise BlockHistoryRetentionError(
                f"block_history_uncheckpointed_prefix_invalid:{first_block_id}"
            )
    else:
        first_block_id, first_record, first_height = ordered[0]
        expected_height = int(checkpoint["through_height"]) + 1
        if int(first_height) != int(expected_height):
            raise BlockHistoryRetentionError(
                f"block_history_checkpoint_height_gap:{first_block_id}"
            )
        if _block_parent(first_record) != str(checkpoint["through_block_id"]):
            raise BlockHistoryRetentionError(
                f"block_history_checkpoint_parent_mismatch:{first_block_id}"
            )

    previous_block_id = ""
    previous_height = 0
    for block_id, record, height in ordered:
        if previous_block_id:
            if int(height) != int(previous_height) + 1:
                raise BlockHistoryRetentionError(f"block_history_height_gap:{block_id}")
            if _block_parent(record) != previous_block_id:
                raise BlockHistoryRetentionError(f"block_history_parent_mismatch:{block_id}")
        previous_block_id = block_id
        previous_height = int(height)

    return ordered


def _extend_checkpoint(
    checkpoint: dict[str, Any] | None,
    pruned: list[tuple[str, dict[str, Any], int]],
) -> dict[str, Any]:
    prior_root = str((checkpoint or {}).get("root") or ("0" * 64)).strip().lower()
    prior_count = int((checkpoint or {}).get("records_committed") or 0)
    prior_height = int((checkpoint or {}).get("through_height") or 0)
    prior_block_id = str((checkpoint or {}).get("through_block_id") or "").strip()

    root = prior_root
    last_height = prior_height
    last_block_id = prior_block_id
    for block_id, record, height in pruned:
        expected_height = int(last_height) + 1
        if int(height) != int(expected_height):
            raise BlockHistoryRetentionError("block_history_checkpoint_noncontiguous_height")
        if _block_parent(record) != last_block_id:
            if int(last_height) > 0 or _block_parent(record):
                raise BlockHistoryRetentionError("block_history_checkpoint_noncontiguous_parent")
        payload = {
            "domain": BLOCK_HISTORY_CHECKPOINT_DOMAIN,
            "prior_root": root,
            "block_id": str(block_id),
            "record": _canonical(record),
        }
        encoded = json.dumps(
            _canonical(payload),
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        root = hashlib.sha256(encoded).hexdigest()
        last_height = int(height)
        last_block_id = str(block_id)

    return {
        "version": int(BLOCK_HISTORY_CHECKPOINT_VERSION),
        "records_committed": int(prior_count + len(pruned)),
        "through_height": int(last_height),
        "through_block_id": str(last_block_id),
        "root": str(root),
    }


def project_bounded_block_history_state(state: Json) -> Json:
    """Return a pure finite-history projection for application-state commitment.

    Once live canonical ancestry exceeds the protocol ceiling, compaction is
    permitted only behind the root-visible ``state["finalized"]`` anchor. Removed
    canonical history is represented by a constant-size rolling hash checkpoint.
    Node-local ``state["bft"]`` is deliberately ignored because it is excluded from
    the application state root and may differ across honest nodes.
    """

    if not isinstance(state, dict):
        raise BlockHistoryRetentionError("block_history_state_not_object")
    checkpoint = _validated_checkpoint(state)
    blocks_raw = state.get("blocks")
    if blocks_raw is None:
        return dict(state)
    if not isinstance(blocks_raw, dict):
        raise BlockHistoryRetentionError("block_history_blocks_not_object")

    limit = consensus_block_history_max_records(state)
    if len(blocks_raw) <= int(limit):
        return dict(state)

    finalized = _canonical_safety_anchor(state)
    if finalized is None:
        raise BlockHistoryRetentionError("block_history_compaction_requires_finalized_anchor")
    finalized_block_id, finalized_height = finalized

    ordered = _ordered_linear_block_history(blocks_raw, checkpoint=checkpoint)
    by_id = {block_id: (record, height) for block_id, record, height in ordered}
    finalized_record = by_id.get(finalized_block_id)
    if finalized_record is None:
        raise BlockHistoryRetentionError("block_history_finalized_anchor_not_live")
    if int(finalized_record[1]) != int(finalized_height):
        raise BlockHistoryRetentionError("block_history_finalized_height_mismatch")

    tip = str(state.get("tip") or "").strip()
    if not tip or tip != ordered[-1][0]:
        raise BlockHistoryRetentionError("block_history_tip_not_latest_live_record")

    prune_count = int(len(ordered) - int(limit))
    pruned = ordered[:prune_count]
    if any(int(height) >= int(finalized_height) for _block_id, _record, height in pruned):
        raise BlockHistoryRetentionError("block_history_window_exhausted_by_live_safety_ancestry")

    pruned_ids = {block_id for block_id, _record, _height in pruned}
    next_blocks = {key: value for key, value in blocks_raw.items() if str(key) not in pruned_ids}
    if len(next_blocks) > int(limit):
        raise BlockHistoryRetentionError("block_history_compaction_failed_to_bound_live_records")

    out = dict(state)
    out["blocks"] = next_blocks
    out[BLOCK_HISTORY_CHECKPOINT_KEY] = _extend_checkpoint(checkpoint, pruned)
    return out


def compact_bounded_block_history_in_place(state: Json) -> int:
    """Install the exact finite-history root projection in canonical live state."""

    before_raw = state.get("blocks") if isinstance(state, dict) else None
    before = len(before_raw) if isinstance(before_raw, dict) else 0
    projected = project_bounded_block_history_state(state)
    state["blocks"] = projected.get("blocks", {})
    if BLOCK_HISTORY_CHECKPOINT_KEY in projected:
        state[BLOCK_HISTORY_CHECKPOINT_KEY] = projected[BLOCK_HISTORY_CHECKPOINT_KEY]
    after_raw = state.get("blocks")
    after = len(after_raw) if isinstance(after_raw, dict) else 0
    return max(0, int(before - after))
