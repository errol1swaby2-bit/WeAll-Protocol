"""Read-only reputation-penalty origin review: observations, never authorization.

A SYSTEM queue identifier proves consistency with the queue in a supplied
snapshot, not that an approved dispute generated the queue item. Historical
blocks and the snapshot are caller-supplied and not independently finalized.
This module MUST NOT be imported by consensus, schedulers or appliers.
A positive source match is evidence for investigation, never a ban permit.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.runtime.block_commitment_validation import validate_complete_block_commitments
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    EPOCH_FINALITY_SINGLE_TX_CHILDREN,
    validate_same_block_single_tx_lineage,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope

SCHEMA = "weall.review-only.reputation-delta-origin.v0"
STATUS = "BLOCKED_UNAUTHENTICATED_REPUTATION_PENALTY_ORIGIN"

Json = dict[str, Any]


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _height(value: Any) -> bool:
    return type(value) is int and value >= 0


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _parent_candidates(
    blocks: Any, parent_queue_id: str
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Find only SYSTEM DISPUTE_RESOLVE records with exact queue-origin keys.

    Do not infer a historical producer from a human-written parent string,
    same-block TxType, case ID, or arbitrary fallback tx:SYSTEM:<nonce> label.
    """
    if not isinstance(blocks, (list, tuple)) or not parent_queue_id:
        return []
    found: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for block in blocks:
        b = _map(block)
        txs = b.get("txs")
        if not isinstance(txs, list):
            continue
        for tx in txs:
            t = _map(tx)
            if (
                t.get("tx_type") == "DISPUTE_RESOLVE"
                and t.get("system") is True
                and _str(_map(t.get("payload")).get("_system_queue_id")) == parent_queue_id
            ):
                found.append((b, t))
    return found


def review_reputation_delta_origin(
    *,
    pre_state: Any,
    delta: Any,
    tx_index: Any,
    supplied_history_blocks: Any = (),
) -> Json:
    """Inventory alleged causal links without approving a penalty or ban.

    The function does not look up network trust roots, signatures, validator QCs,
    historical replay, or constitutional appeals. All supplied data is untrusted.
    """
    state = _map(pre_state)
    d = _map(delta)
    payload = _map(d.get("payload"))
    chain_id = _str(state.get("chain_id"))
    height = state.get("height")
    due = height + 1 if _height(height) else -1
    parent_ref = _str(d.get("parent"))
    envelope: TxEnvelope | None = None
    if (
        d.get("tx_type") == "REPUTATION_DELTA_APPLY"
        and d.get("system") is True
        and _str(d.get("signer"))
        and isinstance(d.get("payload"), dict)
    ):
        try:
            envelope = TxEnvelope.from_json(dict(d))
        except (TypeError, ValueError, OverflowError):
            envelope = None

    queue_bound = False
    optional_same_block_lineage_valid = False
    if envelope is not None and due > 0 and tx_index is not None:
        try:
            queue_bound, _ = validate_system_tx_queue_binding(
                dict(state),
                tx_index,
                envelope,
                next_height=due,
                phase="post",
            )
            optional_same_block_lineage_valid, _ = validate_same_block_single_tx_lineage(
                tx_index,
                envelope,
                prior_txs=[],
                required_child_tx_types=EPOCH_FINALITY_SINGLE_TX_CHILDREN,
            )
        except (TypeError, ValueError, KeyError, RuntimeError):
            queue_bound = False
            optional_same_block_lineage_valid = False

    candidates = _parent_candidates(supplied_history_blocks, parent_ref)
    single = len(candidates) == 1
    block, parent_tx = candidates[0] if single else ({}, {})
    parent_payload = _map(parent_tx.get("payload"))
    tx_id = _str(parent_tx.get("tx_id"))
    receipts = block.get("receipts")
    success_receipts = (
        [
            receipt
            for receipt in receipts
            if isinstance(receipt, Mapping)
            and receipt.get("tx_id") == tx_id
            and receipt.get("tx_type") == "DISPUTE_RESOLVE"
            and receipt.get("ok") is True
        ]
        if isinstance(receipts, list) and tx_id
        else []
    )
    block_self_committed = False
    if single and chain_id:
        try:
            valid, _why, binding = validate_complete_block_commitments(
                block=dict(block), chain_id=chain_id
            )
            block_self_committed = bool(valid and binding is not None)
        except (TypeError, ValueError, OverflowError, KeyError):
            block_self_committed = False

    alleged_dispute_id = _str(payload.get("dispute_id"))
    parent_dispute_id = _str(parent_payload.get("dispute_id"))
    observations: dict[str, bool] = {
        "canonical_system_reputation_delta_shape": envelope is not None,
        "receipt_queue_binding_matches_supplied_prestate": bool(queue_bound),
        "receipt_same_block_lineage_shape_valid": bool(optional_same_block_lineage_valid),
        "parent_queue_reference_present": bool(parent_ref),
        "exactly_one_parent_resolution_in_supplied_history": bool(single),
        "alleged_parent_resolution_precedes_receipt": bool(
            single
            and _height(block.get("height"))
            and _height(height)
            and block["height"] <= height
        ),
        "alleged_parent_success_receipt_unique": len(success_receipts) == 1,
        "alleged_dispute_id_bound_to_parent": bool(
            single and alleged_dispute_id and alleged_dispute_id == parent_dispute_id
        ),
        "alleged_parent_block_self_commitments_valid": bool(block_self_committed),
    }
    blockers = [key for key, observed in observations.items() if not observed]
    blockers.extend(
        (
            "supplied_prestate_not_independently_verified_as_committed",
            "supplied_historical_blocks_not_authenticated_as_finalized_chain",
            "dispute_to_reputation_queue_producer_not_authenticated",
            "juror_verdict_severity_and_appeal_authority_unreviewed",
            "historical_replay_and_v2_semantic_approval_pending",
        )
    )
    return {
        "schema": SCHEMA,
        "status": STATUS,
        "observations": observations,
        "parent_resolution_candidates": len(candidates),
        "blocking_reasons": blockers,
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_enqueue_reputation_delta": False,
        "may_ban_account": False,
    }


def review_persisted_reputation_delta_origin(
    *,
    executor: Any,
    delta: Any,
    tx_index: Any,
    max_history_blocks: int = 64,
) -> Json:
    """Read a bounded local block history; never equate SQLite with BFT finality.

    Requires only the executor's read_state/get_block_by_height read interfaces.
    The executor (or a substituted reader) and its local SQLite files are not
    trusted network anchors, even when all stored block commitments agree.
    """
    if type(max_history_blocks) is not int or not 1 <= max_history_blocks <= 256:
        raise ValueError("max_history_blocks_out_of_range")

    state_error = ""
    try:
        observed_state = executor.read_state()
        if not isinstance(observed_state, dict):
            raise ValueError("read_state_not_object")
        state = observed_state
    except (AttributeError, OSError, TypeError, ValueError, RuntimeError) as exc:
        state = {}
        state_error = f"state_read_failed:{type(exc).__name__}"

    chain_id = _str(state.get("chain_id"))
    height = state.get("height")
    height_ok = _height(height)
    highest = height if height_ok else 0
    first = max(1, highest - max_history_blocks + 1) if highest else 0
    history: list[Mapping[str, Any]] = []
    bindings: list[Any] = []
    errors: list[str] = []
    full_window_read = height_ok and not state_error

    if not height_ok:
        errors.append("prestate_height_invalid")
        full_window_read = False
    if not chain_id:
        errors.append("prestate_chain_id_missing")
        full_window_read = False
    if chain_id and _str(getattr(executor, "chain_id", None)) != chain_id:
        errors.append("prestate_executor_chain_id_mismatch")
        full_window_read = False
    if state_error:
        errors.append(state_error)

    if full_window_read and highest > 0:
        for at in range(first, highest + 1):
            try:
                block = executor.get_block_by_height(at)
            except (AttributeError, OSError, TypeError, ValueError, RuntimeError) as exc:
                errors.append(f"block_read_failed:{at}:{type(exc).__name__}")
                full_window_read = False
                break
            if not isinstance(block, dict) or block.get("height") != at:
                errors.append(f"missing_or_wrong_height_block:{at}")
                full_window_read = False
                break
            try:
                ok, reason, binding = validate_complete_block_commitments(
                    block=block, chain_id=chain_id
                )
            except (TypeError, ValueError, KeyError, OverflowError) as exc:
                errors.append(f"block_commitment_error:{at}:{type(exc).__name__}")
                full_window_read = False
                break
            if not ok or binding is None:
                errors.append(f"block_commitment_invalid:{at}:{reason}")
                full_window_read = False
                break
            history.append(block)
            bindings.append(binding)

    adjacent_links_valid = bool(full_window_read and history)
    if adjacent_links_valid:
        for next_block, previous_binding in zip(history[1:], bindings, strict=False):
            if (
                next_block.get("prev_block_id") != previous_binding.block_id
                or _str(next_block.get("prev_block_hash")) != previous_binding.block_hash
            ):
                adjacent_links_valid = False
                errors.append(f"adjacent_block_link_mismatch:{next_block.get('height')}")
                break

    tip_matches = bool(
        full_window_read
        and history
        and _str(state.get("tip")) == bindings[-1].block_id
        and _str(state.get("tip_hash")) == bindings[-1].block_hash
    )
    if highest > 0 and full_window_read and not tip_matches:
        errors.append("persisted_tip_commitment_mismatch")
    if highest == 0:
        tip_matches = bool(full_window_read and not _str(state.get("tip")))
        adjacent_links_valid = bool(full_window_read)

    # A canonical block commits to the *post-apply* state root, not merely
    # its own hash or the stored ledger tip. Recompute against the persisted
    # snapshot to detect changed account/reputation state behind intact block
    # rows. This is still local consistency, never authenticated BFT finality.
    snapshot_root_matches_tip = False
    if full_window_read and history and adjacent_links_valid and tip_matches:
        declared_root = _str(_map(history[-1].get("header")).get("state_root"))
        if not declared_root:
            errors.append("persisted_tip_state_root_missing")
        else:
            try:
                snapshot_root_matches_tip = compute_state_root(state) == declared_root
            except (TypeError, ValueError, OverflowError) as exc:
                errors.append(
                    f"persisted_state_root_recompute_failed:{type(exc).__name__}"
                )
            if not snapshot_root_matches_tip and not any(
                name.startswith("persisted_state_root_recompute_failed:")
                for name in errors
            ):
                errors.append("persisted_snapshot_state_root_mismatch")

    result = review_reputation_delta_origin(
        pre_state=state,
        delta=delta,
        tx_index=tx_index,
        supplied_history_blocks=history if full_window_read else (),
    )
    parent_candidates = _parent_candidates(
        history if full_window_read else (), _str(_map(delta).get("parent"))
    )
    single_parent_height = (
        _map(parent_candidates[0][0]).get("height") if len(parent_candidates) == 1 else None
    )
    finalized = _map(state.get("finalized"))
    recorded_finalized_covers_parent = bool(
        _height(single_parent_height)
        and _height(finalized.get("height"))
        and finalized["height"] >= single_parent_height
    )
    observations = {
        "local_state_readable_and_chain_id_matches": bool(
            height_ok
            and chain_id
            and not state_error
            and "prestate_executor_chain_id_mismatch" not in errors
        ),
        "bounded_local_history_available_and_self_bound": bool(
            full_window_read and (highest == 0 or len(history) == highest - first + 1)
        ),
        "adjacent_local_history_parent_links_match": bool(adjacent_links_valid),
        "local_state_tip_matches_last_stored_block": bool(tip_matches),
        "persisted_snapshot_root_matches_committed_tip_state_root": bool(
            snapshot_root_matches_tip
        ),
        "local_history_scanned_from_height_one": bool(
            full_window_read and highest > 0 and first == 1
        ),
        "local_finalized_height_claim_covers_alleged_parent": recorded_finalized_covers_parent,
    }
    result["persisted_history_observations"] = observations
    result["persisted_history_range"] = {
        "first_height": first,
        "last_height": highest,
        "blocks_examined": len(history),
        "limit": max_history_blocks,
    }
    result["persisted_history_errors"] = errors
    result["blocking_reasons"].extend(
        ["local_executor_history_is_not_independent_network_finality"]
        + [f"persisted_history:{name}" for name, observed in observations.items() if not observed]
        + errors
    )
    return result


__all__ = [
    "SCHEMA",
    "STATUS",
    "review_reputation_delta_origin",
    "review_persisted_reputation_delta_origin",
]
