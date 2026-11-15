"""Read-only reputation-penalty origin review: observations, never authorization.

A SYSTEM queue identifier proves consistency with the queue in a supplied
snapshot, not that an approved dispute generated the queue item. Historical
blocks and the snapshot are caller-supplied and not independently finalized.
This module MUST NOT be imported by consensus, schedulers or appliers.
A positive source match is evidence for investigation, never a ban permit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from weall.runtime.block_commitment_validation import validate_complete_block_commitments
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


__all__ = [
    "SCHEMA",
    "STATUS",
    "review_reputation_delta_origin",
]
