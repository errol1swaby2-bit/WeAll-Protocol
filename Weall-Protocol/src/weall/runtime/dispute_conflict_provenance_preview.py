"""Read-only candidate evidence for a post-assignment group-officer conflict.

Input snapshots and a purported block are UNTRUSTED. The checks here can show
that the supplied data is internally consistent, but cannot authenticate a
signature, prove independently finalized history, or authorize a recusal,
reputation waiver, substitute appointment, or governance activation.

Production block admission plus independent replay must be demonstrated
separately before treating an observation as chain-derived evidence.
"""

from __future__ import annotations

from typing import Any

from weall.runtime.apply.dispute import (
    _dispute_conflict_account_ids,
    _identity_variants,
    _resolve_account_identity,
)
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]


def _same_account(left: Any, right: Any) -> bool:
    return bool(set(_identity_variants(left)).intersection(_identity_variants(right)))


def _group_moderators(state: Json, group_id: str) -> list[str] | None:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return None
    groups = roles.get("groups_by_id")
    if not isinstance(groups, dict):
        return None
    group = groups.get(group_id)
    if not isinstance(group, dict):
        return None
    moderators = group.get("moderators")
    if not isinstance(moderators, list) or any(
        not isinstance(value, str) or not value.strip() for value in moderators
    ):
        return None
    return moderators


def preview_post_assignment_group_conflict(
    before: Json,
    after: Json,
    block: Json,
    *,
    dispute_id: str,
    juror: str,
) -> Json:
    """Inspect supplied adjacent snapshots, not their external authenticity.

    The returned observation is never a replacement for production block
    signature/admission verification, BFT finality or replay from trusted
    genesis. It never mutates inputs or infers conflict intent.
    """

    result: Json = {
        "status": "blocked_unverified_input",
        "authorized": False,
        "dispute_id": dispute_id,
        "juror": juror,
        "observed_introduction_height": None,
        "transaction_id": None,
        "transaction_type": "GROUP_MODERATORS_SET",
        "signature_present": False,
        "receipt_successful": False,
        "state_roots_match_supplied_block": False,
        "independent_replay_verified": False,
        "bft_finality_verified": False,
        "authenticated_conflict_provenance_verified": False,
        "recusal_authorized": False,
        "reputation_penalty_waiver_authorized": False,
    }
    if not all(isinstance(item, dict) for item in (before, after, block)):
        return result
    prior_height = before.get("height")
    later_height = after.get("height")
    header = block.get("header")
    if (
        type(prior_height) is not int
        or type(later_height) is not int
        or prior_height < 0
        or later_height != prior_height + 1
        or not isinstance(header, dict)
        or header.get("height") != later_height
        or block.get("height") != later_height
    ):
        result["status"] = "blocked_nonadjacent_height"
        return result
    if compute_state_root(after) != header.get("state_root"):
        result["status"] = "blocked_state_root_mismatch"
        return result
    result["state_roots_match_supplied_block"] = True

    before_cases = before.get("disputes_by_id")
    after_cases = after.get("disputes_by_id")
    previous = before_cases.get(dispute_id) if isinstance(before_cases, dict) else None
    current = after_cases.get(dispute_id) if isinstance(after_cases, dict) else None
    if not isinstance(previous, dict) or not isinstance(current, dict):
        result["status"] = "blocked_missing_dispute"
        return result
    original = previous.get("assigned_jurors")
    following = current.get("assigned_jurors")
    if (
        not isinstance(original, list)
        or not original
        or not isinstance(following, list)
        or original != following
        or previous.get("panel_commitment") != current.get("panel_commitment")
        or not isinstance(previous.get("panel_commitment"), str)
        or len(previous["panel_commitment"]) != 64
        or previous.get("panel_status") != "assigned"
        or current.get("panel_status") != "assigned"
        or previous.get("panel_round") != current.get("panel_round")
        or previous.get("stage") != "juror_review"
        or current.get("stage") != "juror_review"
        or not any(_same_account(member, juror) for member in original)
    ):
        result["status"] = "blocked_panel_snapshot_changed"
        return result
    opened = previous.get("opened_at_height")
    if type(opened) is not int or opened >= later_height:
        result["status"] = "blocked_missing_prior_assignment_height"
        return result

    before_conflicts = _dispute_conflict_account_ids(before, previous)
    after_conflicts = _dispute_conflict_account_ids(after, current)
    if any(_same_account(juror, value) for value in before_conflicts):
        result["status"] = "blocked_preexisting_material_conflict"
        return result
    if not any(_same_account(juror, value) for value in after_conflicts):
        result["status"] = "blocked_no_new_material_conflict"
        return result

    target_type = previous.get("target_type")
    group_id = previous.get("target_id")
    if target_type != "group" or not isinstance(group_id, str) or not group_id:
        result["status"] = "blocked_unsupported_conflict_origin"
        return result
    if current.get("target_type") != "group" or current.get("target_id") != group_id:
        result["status"] = "blocked_target_changed"
        return result
    prior_moderators = _group_moderators(before, group_id)
    current_moderators = _group_moderators(after, group_id)
    if (
        prior_moderators is None
        or current_moderators is None
        or any(_same_account(juror, member) for member in prior_moderators)
        or not any(_same_account(juror, member) for member in current_moderators)
    ):
        result["status"] = "blocked_no_moderator_transition"
        return result

    txs = block.get("txs")
    receipts = block.get("receipts")
    tx_ids = header.get("tx_ids")
    if (
        not isinstance(txs, list)
        or not isinstance(receipts, list)
        or not isinstance(tx_ids, list)
    ):
        result["status"] = "blocked_missing_block_transaction_evidence"
        return result

    matching: list[Json] = []
    for tx in txs:
        if not isinstance(tx, dict) or tx.get("tx_type") != "GROUP_MODERATORS_SET":
            continue
        payload = tx.get("payload")
        if (
            not isinstance(payload, dict)
            or payload.get("group_id") != group_id
            or payload.get("moderators") != current_moderators
            or tx.get("system") is True
        ):
            continue
        signer = tx.get("signer")
        signature = tx.get("sig") or tx.get("signature")
        tx_id = tx.get("tx_id")
        if (
            not isinstance(signer, str)
            or not signer
            or not isinstance(signature, str)
            or not signature
            or not isinstance(tx_id, str)
            or not tx_id
        ):
            continue
        matching.append(tx)
    if len(matching) != 1:
        result["status"] = "blocked_unsigned_or_ambiguous_transaction"
        return result
    tx = matching[0]
    tx_id = tx["tx_id"]
    if tx_ids.count(tx_id) != 1:
        result["status"] = "blocked_transaction_header_binding"
        return result
    matching_receipts = [
        entry
        for entry in receipts
        if isinstance(entry, dict)
        and entry.get("tx_id") == tx_id
        and entry.get("tx_type") == "GROUP_MODERATORS_SET"
        and entry.get("signer") == tx["signer"]
        and entry.get("ok") is True
    ]
    if len(matching_receipts) != 1:
        result["status"] = "blocked_missing_successful_receipt"
        return result
    result.update(
        {
            "status": "candidate_transition_requires_independent_replay",
            "observed_introduction_height": later_height,
            "transaction_id": tx_id,
            "signature_present": True,
            "receipt_successful": True,
        }
    )
    return result
