"""Read-only signed BFT finality candidate review for reputation provenance.

Inputs, including the purported validator registry and QC triplet, are supplied
by the caller. Cryptographic self-consistency is NOT independent validator-key
custody, production network finality, historical replay, case authorization, or
constitutional permission to apply a reputation penalty.

This tool MUST NOT be imported by consensus, state appliers, or schedulers.
The deliberately strict same-epoch three-QC triplet is an evidence review
profile, not a change to production HotStuff commit rules.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.bft_hotstuff import (
    qc_from_json,
    quorum_threshold,
    validator_set_hash,
    verify_qc,
)
from weall.runtime.block_commitment_validation import validate_complete_block_commitments

SCHEMA = "weall.review-only.reputation-parent-qc-three-chain.v0"
STATUS = "BLOCKED_INDEPENDENT_FINALITY_AND_CONSTITUTIONAL_REVIEW"
MAX_VALIDATORS = 128

Json = dict[str, Any]


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _valid_height(value: Any) -> bool:
    return type(value) is int and value > 0


def _pinned_authority(
    candidate: Any,
) -> tuple[list[str], dict[str, str], int, str, str]:
    """Check a caller-supplied registry's shape; NEVER authenticate its origin."""
    item = _map(candidate)
    validators = item.get("validators")
    pubkeys = item.get("validator_pubkeys")
    epoch = item.get("validator_epoch")
    advertised_hash = _s(item.get("validator_set_hash"))
    if not isinstance(validators, list) or not 4 <= len(validators) <= MAX_VALIDATORS:
        return [], {}, 0, "", "validator_registry_size_invalid"
    if any(not isinstance(value, str) or not value.strip() for value in validators):
        return [], {}, 0, "", "validator_registry_identity_invalid"
    if len(set(validators)) != len(validators):
        return [], {}, 0, "", "validator_registry_duplicate_signer"
    if type(epoch) is not int or epoch < 0:
        return [], {}, 0, "", "validator_registry_epoch_invalid"
    if not isinstance(pubkeys, dict) or set(pubkeys) != set(validators):
        return [], {}, 0, "", "validator_registry_pubkeys_incomplete"
    for value in pubkeys.values():
        if not isinstance(value, str) or not 32 <= len(value) <= 8192:
            return [], {}, 0, "", "validator_registry_pubkey_invalid"
        if len(value) % 2:
            return [], {}, 0, "", "validator_registry_pubkey_invalid"
        try:
            bytes.fromhex(value)
        except ValueError:
            return [], {}, 0, "", "validator_registry_pubkey_invalid"
    computed = validator_set_hash(validators)
    if not advertised_hash or advertised_hash != computed:
        return [], {}, 0, "", "validator_registry_set_hash_mismatch"
    return validators, dict(pubkeys), epoch, computed, ""


def _exact_signed_qc(
    *,
    raw: Any,
    block: Mapping[str, Any],
    chain_id: str,
    validators: list[str],
    pubkeys: dict[str, str],
    epoch: int,
    expected_set_hash: str,
    prior_view: int,
) -> tuple[bool, str, int]:
    """Verify exact signed QC -> stored block binding without authorizing finality."""
    if not isinstance(raw, dict) or raw.get("t") != "QC":
        return False, "qc_required", prior_view
    if type(raw.get("view")) is not int or raw["view"] <= prior_view:
        return False, "qc_view_not_strictly_increasing", prior_view
    if type(raw.get("validator_epoch")) is not int:
        return False, "qc_epoch_missing", prior_view
    qc = qc_from_json(raw)
    if qc is None:
        return False, "qc_parse_failed", prior_view
    if qc.chain_id != chain_id:
        return False, "qc_chain_id_mismatch", prior_view
    if qc.validator_epoch != epoch or qc.validator_set_hash != expected_set_hash:
        return False, "qc_pinned_validator_authority_mismatch", prior_view
    if (
        qc.block_id != block.get("block_id")
        or qc.block_hash != block.get("block_hash")
        or qc.parent_id != block.get("prev_block_id")
    ):
        return False, "qc_canonical_block_binding_mismatch", prior_view

    votes = raw.get("votes")
    min_votes = quorum_threshold(len(validators))
    if not isinstance(votes, list) or not min_votes <= len(votes) <= len(validators):
        return False, "qc_vote_count_invalid", prior_view
    signers: set[str] = set()
    for vote in votes:
        if not isinstance(vote, dict):
            return False, "qc_vote_malformed", prior_view
        signer = _s(vote.get("signer"))
        if not signer or signer in signers or signer not in pubkeys:
            return False, "qc_vote_duplicate_or_unauthorized_signer", prior_view
        signers.add(signer)
        required = {
            "t": "VOTE",
            "chain_id": qc.chain_id,
            "view": qc.view,
            "block_id": qc.block_id,
            "block_hash": qc.block_hash,
            "parent_id": qc.parent_id,
            "validator_epoch": epoch,
            "validator_set_hash": expected_set_hash,
            "sig_profile": PQ_MLDSA_V1,
            "pubkey": pubkeys[signer],
        }
        if any(vote.get(name) != value for name, value in required.items()):
            return False, "qc_vote_metadata_or_pinned_key_mismatch", prior_view
        if not _s(vote.get("sig")):
            return False, "qc_vote_signature_missing", prior_view
    try:
        if not verify_qc(qc=qc, validators=validators, vpub=pubkeys, require_threshold=True):
            return False, "qc_signature_or_quorum_invalid", prior_view
    except (TypeError, ValueError, KeyError, OverflowError):
        return False, "qc_verification_failed_closed", prior_view
    return True, "", qc.view


def review_persisted_reputation_parent_qc_chain(
    *,
    executor: Any,
    parent_height: Any,
    qc_triplet: Any,
    pinned_validator_authority: Any,
    parent_queue_id: str = "",
    expected_dispute_id: str = "",
) -> Json:
    """Examine exactly three persisted blocks, three signed QCs, and a parent.

    A cryptographically consistent result is diagnostic only. The trusted
    origin of the validator registry, certificate custody, actual network
    finalization, actual dispute producer and appeal are not established here.
    """
    errors: list[str] = []
    blocks: list[Mapping[str, Any]] = []
    bindings: list[Any] = []
    state: Mapping[str, Any] = {}
    try:
        observed = executor.read_state()
        if isinstance(observed, dict):
            state = observed
        else:
            errors.append("persisted_state_missing")
    except (AttributeError, OSError, TypeError, ValueError, RuntimeError):
        errors.append("persisted_state_read_failed")
    chain_id = _s(state.get("chain_id"))
    if not chain_id or chain_id != _s(getattr(executor, "chain_id", None)):
        errors.append("chain_id_not_bound_to_executor")
    height = state.get("height")
    if not _valid_height(parent_height) or not _valid_height(height):
        errors.append("invalid_parent_or_state_height")
    elif parent_height + 2 > height:
        errors.append("qc_three_chain_history_not_available")
    elif chain_id:
        for at in range(parent_height, parent_height + 3):
            try:
                block = executor.get_block_by_height(at)
            except (AttributeError, OSError, TypeError, ValueError, RuntimeError):
                errors.append(f"historical_block_read_failed:{at}")
                break
            if not isinstance(block, dict) or block.get("height") != at:
                errors.append(f"historical_block_missing_or_wrong_height:{at}")
                break
            try:
                valid, reason, binding = validate_complete_block_commitments(
                    block=block, chain_id=chain_id
                )
            except (TypeError, ValueError, OverflowError, KeyError):
                valid, reason, binding = False, "exception", None
            if not valid or binding is None:
                errors.append(f"historical_block_commitment_invalid:{at}:{reason}")
                break
            blocks.append(block)
            bindings.append(binding)

    canonical_history = len(blocks) == 3
    parent_links = canonical_history and all(
        blocks[index].get("prev_block_id") == bindings[index - 1].block_id
        and _s(blocks[index].get("prev_block_hash")) == bindings[index - 1].block_hash
        for index in (1, 2)
    )
    if canonical_history and not parent_links:
        errors.append("qc_three_chain_parent_link_mismatch")

    validators, pubkeys, epoch, set_hash, authority_error = _pinned_authority(
        pinned_validator_authority
    )
    if authority_error:
        errors.append(authority_error)
    complete_triplet = isinstance(qc_triplet, (list, tuple)) and len(qc_triplet) == 3
    if not complete_triplet:
        errors.append("qc_triplet_required")

    cryptographic_qcs_valid = False
    certificates_checked = 0
    if canonical_history and parent_links and not authority_error and complete_triplet:
        previous_view = -1
        for block, certificate in zip(blocks, qc_triplet, strict=True):
            valid, reason, current_view = _exact_signed_qc(
                raw=certificate,
                block=block,
                chain_id=chain_id,
                validators=validators,
                pubkeys=pubkeys,
                epoch=epoch,
                expected_set_hash=set_hash,
                prior_view=previous_view,
            )
            if not valid:
                errors.append(reason)
                break
            certificates_checked += 1
            previous_view = current_view
        cryptographic_qcs_valid = certificates_checked == 3

    # An exact successful SYSTEM DISPUTE_RESOLVE parent must be shown, rather
    # than inferred from an arbitrary human-written reference or case label.
    parent_receipt_valid = False
    if canonical_history and _s(parent_queue_id) and len(parent_queue_id) <= 256:
        parent = blocks[0]
        txs = parent.get("txs")
        receipts = parent.get("receipts")
        if isinstance(txs, list) and isinstance(receipts, list):
            candidates = [
                tx
                for tx in txs
                if isinstance(tx, dict)
                and tx.get("tx_type") == "DISPUTE_RESOLVE"
                and tx.get("system") is True
                and _s(_map(tx.get("payload")).get("_system_queue_id")) == parent_queue_id
                and (
                    not expected_dispute_id
                    or _s(_map(tx.get("payload")).get("dispute_id")) == expected_dispute_id
                )
            ]
            if len(candidates) == 1:
                tx_id = _s(candidates[0].get("tx_id"))
                matches = [
                    receipt
                    for receipt in receipts
                    if isinstance(receipt, dict)
                    and receipt.get("tx_id") == tx_id
                    and receipt.get("tx_type") == "DISPUTE_RESOLVE"
                    and receipt.get("ok") is True
                ]
                parent_receipt_valid = bool(tx_id and len(matches) == 1)
    if not parent_receipt_valid:
        errors.append("authenticated_parent_dispute_resolution_receipt_not_shown")

    observations = {
        "three_stored_blocks_canonically_self_bound": canonical_history,
        "three_stored_blocks_parent_linked": bool(parent_links),
        "supplied_validator_registry_shape_self_consistent": not bool(authority_error),
        "three_exact_signed_quorum_certificates_verified": cryptographic_qcs_valid,
        "exact_parent_dispute_resolution_success_receipt": parent_receipt_valid,
        "validator_registry_independently_authenticated": False,
        "production_network_finality_independently_verified": False,
    }
    blockers = errors + [
        "caller_supplied_validator_keys_not_independently_authenticated",
        "caller_supplied_qcs_not_authenticated_as_production_network_transcript",
        "historical_consensus_replay_and_epoch_transition_review_pending",
        "juror_verdict_severity_appeal_and_constitutional_authority_pending",
        "v2_semantic_review_pending",
    ]
    return {
        "schema": SCHEMA,
        "status": STATUS,
        "parent_height": parent_height if _valid_height(parent_height) else None,
        "certificates_checked": certificates_checked,
        "observations": observations,
        "blocking_reasons": blockers,
        "cryptographic_three_chain_candidate": bool(
            canonical_history and parent_links and cryptographic_qcs_valid
        ),
        "independent_bft_finality_verified": False,
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_enqueue_reputation_delta": False,
        "may_ban_account": False,
    }


__all__ = [
    "SCHEMA",
    "STATUS",
    "review_persisted_reputation_parent_qc_chain",
]
