from __future__ import annotations

"""Read-only provenance resolver for a candidate first solo-finality witness.

This module does NOT authorize, enqueue, or apply BLOCK_FINALIZE. A valid
canonical inclusion proof is necessary but not sufficient for choosing the
constitutional authority and release rule for the first finalized block.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from weall.runtime.bft_hotstuff import (
    CONSENSUS_PHASE_SOLO_BOOTSTRAP,
    normalize_consensus_phase,
)
from weall.runtime.block_commitment_validation import validate_complete_block_commitments
from weall.runtime.commitments import consensus_active_validator_ids, normalize_validator_ids

Json = dict[str, Any]


class SoloFinalityWitnessError(ValueError):
    """A proposed committed attestation source fails a prerequisite."""


@dataclass(frozen=True, slots=True)
class SoloAttestationSource:
    source_block_id: str
    source_height: int
    target_block_id: str
    target_height: int
    validator: str
    parent_tx_id: str
    parent_nonce: int


def _s(value: Any) -> str:
    return str(value or "").strip()


def _i(value: Any) -> int:
    if isinstance(value, bool):
        return -1
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return -1


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise SoloFinalityWitnessError(reason)


def _active_solo_authority(state: Json) -> str:
    explicit = consensus_active_validator_ids(state)
    if explicit is None:
        roles = state.get("roles")
        validators = roles.get("validators") if isinstance(roles, dict) else None
        active_raw = validators.get("active_set") if isinstance(validators, dict) else None
        _require(isinstance(active_raw, list), "singleton_validator_authority_missing")
        active = normalize_validator_ids(active_raw)
    else:
        active = explicit
    _require(len(active) == 1, "not_singleton_validator_authority")
    consensus = state.get("consensus")
    phase_root = consensus.get("phase") if isinstance(consensus, dict) else None
    phase = phase_root.get("current") if isinstance(phase_root, dict) else ""
    _require(
        _s(phase).lower() == CONSENSUS_PHASE_SOLO_BOOTSTRAP,
        "solo_bootstrap_phase_not_explicit",
    )
    normalized = normalize_consensus_phase(phase, validator_count=len(active))
    _require(normalized == CONSENSUS_PHASE_SOLO_BOOTSTRAP, "not_solo_bootstrap_phase")
    return active[0]


def _require_ancestry(state: Json, *, descendant: str, ancestor: str) -> None:
    """Confirm both IDs are on the same canonical, height-contiguous state path."""
    blocks = state.get("blocks")
    _require(isinstance(blocks, dict), "canonical_ancestry_unavailable")
    current = descendant
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        record = blocks.get(current)
        _require(isinstance(record, dict), "canonical_ancestor_missing")
        if current == ancestor:
            return
        parent = _s(record.get("prev_block_id"))
        _require(bool(parent), "canonical_ancestor_not_found")
        parent_record = blocks.get(parent)
        _require(isinstance(parent_record, dict), "canonical_parent_missing")
        _require(
            _i(parent_record.get("height")) + 1 == _i(record.get("height")),
            "canonical_ancestor_height_discontinuity",
        )
        current = parent
    raise SoloFinalityWitnessError("canonical_ancestry_cycle_or_mismatch")


def resolve_committed_solo_attestation_source(
    *,
    state: Json,
    source_block: Json,
    target_block_id: str,
    chain_id: str,
) -> SoloAttestationSource:
    """Inspect a *previously committed* source block for one signed yes-attestation.

    Caller must supply the canonical block body retrieved from durable history.
    Its body/header transaction identities and receipt contents are rebound
    cryptographically, and canonical state ancestry must include the source.
    The original signed transaction is accepted as historical inclusion evidence
    ONLY because a committed successful receipt proves it already passed
    canonical admission and execution. Never revalidate historical signing
    authority against mutable current keys after a later key rotation.

    This resolver cannot choose whether a sole validator has constitutional
    first-finality authority, and deliberately never creates a SYSTEM receipt.
    """
    _require(isinstance(state, dict), "state_not_object")
    _require(isinstance(source_block, dict), "source_block_not_object")
    _require(bool(_s(chain_id)), "chain_id_missing")
    expected_chain = _s(state.get("chain_id"))
    if not expected_chain:
        params = state.get("params")
        expected_chain = _s(params.get("chain_id")) if isinstance(params, dict) else ""
    _require(expected_chain == _s(chain_id), "canonical_chain_id_mismatch")

    validator = _active_solo_authority(state)
    finalized = state.get("finalized")
    finalized_height = _i(finalized.get("height", 0)) if isinstance(finalized, dict) else 0
    _require(finalized_height == 0, "already_finalized")

    blocks = state.get("blocks")
    _require(isinstance(blocks, dict), "canonical_ancestry_unavailable")
    target_id = _s(target_block_id)
    target_record = blocks.get(target_id)
    _require(isinstance(target_record, dict), "target_not_canonically_committed")
    _require(_i(target_record.get("height")) == 1, "first_finality_target_not_height_one")
    _require(_s(state.get("tip")) != target_id, "source_not_yet_committed")

    ok, reason, binding = validate_complete_block_commitments(
        block=source_block, chain_id=_s(chain_id)
    )
    if not ok or binding is None:
        raise SoloFinalityWitnessError(f"source_commitment_invalid:{reason}")
    source_id = _s(source_block.get("block_id"))
    _require(source_id == binding.block_id, "source_block_id_missing_or_alias")
    source_record = blocks.get(source_id)
    _require(isinstance(source_record, dict), "source_not_canonically_committed")
    source_height = _i(source_record.get("height"))
    header = source_block.get("header")
    _require(isinstance(header, dict), "source_header_missing")
    _require(source_height > 1, "source_not_after_target")
    _require(source_height == _i(header.get("height")), "source_height_mismatch")
    _require(
        _s(source_record.get("prev_block_id")) == _s(source_block.get("prev_block_id")),
        "source_parent_mismatch",
    )
    _require_ancestry(state, descendant=_s(state.get("tip")), ancestor=source_id)
    _require_ancestry(state, descendant=source_id, ancestor=target_id)

    summaries = state.get("block_attestations")
    votes = summaries.get(target_id) if isinstance(summaries, dict) else None
    summary = votes.get(validator) if isinstance(votes, dict) else None
    _require(isinstance(summary, dict), "canonical_attestation_summary_missing")
    _require(_s(summary.get("attestation")).lower() == "yes", "canonical_vote_not_yes")

    txs = source_block.get("txs")
    receipts = source_block.get("receipts")
    _require(isinstance(txs, list) and isinstance(receipts, list), "source_body_missing")
    matches: list[SoloAttestationSource] = []
    for index, raw in enumerate(txs):
        if not isinstance(raw, dict) or _s(raw.get("tx_type")).upper() != "BLOCK_ATTEST":
            continue
        if _s(raw.get("signer")) != validator or bool(raw.get("system")):
            continue
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            continue
        if _s(payload.get("block_id") or payload.get("id")) != target_id:
            continue
        if _i(payload.get("height")) != 1:
            continue
        if _s(payload.get("validator")) not in ("", validator):
            continue
        if _s(payload.get("attestation") or payload.get("vote") or "yes").lower() != "yes":
            continue
        if payload != summary.get("payload"):
            continue
        signature = raw.get("signature")
        structured_sig = _s(signature.get("sig")) if isinstance(signature, dict) else ""
        top_level_sig = _s(raw.get("sig"))
        _require(
            not (structured_sig and top_level_sig and structured_sig != top_level_sig),
            "ambiguous_signature_alias",
        )
        sig_value = structured_sig or top_level_sig
        if not sig_value or not _s(raw.get("sig_profile")):
            continue
        nonce = _i(raw.get("nonce"))
        if nonce <= 0:
            continue
        tx_id = binding.tx_ids[index]
        agreeing = [
            rec for rec in receipts if isinstance(rec, dict) and _s(rec.get("tx_id")) == tx_id
        ]
        if len(agreeing) != 1:
            continue
        receipt = agreeing[0]
        if (
            receipt.get("ok") is not True
            or _s(receipt.get("tx_type")).upper() != "BLOCK_ATTEST"
            or _s(receipt.get("signer")) != validator
            or _i(receipt.get("nonce")) != nonce
        ):
            continue
        matches.append(
            SoloAttestationSource(
                source_block_id=source_id,
                source_height=source_height,
                target_block_id=target_id,
                target_height=1,
                validator=validator,
                parent_tx_id=tx_id,
                parent_nonce=nonce,
            )
        )

    _require(bool(matches), "no_committed_successful_signed_attestation")
    _require(len(matches) == 1, "ambiguous_committed_attestation_parent")
    return matches[0]


def resolve_committed_solo_attestation_from_history(
    *,
    state: Json,
    target_block_id: str,
    chain_id: str,
    load_committed_block: Callable[[str], Json | None],
) -> SoloAttestationSource:
    """Locate an unambiguous signed solo attestation in complete canonical history.

    The caller supplies a trusted, durable canonical block-body lookup, such as
    `WeAllExecutor.get_block_by_id`. No network proposal/cache body is eligible.
    Every block from the target's successor through the committed tip must be
    available and fully self-bound. Missing bodies are a hard failure, not an
    excuse to select an arbitrary later witness.

    Only read-only historical evidence is returned. This is not a constitutional
    authority check or an alternative way to enqueue BLOCK_FINALIZE. The scan is
    deliberately not on the block-production or consensus-replay hot path.
    """
    _require(isinstance(state, dict), "state_not_object")
    _require(bool(_s(chain_id)), "chain_id_missing")
    _require(callable(load_committed_block), "committed_block_loader_missing")
    validator = _active_solo_authority(state)
    blocks = state.get("blocks")
    _require(isinstance(blocks, dict), "canonical_ancestry_unavailable")
    target_id = _s(target_block_id)
    target = blocks.get(target_id)
    _require(isinstance(target, dict), "target_not_canonically_committed")
    _require(_i(target.get("height")) == 1, "first_finality_target_not_height_one")
    tip = _s(state.get("tip"))
    _require(bool(tip and tip != target_id), "source_not_yet_committed")
    _require_ancestry(state, descendant=tip, ancestor=target_id)

    # The ancestry guard above proves this is a single, acyclic, height-contiguous
    # path. Iterate it oldest first so the result is independent of DB row order.
    source_ids: list[str] = []
    current = tip
    while current != target_id:
        source_ids.append(current)
        record = blocks[current]
        current = _s(record.get("prev_block_id"))
    source_ids.reverse()

    matches: list[SoloAttestationSource] = []
    for source_id in source_ids:
        block = load_committed_block(source_id)
        _require(isinstance(block, dict), "committed_source_body_missing")
        ok, reason, binding = validate_complete_block_commitments(
            block=block, chain_id=_s(chain_id)
        )
        if not ok or binding is None:
            raise SoloFinalityWitnessError(f"committed_source_invalid:{reason}")
        _require(
            _s(block.get("block_id")) == source_id == binding.block_id,
            "committed_source_identity_mismatch",
        )

        # A body can be self-committed while the caller's ancestry index has
        # been corrupted or spliced. Rebind *every* historical body, including
        # blocks without a matching attestation, to its canonical state record.
        # A future finality scheduler must never trust two different histories
        # simply because each block is individually hash-consistent.
        record = blocks.get(source_id)
        _require(isinstance(record, dict), "committed_source_ancestry_record_missing")
        header = block.get("header")
        _require(isinstance(header, dict), "committed_source_header_missing")
        _require(
            _i(record.get("height")) > 1
            and _i(record.get("height")) == _i(header.get("height")),
            "committed_source_state_height_mismatch",
        )
        _require(
            _s(record.get("prev_block_id")) == _s(block.get("prev_block_id")),
            "committed_source_state_parent_mismatch",
        )

        txs = block.get("txs")
        if not isinstance(txs, list) or not any(
            isinstance(raw, dict)
            and _s(raw.get("tx_type")).upper() == "BLOCK_ATTEST"
            and _s(raw.get("signer")) == validator
            and isinstance(raw.get("payload"), dict)
            and _s(raw["payload"].get("block_id") or raw["payload"].get("id")) == target_id
            for raw in txs
        ):
            continue

        try:
            source = resolve_committed_solo_attestation_source(
                state=state,
                source_block=block,
                target_block_id=target_id,
                chain_id=chain_id,
            )
        except SoloFinalityWitnessError as exc:
            # A committed rejected transaction is not positive finality
            # evidence. All structural, authority, and ancestry errors remain
            # fatal rather than being masked by a later successful source.
            if str(exc) != "no_committed_successful_signed_attestation":
                raise
            continue
        matches.append(source)

    _require(bool(matches), "no_committed_successful_signed_attestation")
    _require(len(matches) == 1, "ambiguous_committed_attestation_sources")
    return matches[0]


__all__ = [
    "SoloAttestationSource",
    "SoloFinalityWitnessError",
    "resolve_committed_solo_attestation_source",
    "resolve_committed_solo_attestation_from_history",
]
