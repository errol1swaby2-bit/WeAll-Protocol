"""Review-only source binding for a signed DISPUTE_OPEN in a block-shaped record.

No finalized-chain source adapter or canonical S4 classifier exists here.
The supplied pre-state/block may be forged as a self-consistent pair.
Positive observations never authorize classification or enforcement.
This module must stay outside consensus, admission, scheduling, and appliers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.crypto.sig import verify_tx_sig_against_any_key
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.runtime.block_commitment_validation import validate_complete_block_commitments
from weall.runtime.tx_id import compute_tx_id_from_dict

SCHEMA = "weall.review-only.signed-dispute-opening.v0"
STATUS = "BLOCKED_NO_FINALIZED_CHAIN_AUTHORITY"


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _str(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _height(value: Any) -> bool:
    return type(value) is int and value >= 0


def _matching_one(items: Any, tx_id: str) -> Mapping[str, Any]:
    if not isinstance(items, list):
        return {}
    found = [item for item in items if isinstance(item, Mapping) and item.get("tx_id") == tx_id]
    return found[0] if len(found) == 1 else {}


def review_signed_dispute_opening(
    *,
    case: Any,
    block: Any,
    pre_state: Any,
    chain_id: str,
    opening_tx_id: str,
) -> dict[str, Any]:
    """Verify a signed *supplied* opening without claiming block finality.

    Uses the runtime's canonical transaction ID, full block self-commitment
    validator, and ML-DSA signer-key verification. A valid signature against
    a caller-supplied pre_state is NOT an authenticated chain-state snapshot.
    No environmental unsigned-dev bypass is consulted for the signature check.
    """
    d = _map(case)
    b = _map(block)
    s = _map(pre_state)
    h = _map(b.get("header"))
    tx = _matching_one(b.get("txs"), opening_tx_id)
    rec = _matching_one(b.get("receipts"), opening_tx_id)
    payload = _map(tx.get("payload"))
    raw_case_id = payload.get("dispute_id")
    explicit_case_id = raw_case_id.strip() if isinstance(raw_case_id, str) else ""
    canonical_case_id = explicit_case_id or (f"dispute:{tx.get('signer')}:{tx.get('nonce')}")
    raw_target_type = payload.get("target_type")
    canonical_target_type = (
        raw_target_type.strip().lower() if isinstance(raw_target_type, str) else ""
    )
    raw_target_id = payload.get("target_id")
    canonical_target_id = raw_target_id.strip() if isinstance(raw_target_id, str) else ""
    raw_reason = payload.get("reason")
    canonical_reason = raw_reason.strip() if isinstance(raw_reason, str) else ""
    nested_signature = tx.get("signature")
    matching_signature_forms = nested_signature is None or (
        isinstance(nested_signature, Mapping) and nested_signature.get("sig") == tx.get("sig")
    )

    block_height = h.get("height")
    candidate_shape = (
        _str(chain_id)
        and _str(opening_tx_id)
        and opening_tx_id.startswith("tx:")
        and _str(tx.get("tx_type"))
        and tx.get("tx_type") == "DISPUTE_OPEN"
        and (tx.get("system") is None or tx.get("system") is False)
        and tx.get("parent") is None
        and _str(tx.get("signer"))
        and _height(tx.get("nonce"))
        and tx.get("nonce") > 0
        and isinstance(tx.get("payload"), dict)
        and tx.get("chain_id") == chain_id
        and tx.get("sig_profile") == PQ_MLDSA_V1
        and _str(tx.get("sig"))
        and matching_signature_forms
    )

    canonical_tx_id = ""
    if candidate_shape:
        try:
            canonical_tx_id = compute_tx_id_from_dict(chain_id, dict(tx))
        except (TypeError, ValueError, OverflowError):
            canonical_tx_id = ""

    block_bound = False
    if isinstance(block, dict) and _str(chain_id):
        try:
            valid, _why, binding = validate_complete_block_commitments(
                block=block, chain_id=chain_id
            )
            block_bound = bool(
                valid
                and binding is not None
                and b.get("block_id") == binding.block_id
                and b.get("block_hash") in (None, "", binding.block_hash)
            )
        except (TypeError, ValueError, OverflowError):
            block_bound = False

    # Canonical signed transactions can bind just chain_id, without a
    # separately configured network_id. If either explicitly supplies one,
    # require exact agreement; never accept only one side naming a network.
    state_network = s.get("network_id")
    tx_network = tx.get("network_id")
    same_network = (
        isinstance(state_network, str)
        and bool(state_network.strip())
        and state_network == tx_network
    ) or (state_network in (None, "") and tx_network in (None, ""))
    params = _map(s.get("params"))
    required_policy = params.get("require_signatures") is True or (
        params.get("block_tx_signature_policy") == "required"
    )
    prestate_context = (
        _height(s.get("height"))
        and _height(block_height)
        and block_height > 0
        and s.get("height") + 1 == block_height
        and s.get("tip") == b.get("prev_block_id")
        and s.get("chain_id") == chain_id
        and same_network
        and required_policy
        and isinstance(s.get("accounts"), dict)
        and isinstance(_map(s.get("accounts")).get(tx.get("signer")), dict)
    )

    signed = False
    if candidate_shape and prestate_context:
        try:
            signed, _verification = verify_tx_sig_against_any_key(
                ledger=dict(s),
                tx_type="DISPUTE_OPEN",
                signer=tx["signer"],
                nonce=tx["nonce"],
                payload=dict(payload),
                sig=tx["sig"],
                parent=None,
                chain_id=chain_id,
                network_id=tx.get("network_id"),
                sig_profile=tx["sig_profile"],
                chain_config=dict(_map(s.get("chain_config"))),
            )
        except (TypeError, ValueError, OverflowError):
            signed = False

    observations = {
        "opening_is_exact_canonical_tx": bool(candidate_shape and canonical_tx_id == opening_tx_id),
        "block_self_commitments_match": block_bound,
        "prestate_height_tip_chain_and_signature_policy_match": bool(prestate_context),
        "signed_against_supplied_prestate_key": bool(signed),
        "opening_admitted_success_receipt_observed": bool(
            rec
            and rec.get("ok") is True
            and rec.get("tx_type") == "DISPUTE_OPEN"
            and rec.get("signer") == tx.get("signer")
            and type(rec.get("nonce")) is int
            and rec.get("nonce") == tx.get("nonce")
        ),
        "case_mutation_matches_signed_opening": bool(
            d.get("target_type") == "account"
            and canonical_target_type == "account"
            and _str(d.get("id"))
            and _str(d.get("target_id"))
            and d.get("id") == canonical_case_id
            and canonical_target_id == d.get("target_id")
            and d.get("reason") == canonical_reason
            and d.get("opened_by") == tx.get("signer")
            and d.get("id") not in _map(s.get("disputes_by_id"))
            and type(d.get("opened_at_nonce")) is int
            and d.get("opened_at_nonce") == tx.get("nonce")
            and type(d.get("opened_at_height")) is int
            # DISPUTE_OPEN executes against the predecessor's working state.
            # Builder and follower set state["height"] to the new block height
            # only AFTER applying transactions, so this marker is H-1.
            and d.get("opened_at_height") == s.get("height")
        ),
    }
    blockers = [k for k, v in observations.items() if not v]
    blockers.extend(
        (
            "supplied_block_not_authenticated_as_network_finalized",
            "supplied_historical_prestate_not_bound_to_verified_replay",
            "s4_classification_and_independent_admission_producer_missing",
            "constitutional_evidence_and_violation_taxonomy_not_adjudicated",
            "automatic_appeal_and_system_enforcement_authority_missing",
            "historical_activation_and_semantic_reviews_pending",
        )
    )
    return {
        "schema": SCHEMA,
        "status": STATUS,
        "opening_tx_id": opening_tx_id,
        "observations": observations,
        "blocking_reasons": blockers,
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_classify_canonical_case": False,
        "may_enqueue_account_ban": False,
    }
