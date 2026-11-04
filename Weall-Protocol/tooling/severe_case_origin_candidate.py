"""Review-only severe-case origin / classification binding prototype.

IMPORTANT: No chain adapter, authenticated classification producer, S4 policy,
signature verification, or constitutional authorization exists here.
This module is not imported by consensus, admission, scheduler, or appliers.
Even perfectly self-consistent *forged* inputs never authorize a sanction.
The proposed classification record kind is NOT a registered WeAll TX type.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

SCHEMA = "weall.review-only.severe-case-origin.v0"
CANDIDATE_KIND = "weall.candidate.severe-case-admission.v0"
STATUS = "BLOCKED_UNAUTHENTICATED_CASE_CLASSIFICATION"
HEX = frozenset("0123456789abcdef")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and any(c != "0" for c in value)
        and all(c in HEX for c in value)
    )


def _height(value: Any) -> bool:
    return type(value) is int and value >= 0


def review_severe_case_origin(
    *,
    case: Any,
    opening: Any,
    classification: Any,
    chain_id: str,
) -> dict[str, Any]:
    """Compare alleged origin and classification records, without trusting them.

    Inputs are copied conceptually from a future chain-verified adapter, but
    this review accepts arbitrary mappings and CANNOT know whether any record
    was committed, signed, valid, non-reverted, or legally classified.
    "True" observations mean field consistency *only*. No caller-supplied
    flag, signature claim, digest or record can change the authorization veto.
    """
    d = _mapping(case)
    o = _mapping(opening)
    c = _mapping(classification)
    p = _mapping(o.get("payload"))
    case_id = d.get("id")
    target_id = d.get("target_id")
    opened_at = d.get("opened_at_height")
    nonce = d.get("opened_at_nonce")
    opening_id = o.get("tx_id")

    observations = {
        "canonical_case_shape_observed": (
            _identifier(case_id)
            and d.get("target_type") == "account"
            and _identifier(target_id)
            and _identifier(d.get("opened_by"))
            and _height(opened_at)
            and _height(nonce)
        ),
        "opening_envelope_shape_observed": (
            o.get("tx_type") == "DISPUTE_OPEN"
            and _digest(opening_id)
            and _height(o.get("height"))
            and _height(o.get("nonce"))
            and _identifier(o.get("signer"))
        ),
        "opening_matches_case_fields": (
            p.get("dispute_id") == case_id
            and p.get("target_type") == "account"
            and p.get("target_id") == target_id
            and o.get("signer") == d.get("opened_by")
            and type(o.get("height")) is int
            and o.get("height") == opened_at
            and type(o.get("nonce")) is int
            and o.get("nonce") == nonce
        ),
        "opening_chain_bound": (_identifier(chain_id) and o.get("chain_id") == chain_id),
        "classification_separate_record_shape_observed": (
            c.get("record_kind") == CANDIDATE_KIND
            and _digest(c.get("record_id"))
            and c.get("record_id") != opening_id
            and _height(c.get("height"))
        ),
        "classification_matches_origin_and_target": (
            c.get("chain_id") == chain_id
            and c.get("dispute_id") == case_id
            and c.get("opening_tx_id") == opening_id
            and c.get("target_type") == "account"
            and c.get("target_id") == target_id
        ),
        "explicit_s4_claim_observed": (
            c.get("sanction_class") == "S4"
            and c.get("severity") in ("severe", "critical")
            and _identifier(c.get("alleged_violation_class"))
        ),
        "evidence_and_policy_commitment_shapes_observed": (
            _digest(c.get("evidence_root")) and _digest(c.get("policy_digest"))
        ),
        "classification_not_before_opening": (
            type(c.get("height")) is int and type(opened_at) is int and c.get("height") >= opened_at
        ),
        "reasoned_admission_claim_observed": _identifier(c.get("reason")),
    }
    all_consistent = all(observations.values())
    fingerprint = None
    if all_consistent:
        # A content-integrity review hash; NOT a signature, proof or ledger ID.
        fingerprint_material = {
            "domain": SCHEMA,
            "chain_id": chain_id,
            "dispute_id": case_id,
            "target_id": target_id,
            "opening_tx_id": opening_id,
            "opening_height": opened_at,
            "opening_nonce": nonce,
            "classification_record_id": c["record_id"],
            "classification_height": c["height"],
            "alleged_violation_class": c["alleged_violation_class"],
            "evidence_root": c["evidence_root"],
            "policy_digest": c["policy_digest"],
            "reason": c["reason"],
        }
        fingerprint = hashlib.sha256(
            json.dumps(fingerprint_material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    blockers = [key for key, present in observations.items() if not present]
    blockers.extend(
        (
            "trusted_chain_origin_and_finality_adapter_unimplemented",
            "evidence_root_and_policy_digest_not_proven_from_finalized_state",
            "s4_violation_classification_authority_unadjudicated",
            "signed_independent_admission_decision_not_verified",
            "constitutional_appeal_and_enforcement_producer_unimplemented",
            "replay_version_and_v2_semantic_approval_pending",
        )
    )
    return {
        "schema": SCHEMA,
        "status": STATUS,
        "observations": observations,
        "structurally_consistent_claims": all_consistent,
        "review_fingerprint_not_authority": fingerprint,
        "blocking_reasons": blockers,
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_classify_canonical_case": False,
        "may_enqueue_account_ban": False,
    }
