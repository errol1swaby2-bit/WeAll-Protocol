"""Non-authoritative, deterministic V2 severe-sanction evidence inventory.

NOT a SYSTEM receipt producer, authorization verifier, consensus transition,
or approval to activate ACCOUNT_BAN. Source fields are treated as observations;
even a fully populated case cannot authenticate its own evidence.

V2 first-draft references: DSP-210, SAN-005, SAN-006, section 32 (25/20).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

INITIAL_PANEL_SIZE = 25
INITIAL_APPROVALS = 20
APPEAL_PANEL_SIZE = 25
APPEAL_APPROVALS = 20

STATUS = "BLOCKED_UNAUTHENTICATED_SEVERE_SANCTION_EVIDENCE"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _identities(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(x for x in value if isinstance(x, str) and x.strip() and x == x.strip())


def _count(value: Any) -> int:
    # Never interpret bool or a user-supplied numeric string as vote evidence.
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def review_severe_sanction_candidate(
    state: Mapping[str, Any], *, dispute_id: str, account_id: str
) -> dict[str, Any]:
    """Inventory on-chain-shaped fields without conferring authority.

    The result is deliberately incapable of approving an ACCOUNT_BAN.
    Its boolean indicators are only syntactic review cues, NOT authenticated
    ballots, finalization, waiver, independent review, or replay evidence.
    """
    cases = _mapping(state.get("disputes_by_id"))
    dispute = _mapping(cases.get(dispute_id))
    severity = str(dispute.get("severity") or _mapping(dispute.get("rules")).get("severity") or "")
    initial = _identities(
        dispute.get("original_panel_juror_ids")
        if isinstance(dispute.get("original_panel_juror_ids"), list)
        else dispute.get("assigned_jurors")
    )
    appeal = _identities(dispute.get("appeal_panel_juror_ids"))
    appeal_result = _mapping(dispute.get("appeal_panel_result"))
    initial_resolution = _mapping(dispute.get("resolution"))
    initial_tally = _mapping(initial_resolution.get("tally"))
    appeal_counts = _mapping(appeal_result.get("counts"))
    final_resolution = _mapping(dispute.get("final_resolution"))
    receipts = _mapping(state.get("dispute_receipts"))
    recorded_final = any(
        isinstance(receipt, Mapping)
        and _mapping(receipt.get("payload")).get("dispute_id") == dispute_id
        and _mapping(receipt.get("appeal_finalization")).get("decision") == "uphold"
        for receipt in receipts.values()
    )
    observations: dict[str, bool] = {
        "case_exists": bool(dispute),
        "account_target_bound": (
            dispute.get("target_type") == "account" and dispute.get("target_id") == account_id
        ),
        "severe_class_declared": severity.strip().lower() in {"severe", "critical"},
        "initial_25_distinct": (
            len(initial) == INITIAL_PANEL_SIZE and len(set(initial)) == INITIAL_PANEL_SIZE
        ),
        "initial_commitment_present": bool(
            isinstance(dispute.get("panel_commitment"), str)
            and dispute["panel_commitment"].strip()
        ),
        "initial_20_yes_observed": (
            initial_resolution.get("outcome") == "report_upheld"
            and _count(initial_tally.get("yes")) >= INITIAL_APPROVALS
        ),
        "fresh_appeal_25_distinct": (
            len(appeal) == APPEAL_PANEL_SIZE
            and len(set(appeal)) == APPEAL_PANEL_SIZE
            and set(initial).isdisjoint(appeal)
        ),
        "appeal_commitment_present": bool(
            isinstance(dispute.get("appeal_panel_commitment"), str)
            and dispute["appeal_panel_commitment"].strip()
        ),
        "appeal_20_uphold_observed": (
            appeal_result.get("reached") is True
            and appeal_result.get("decision") == "uphold"
            and _count(appeal_counts.get("uphold")) >= APPEAL_APPROVALS
        ),
        "automatic_appeal_recorded": (
            isinstance(dispute.get("automatic_appeal_receipt"), Mapping)
            and bool(dispute["automatic_appeal_receipt"])
        ),
        "public_reason_present": bool(
            isinstance(final_resolution.get("summary"), str)
            and final_resolution["summary"].strip()
        ),
        "final_receipt_observed": (
            dispute.get("stage") == "finalized" and recorded_final
        ),
    }
    # These are hard blockers even if every observational field appears.
    # No supplied payload or dispute record can flip them to True.
    blockers = [
        name for name, observed in observations.items() if not observed
    ]
    blockers.extend(
        (
            "authenticated_panel_ballots_not_independently_verified",
            "authenticated_automatic_appeal_or_waiver_not_implemented",
            "canonical_system_producer_parent_binding_not_implemented",
            "consensus_activation_and_legacy_replay_not_adjudicated",
        )
    )
    return {
        "schema": "weall.review-only.severe-sanction-candidate.v0",
        "status": STATUS,
        "dispute_id": dispute_id,
        "account_id": account_id,
        "thresholds": {
            "initial_panel": INITIAL_PANEL_SIZE,
            "initial_approvals": INITIAL_APPROVALS,
            "appeal_panel": APPEAL_PANEL_SIZE,
            "appeal_approvals": APPEAL_APPROVALS,
        },
        "observations": observations,
        "blocking_reasons": blockers,
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_enqueue_account_ban": False,
    }
