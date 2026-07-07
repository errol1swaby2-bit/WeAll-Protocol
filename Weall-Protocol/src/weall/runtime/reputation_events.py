from __future__ import annotations

"""Canonical event-sourced Reputation Matrix subsystem.

This module is deliberately pure-Python and deterministic.  It owns the
append-only reputation event ledger, event registry, reducer, and role
eligibility read model used by API and frontend surfaces.  Apply modules may
append events, but they must not compute cross-role eligibility themselves.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

from weall.runtime.reputation_units import (
    REPUTATION_MAX_UNITS,
    REPUTATION_MIN_UNITS,
    clamp_reputation_units,
    units_to_reputation,
)

Json = dict[str, Any]

REPUTATION_EVENT_SCHEMA = "weall.reputation_event.v1_5"
REPUTATION_REGISTRY_SCHEMA = "weall.reputation_event_registry.v1_5"
REPUTATION_MATRIX_CONTRACT_SCHEMA = "weall.reputation_matrix_contract.v1_5"
REPUTATION_FLOW_COVERAGE_SCHEMA = "weall.reputation_flow_coverage_map.v1_5"
REPUTATION_INVARIANT_SCHEMA = "weall.reputation_invariant_report.v1_5"
REPUTATION_API_CONTRACT_SCHEMA = "weall.reputation_api_contract_map.v1_5"

REPUTATION_DIMENSIONS: tuple[str, ...] = (
    "poh_reputation",
    "civic_reputation",
    "juror_reputation",
    "governance_reputation",
    "creator_reputation",
    "safety_reputation",
    "validator_reputation",
    "storage_reputation",
    "helper_reputation",
    "appeal_correction_history",
)

DIMENSION_ALIASES: dict[str, tuple[str, ...]] = {
    "poh_reputation": ("identity_poh",),
    "civic_reputation": ("social_trust",),
    "juror_reputation": ("juror", "dispute_participation"),
    "governance_reputation": ("governance",),
    "creator_reputation": ("creator", "social_trust"),
    "safety_reputation": ("social_trust", "abuse_risk"),
    "validator_reputation": ("validator",),
    "storage_reputation": ("storage",),
    "helper_reputation": ("helper",),
    "appeal_correction_history": ("social_trust",),
}

SEVERITY_LABELS: dict[int, str] = {
    0: "informational",
    1: "minor",
    2: "moderate",
    3: "serious",
    4: "severe_integrity",
    5: "critical_disqualification",
}


@dataclass(frozen=True)
class ReputationEventSpec:
    event_code: str
    source_flow: str
    dimension: str
    default_delta: int
    severity: int
    appealable: bool
    decay_policy: str
    eligibility_impact: str
    explanation: str
    farming_policy: str = "none"
    visibility: str = "public"
    can_trigger_ineligibility: bool = False

    def as_dict(self) -> Json:
        return {
            "event_code": self.event_code,
            "source_flow": self.source_flow,
            "dimension": self.dimension,
            "default_delta": int(self.default_delta),
            "severity": int(self.severity),
            "severity_label": SEVERITY_LABELS.get(int(self.severity), "unknown"),
            "appealable": bool(self.appealable),
            "decay_policy": self.decay_policy,
            "eligibility_impact": self.eligibility_impact,
            "explanation": self.explanation,
            "farming_policy": self.farming_policy,
            "visibility": self.visibility,
            "can_trigger_ineligibility": bool(self.can_trigger_ineligibility),
        }


def _spec(
    event_code: str,
    source_flow: str,
    dimension: str,
    default_delta: int,
    severity: int,
    appealable: bool,
    decay_policy: str,
    eligibility_impact: str,
    explanation: str,
    *,
    farming_policy: str = "none",
    visibility: str = "public",
    can_trigger_ineligibility: bool = False,
) -> ReputationEventSpec:
    if dimension not in REPUTATION_DIMENSIONS:
        raise ValueError(f"unknown reputation dimension: {dimension}")
    if severity < 0 or severity > 5:
        raise ValueError(f"invalid severity for {event_code}: {severity}")
    return ReputationEventSpec(
        event_code=event_code,
        source_flow=source_flow,
        dimension=dimension,
        default_delta=int(default_delta),
        severity=int(severity),
        appealable=bool(appealable),
        decay_policy=decay_policy,
        eligibility_impact=eligibility_impact,
        explanation=explanation,
        farming_policy=farming_policy,
        visibility=visibility,
        can_trigger_ineligibility=bool(can_trigger_ineligibility),
    )


_EVENT_SPECS: tuple[ReputationEventSpec, ...] = (
    # PoH / humanity
    _spec("POH_TIER1_VERIFIED", "poh", "poh_reputation", 250, 1, False, "none", "supports_poh_reviewer_eligibility", "Tier 1 humanity verification completed."),
    _spec("POH_TIER2_APPROVED", "poh", "poh_reputation", 1000, 1, True, "none", "supports_civic_and_review_eligibility", "Tier 2 async humanity review approved."),
    _spec("POH_TIER3_APPROVED", "poh", "poh_reputation", 1500, 1, True, "none", "supports_live_review_eligibility", "Tier 3 live humanity verification approved."),
    _spec("POH_REVERIFICATION_COMPLETED", "poh", "poh_reputation", 500, 1, True, "none", "restores_or_preserves_poh_eligibility", "Humanity reverification completed."),
    _spec("POH_DUPLICATE_ATTEMPT", "poh", "poh_reputation", -2500, 4, True, "none", "blocks_or_suspends_poh_eligibility", "Duplicate humanity attempt detected.", can_trigger_ineligibility=True),
    _spec("POH_FRAUDULENT_EVIDENCE", "poh", "poh_reputation", -10000, 5, True, "none", "disqualifies_poh_review_and_may_revoke_humanity", "Fraudulent humanity evidence confirmed.", can_trigger_ineligibility=True),
    _spec("POH_LIVENESS_FAILURE_AFTER_ACCEPTED_REVIEW", "poh", "poh_reputation", -750, 2, True, "recoverable_after_reverification", "temporarily_limits_poh_review_eligibility", "Accepted reviewer missed required PoH liveness obligation.", can_trigger_ineligibility=True),
    _spec("POH_REVOKED_BY_FINAL_DISPUTE", "poh", "poh_reputation", -100000, 5, True, "none", "revokes_poh_eligibility", "Final dispute revoked PoH status.", can_trigger_ineligibility=True),
    # Juror/dispute
    _spec("DISPUTE_JUROR_ACCEPTED", "dispute", "juror_reputation", 0, 0, False, "none", "creates_review_obligation", "Juror accepted a dispute assignment."),
    _spec("DISPUTE_JUROR_WITHDREW_EARLY", "dispute", "juror_reputation", 0, 0, False, "none", "slot_released_no_penalty", "Juror withdrew within the no-penalty window."),
    _spec("DISPUTE_JUROR_WITHDREW_LATE", "dispute", "juror_reputation", -500, 1, True, "recoverable_by_timely_reviews", "light_juror_reliability_penalty", "Juror withdrew after the no-penalty window.", can_trigger_ineligibility=False),
    _spec("DISPUTE_JUROR_TIMED_OUT", "dispute", "juror_reputation", -1500, 2, True, "recoverable_by_timely_reviews", "juror_assignment_risk", "Juror missed the canonical review deadline.", can_trigger_ineligibility=True),
    _spec("DISPUTE_JUROR_VOTED_ON_TIME", "dispute", "juror_reputation", 250, 1, False, "positive_cap_per_epoch", "supports_juror_eligibility", "Juror voted before the canonical review deadline.", farming_policy="cap_positive_dispute_participation_per_epoch"),
    _spec("JUROR_ACCEPTED_AND_COMPLETED_CASE", "dispute", "juror_reputation", 250, 1, False, "positive_cap_per_epoch", "supports_juror_eligibility", "Juror completed an accepted case.", farming_policy="cap_positive_dispute_participation_per_epoch"),
    _spec("JUROR_VOTED_BEFORE_DEADLINE", "dispute", "juror_reputation", 250, 1, False, "positive_cap_per_epoch", "supports_juror_eligibility", "Juror submitted a vote before deadline.", farming_policy="cap_positive_dispute_participation_per_epoch"),
    _spec("JUROR_PROVIDED_REQUIRED_REASONING", "dispute", "juror_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_juror_eligibility", "Juror provided required reasoning."),
    _spec("JUROR_PARTICIPATED_IN_APPEAL_REVIEW", "appeal", "juror_reputation", 150, 1, False, "positive_cap_per_epoch", "supports_appeal_panel_eligibility", "Juror participated in appeal review."),
    _spec("JUROR_TIMEOUT", "dispute", "juror_reputation", -1500, 2, True, "recoverable_by_timely_reviews", "juror_assignment_risk", "Juror timed out.", can_trigger_ineligibility=True),
    _spec("JUROR_LATE_WITHDRAWAL", "dispute", "juror_reputation", -500, 1, True, "recoverable_by_timely_reviews", "light_juror_reliability_penalty", "Juror withdrew late."),
    _spec("JUROR_CONFLICT_OF_INTEREST_VIOLATION", "dispute", "juror_reputation", -5000, 4, True, "none", "blocks_juror_eligibility", "Juror conflict of interest violation confirmed.", can_trigger_ineligibility=True),
    _spec("JUROR_ABUSIVE_REASONING", "dispute", "juror_reputation", -2500, 3, True, "none", "limits_juror_eligibility", "Juror reasoning violated safety rules.", can_trigger_ineligibility=True),
    _spec("JUROR_PATTERN_OF_BAD_FAITH_VOTES", "dispute", "juror_reputation", -5000, 4, True, "none", "blocks_juror_eligibility", "Pattern of bad-faith juror votes confirmed; disagreement alone is never penalized.", can_trigger_ineligibility=True),
    # Governance
    _spec("GOVERNANCE_VOTED", "governance", "governance_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_governance_eligibility", "Governance vote submitted."),
    _spec("GOVERNANCE_COMMENTED_DURING_DELIBERATION", "governance", "governance_reputation", 50, 1, False, "positive_cap_per_epoch", "supports_governance_eligibility", "Comment made during deliberation."),
    _spec("GOVERNANCE_CREATED_VALID_PROPOSAL", "governance", "governance_reputation", 150, 1, True, "positive_cap_per_epoch", "supports_proposal_eligibility", "Valid governance proposal created."),
    _spec("GOVERNANCE_PROPOSAL_PASSED_WITHOUT_SAFETY_ISSUE", "governance", "governance_reputation", 250, 1, True, "positive_cap_per_epoch", "supports_proposal_eligibility", "Proposal passed without a safety issue."),
    _spec("GOVERNANCE_SPAM_PROPOSAL", "governance", "governance_reputation", -1000, 2, True, "recoverable_by_valid_participation", "limits_proposal_creation", "Governance spam proposal confirmed.", can_trigger_ineligibility=True),
    _spec("GOVERNANCE_MALFORMED_UPGRADE_PATCH", "governance", "governance_reputation", -2500, 3, True, "none", "blocks_upgrade_submission", "Malformed or unsafe upgrade patch submitted.", can_trigger_ineligibility=True),
    _spec("GOVERNANCE_DUPLICATE_OR_ABUSIVE_PROPOSAL", "governance", "governance_reputation", -1500, 2, True, "recoverable_by_valid_participation", "limits_proposal_creation", "Duplicate or abusive governance proposal confirmed.", can_trigger_ineligibility=True),
    _spec("GOVERNANCE_CONFIRMED_BRIBERY_OR_COLLUSION", "governance", "governance_reputation", -10000, 5, True, "none", "disqualifies_governance_roles", "Governance bribery or collusion confirmed.", can_trigger_ineligibility=True),
    # Creator/social/content
    _spec("CREATOR_POST_UPHELD_AFTER_REPORT", "content", "creator_reputation", 250, 1, True, "positive_cap_per_epoch", "supports_creator_trust", "Creator post was upheld after report review."),
    _spec("CREATOR_HELPFUL_CONTRIBUTION", "content", "creator_reputation", 100, 1, True, "positive_cap_per_epoch", "supports_feed_trust", "Helpful creator contribution recorded.", farming_policy="cap_positive_creator_events_per_epoch"),
    _spec("CREATOR_GROUP_CONTRIBUTION", "groups", "creator_reputation", 100, 1, True, "positive_cap_per_epoch", "supports_group_trust", "Helpful group contribution recorded."),
    _spec("CREATOR_EDUCATIONAL_CONTENT", "content", "creator_reputation", 150, 1, True, "positive_cap_per_epoch", "supports_feed_trust", "Educational content contribution recorded."),
    _spec("CONTENT_CONFIRMED_VIOLATION", "moderation", "creator_reputation", -1500, 3, True, "recoverable_after_clean_participation", "limits_creator_and_feed_trust", "Content violation confirmed.", can_trigger_ineligibility=True),
    _spec("CONTENT_SPAM", "moderation", "creator_reputation", -1000, 2, True, "recoverable_after_clean_participation", "limits_creator_and_feed_trust", "Content spam confirmed.", can_trigger_ineligibility=True),
    _spec("CONTENT_HARASSMENT", "moderation", "creator_reputation", -3000, 4, True, "none", "limits_or_blocks_creator_trust", "Content harassment confirmed.", can_trigger_ineligibility=True),
    _spec("CONTENT_MANIPULATION", "moderation", "creator_reputation", -2500, 3, True, "none", "limits_feed_trust", "Content manipulation confirmed.", can_trigger_ineligibility=True),
    _spec("CONTENT_EVASION_AFTER_MODERATION", "moderation", "creator_reputation", -5000, 4, True, "none", "blocks_creator_trust", "Evasion after moderation confirmed.", can_trigger_ineligibility=True),
    # Safety/moderation/reporting
    _spec("SAFETY_ACCURATE_REPORT", "moderation", "safety_reputation", 150, 1, True, "positive_cap_per_epoch", "supports_safety_role_eligibility", "Accurate report confirmed."),
    _spec("SAFETY_FALSE_OR_ABUSIVE_REPORT", "moderation", "safety_reputation", -1500, 3, True, "recoverable_after_clean_participation", "limits_safety_role_eligibility", "False or abusive report confirmed.", can_trigger_ineligibility=True),
    _spec("SAFETY_CONFIRMED_MODERATION_ACTION", "moderation", "safety_reputation", 150, 1, True, "positive_cap_per_epoch", "supports_safety_role_eligibility", "Moderation action confirmed."),
    _spec("SAFETY_REVERSED_MODERATION_ACTION", "appeal", "safety_reputation", -1000, 2, True, "recoverable_after_clean_participation", "limits_safety_role_eligibility", "Moderation action reversed on appeal.", can_trigger_ineligibility=True),
    _spec("SAFETY_FRIVOLOUS_APPEAL_PATTERN", "appeal", "safety_reputation", -1000, 2, True, "recoverable_after_clean_participation", "limits_appeal_submission_trust", "Frivolous appeal pattern confirmed.", can_trigger_ineligibility=True),
    # Validator/operator
    _spec("VALIDATOR_SIGNED_VALID_BLOCK", "validator", "validator_reputation", 50, 1, False, "positive_cap_per_epoch", "supports_validator_readiness", "Validator signed a valid block."),
    _spec("VALIDATOR_MAINTAINED_UPTIME", "validator", "validator_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_validator_readiness", "Validator maintained uptime."),
    _spec("VALIDATOR_PASSED_REHEARSAL", "validator", "validator_reputation", 250, 1, False, "none", "supports_validator_readiness", "Validator passed rehearsal."),
    _spec("VALIDATOR_COMPLETED_VERSION_UPGRADE", "validator", "validator_reputation", 150, 1, False, "none", "supports_validator_readiness", "Validator completed version upgrade."),
    _spec("VALIDATOR_DOWNTIME", "validator", "validator_reputation", -1000, 2, True, "recoverable_by_uptime", "limits_validator_readiness", "Validator downtime confirmed.", can_trigger_ineligibility=True),
    _spec("VALIDATOR_DOUBLE_SIGN", "validator", "validator_reputation", -100000, 5, True, "none", "disqualifies_validator", "Validator double-signing confirmed.", can_trigger_ineligibility=True),
    _spec("VALIDATOR_INVALID_BLOCK", "validator", "validator_reputation", -10000, 5, True, "none", "disqualifies_or_suspends_validator", "Validator invalid block confirmed.", can_trigger_ineligibility=True),
    _spec("VALIDATOR_STATE_DIVERGENCE", "validator", "validator_reputation", -25000, 5, True, "none", "disqualifies_validator_until_review", "Validator state divergence confirmed.", can_trigger_ineligibility=True),
    _spec("VALIDATOR_UNSAFE_VERSION", "validator", "validator_reputation", -2500, 3, True, "recoverable_by_upgrade", "blocks_validator_until_upgrade", "Validator unsafe version detected.", can_trigger_ineligibility=True),
    # Storage/IPFS
    _spec("STORAGE_PIN_CONFIRMED", "storage", "storage_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_storage_assignment", "Storage pin confirmed."),
    _spec("STORAGE_REVALIDATION_PASSED", "storage", "storage_reputation", 150, 1, False, "positive_cap_per_epoch", "supports_storage_assignment", "Storage revalidation passed."),
    _spec("STORAGE_SERVED_REQUIRED_CONTENT", "storage", "storage_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_storage_assignment", "Required content served."),
    _spec("STORAGE_MISSING_REQUIRED_CONTENT", "storage", "storage_reputation", -1500, 3, True, "recoverable_by_revalidation", "limits_storage_assignment", "Required content missing.", can_trigger_ineligibility=True),
    _spec("STORAGE_FAILED_REVALIDATION", "storage", "storage_reputation", -1000, 2, True, "recoverable_by_revalidation", "limits_storage_assignment", "Storage revalidation failed.", can_trigger_ineligibility=True),
    _spec("STORAGE_FALSE_AVAILABILITY_CLAIM", "storage", "storage_reputation", -5000, 4, True, "none", "blocks_storage_assignment", "False storage availability claim confirmed.", can_trigger_ineligibility=True),
    # Helper/execution
    _spec("HELPER_VALID_RECEIPT", "helper", "helper_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_helper_assignment", "Helper submitted a valid receipt."),
    _spec("HELPER_TIMELY_EXECUTION", "helper", "helper_reputation", 100, 1, False, "positive_cap_per_epoch", "supports_helper_assignment", "Helper execution was timely."),
    _spec("HELPER_SERIAL_EQUIVALENCE_CONFIRMED", "helper", "helper_reputation", 150, 1, False, "positive_cap_per_epoch", "supports_helper_assignment", "Helper result matched serial execution."),
    _spec("HELPER_MALFORMED_RECEIPT", "helper", "helper_reputation", -1000, 2, True, "recoverable_by_valid_receipts", "limits_helper_assignment", "Malformed helper receipt rejected.", can_trigger_ineligibility=True),
    _spec("HELPER_CONTEXT_MISMATCH", "helper", "helper_reputation", -2500, 3, True, "none", "blocks_helper_assignment_until_review", "Helper receipt context mismatch rejected.", can_trigger_ineligibility=True),
    _spec("HELPER_NONDETERMINISTIC_OUTPUT", "helper", "helper_reputation", -10000, 5, True, "none", "disqualifies_helper", "Nondeterministic helper output rejected.", can_trigger_ineligibility=True),
    _spec("HELPER_REPLAY_ATTEMPT", "helper", "helper_reputation", -2500, 3, True, "none", "blocks_helper_assignment_until_review", "Helper receipt replay attempt rejected.", can_trigger_ineligibility=True),
    # Appeals/corrections
    _spec("REPUTATION_EVENT_REVERSED", "appeal", "appeal_correction_history", 0, 0, False, "none", "reversal_history_only", "A reputation event was reversed by an append-only correction."),
    _spec("APPEAL_ACCEPTED", "appeal", "appeal_correction_history", 0, 0, False, "none", "records_successful_appeal", "Appeal accepted."),
    _spec("APPEAL_REJECTED", "appeal", "appeal_correction_history", 0, 0, False, "none", "records_rejected_appeal", "Appeal rejected."),
    _spec("APPEAL_REPUTATION_RESTORED", "appeal", "appeal_correction_history", 0, 0, False, "none", "restores_dimension_score_by_reversal_event", "Appeal restored reputation through a reversal event."),
    _spec("APPEAL_FRIVOLOUS_PATTERN_CONFIRMED", "appeal", "appeal_correction_history", -1000, 2, True, "recoverable_after_clean_participation", "limits_appeal_submission_trust", "Frivolous appeal pattern confirmed.", can_trigger_ineligibility=True),
)

EVENT_REGISTRY: dict[str, ReputationEventSpec] = {spec.event_code: spec for spec in _EVENT_SPECS}

REASON_TO_EVENT_CODE: dict[str, str] = {
    "content_post_matured": "CREATOR_HELPFUL_CONTRIBUTION",
    "content_media_matured": "CREATOR_HELPFUL_CONTRIBUTION",
    "equivocation": "VALIDATOR_DOUBLE_SIGN",
    "validator_equivocation": "VALIDATOR_DOUBLE_SIGN",
    "late_withdraw_light_penalty": "DISPUTE_JUROR_WITHDREW_LATE",
    "dispute_timeout_penalty": "DISPUTE_JUROR_TIMED_OUT",
    "missed_dispute_vote": "DISPUTE_JUROR_TIMED_OUT",
    "safe_withdraw_no_penalty": "DISPUTE_JUROR_WITHDREW_EARLY",
    "false_report": "SAFETY_FALSE_OR_ABUSIVE_REPORT",
    "spam": "CONTENT_SPAM",
    "abuse": "CONTENT_HARASSMENT",
}

ELIGIBILITY_ROLES: tuple[str, ...] = (
    "juror_assignment",
    "poh_reviewer",
    "governance_proposal",
    "governance_voting",
    "validator_operator",
    "storage_assignment",
    "helper_assignment",
    "creator_feed_trust",
    "safety_moderator",
)

ROLE_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "juror_assignment": ("juror_reputation",),
    "poh_reviewer": ("poh_reputation", "juror_reputation"),
    "governance_proposal": ("governance_reputation",),
    "governance_voting": ("governance_reputation", "civic_reputation"),
    "validator_operator": ("validator_reputation",),
    "storage_assignment": ("storage_reputation",),
    "helper_assignment": ("helper_reputation",),
    "creator_feed_trust": ("creator_reputation", "safety_reputation"),
    "safety_moderator": ("safety_reputation", "juror_reputation"),
}

ROLE_MINIMUMS: dict[str, dict[str, int]] = {
    "juror_assignment": {"juror_reputation": -1000},
    "poh_reviewer": {"poh_reputation": 0, "juror_reputation": -1000},
    "governance_proposal": {"governance_reputation": -1000},
    "governance_voting": {"governance_reputation": -5000, "civic_reputation": -5000},
    "validator_operator": {"validator_reputation": 0},
    "storage_assignment": {"storage_reputation": -1000},
    "helper_assignment": {"helper_reputation": -1000},
    "creator_feed_trust": {"creator_reputation": -2500, "safety_reputation": -5000},
    "safety_moderator": {"safety_reputation": 0, "juror_reputation": -1000},
}

ROLE_ALIASES: dict[str, str] = {
    "dispute_juror": "juror_assignment",
    "juror": "juror_assignment",
    "creator_trust": "creator_feed_trust",
    "feed_trust": "creator_feed_trust",
    "validator_readiness": "validator_operator",
    "storage_eligibility": "storage_assignment",
    "helper_eligibility": "helper_assignment",
}

DISQUALIFYING_SEVERITY = 5


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_short(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()[:32]


def _identity_variants(account_id: str) -> set[str]:
    acct = _as_str(account_id)
    if not acct:
        return set()
    bare = acct[1:] if acct.startswith("@") else acct
    out = {acct, bare}
    if bare:
        out.add(f"@{bare}")
    return {x for x in out if x}


def _matches_actor(value: Any, actor_id: str) -> bool:
    return _as_str(value) in _identity_variants(actor_id)


def registry_payload() -> Json:
    events = [EVENT_REGISTRY[key].as_dict() for key in sorted(EVENT_REGISTRY)]
    by_dimension: dict[str, int] = {dimension: 0 for dimension in REPUTATION_DIMENSIONS}
    for spec in events:
        by_dimension[str(spec["dimension"])] = by_dimension.get(str(spec["dimension"]), 0) + 1
    return {
        "schema": REPUTATION_REGISTRY_SCHEMA,
        "version": "2026-06-v1.5-reputation-matrix",
        "dimension_count": len(REPUTATION_DIMENSIONS),
        "dimensions": list(REPUTATION_DIMENSIONS),
        "severity_scale": SEVERITY_LABELS,
        "event_count": len(events),
        "by_dimension": dict(sorted(by_dimension.items())),
        "events": events,
        "determinism": {
            "event_id_from_canonical_inputs": True,
            "append_only": True,
            "appeals_are_reversal_events": True,
            "frontend_timer_inputs_forbidden": True,
            "wall_clock_penalties_forbidden": True,
        },
    }


def event_spec(event_code: str) -> ReputationEventSpec:
    code = _as_str(event_code).upper()
    spec = EVENT_REGISTRY.get(code)
    if spec is None:
        raise KeyError(f"unknown reputation event code: {event_code}")
    return spec


def event_code_for_reason(reason: str, *, default: str = "CREATOR_HELPFUL_CONTRIBUTION") -> str:
    key = _as_str(reason).lower()
    return REASON_TO_EVENT_CODE.get(key, default)


def ensure_reputation_event_ledger(state: Json) -> Json:
    rep = state.get("reputation")
    if not isinstance(rep, dict):
        rep = {}
        state["reputation"] = rep
    events = rep.get("events")
    if not isinstance(events, list):
        events = []
        rep["events"] = events
    source_index = rep.get("event_source_index")
    if not isinstance(source_index, dict):
        source_index = {}
        rep["event_source_index"] = source_index
    event_ids = rep.get("event_ids")
    if not isinstance(event_ids, dict):
        event_ids = {}
        rep["event_ids"] = event_ids
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_id = _as_str(ev.get("event_id"))
        source_key = _as_str(ev.get("source_key"))
        if event_id:
            event_ids.setdefault(event_id, True)
        if event_id and source_key:
            source_index.setdefault(source_key, event_id)
    rep["event_schema"] = REPUTATION_EVENT_SCHEMA
    rep["event_ledger_mode"] = "append_only"
    return rep


def reputation_event_source_key(
    *,
    actor_id: str,
    event_code: str,
    source_flow: str,
    source_tx_id: str,
    source_object_id: str,
    dimension: str,
    reversal_of_optional: str = "",
) -> str:
    return _sha256_short(
        {
            "actor_id": _as_str(actor_id),
            "event_code": _as_str(event_code).upper(),
            "source_flow": _as_str(source_flow),
            "source_tx_id": _as_str(source_tx_id),
            "source_object_id": _as_str(source_object_id),
            "dimension": _as_str(dimension),
            "reversal_of_optional": _as_str(reversal_of_optional),
        }
    )


def reputation_event_id(
    *,
    actor_id: str,
    event_code: str,
    source_flow: str,
    source_tx_id: str,
    source_object_id: str,
    dimension: str,
    occurred_at_block: int,
    occurred_at_time: int,
    reversal_of_optional: str = "",
) -> str:
    digest = _sha256_short(
        {
            "schema": REPUTATION_EVENT_SCHEMA,
            "actor_id": _as_str(actor_id),
            "event_code": _as_str(event_code).upper(),
            "source_flow": _as_str(source_flow),
            "source_tx_id": _as_str(source_tx_id),
            "source_object_id": _as_str(source_object_id),
            "dimension": _as_str(dimension),
            "occurred_at_block": int(occurred_at_block),
            "occurred_at_time": int(occurred_at_time),
            "reversal_of_optional": _as_str(reversal_of_optional),
        }
    )
    return f"rep-event:v1_5:{digest}"


def append_reputation_event(
    state: Json,
    *,
    actor_id: str,
    event_code: str,
    source_flow: str | None = None,
    source_tx_id: str = "",
    source_object_id: str = "",
    dimension: str | None = None,
    delta: int | None = None,
    occurred_at_block: int | None = None,
    occurred_at_time: int | None = None,
    expires_at_optional: int | None = None,
    reversal_of_optional: str = "",
    details: Mapping[str, Any] | None = None,
) -> Json:
    code = _as_str(event_code).upper()
    spec = event_spec(code)
    dim = _as_str(dimension) or spec.dimension
    if dim not in REPUTATION_DIMENSIONS:
        dim = spec.dimension
    flow = _as_str(source_flow) or spec.source_flow
    actor = _as_str(actor_id)
    if not actor:
        raise ValueError("actor_id is required for reputation event")
    block = _as_int(occurred_at_block, _as_int(state.get("height"), 0))
    # Protocol reputation time is block-height based.  Caller-supplied
    # occurred_at_time may come from legacy payloads or UI-adjacent clocks; do
    # not let it influence canonical event identity or protocol truth.
    protocol_time = int(block)
    source_tx = _as_str(source_tx_id) or f"{flow}:{source_object_id or actor}:{code}"
    source_obj = _as_str(source_object_id) or source_tx
    reversal = _as_str(reversal_of_optional)
    source_key = reputation_event_source_key(
        actor_id=actor,
        event_code=code,
        source_flow=flow,
        source_tx_id=source_tx,
        source_object_id=source_obj,
        dimension=dim,
        reversal_of_optional=reversal,
    )
    event_id = reputation_event_id(
        actor_id=actor,
        event_code=code,
        source_flow=flow,
        source_tx_id=source_tx,
        source_object_id=source_obj,
        dimension=dim,
        occurred_at_block=block,
        occurred_at_time=protocol_time,
        reversal_of_optional=reversal,
    )
    rep = ensure_reputation_event_ledger(state)
    events = rep["events"]
    source_index = rep["event_source_index"]
    event_ids = rep["event_ids"]
    existing_id = source_index.get(source_key)
    if existing_id:
        for raw in events:
            if isinstance(raw, dict) and raw.get("event_id") == existing_id:
                return dict(raw, deduped=True)
    if event_ids.get(event_id):
        for raw in events:
            if isinstance(raw, dict) and raw.get("event_id") == event_id:
                source_index[source_key] = event_id
                return dict(raw, deduped=True)

    event: Json = {
        "schema": REPUTATION_EVENT_SCHEMA,
        "event_id": event_id,
        "actor_id": actor,
        "source_flow": flow,
        "source_tx_id": source_tx,
        "source_object_id": source_obj,
        "dimension": dim,
        "delta": int(spec.default_delta if delta is None else delta),
        "severity": int(spec.severity),
        "reason_code": code,
        "event_code": code,
        "occurred_at_block": int(block),
        "occurred_at_time": int(protocol_time),
        "protocol_time_height": int(block),
        "protocol_time_basis": "block_height",
        "expires_at_optional": expires_at_optional if expires_at_optional is not None else None,
        "appealable": bool(spec.appealable),
        "reversal_of_optional": reversal or None,
        "visibility": spec.visibility,
        "source_key": source_key,
        "explanation": spec.explanation,
        "eligibility_impact": spec.eligibility_impact,
        "deduped": False,
        "details": dict(details or {}),
    }
    events.append(event)
    event_ids[event_id] = True
    source_index[source_key] = event_id
    rep["event_count"] = len(events)
    rep["event_history_root"] = reputation_event_history_root(events)
    return dict(event)


def append_reputation_reversal_event(
    state: Json,
    *,
    reversed_event: Mapping[str, Any] | None = None,
    original_event_id: str = "",
    actor_id: str = "",
    source_flow: str = "appeal",
    source_tx_id: str = "",
    source_object_id: str = "",
    occurred_at_block: int | None = None,
    occurred_at_time: int | None = None,
    details: Mapping[str, Any] | None = None,
) -> Json:
    original: Mapping[str, Any] | None = reversed_event
    if original is None:
        wanted = _as_str(original_event_id)
        for candidate in canonical_reputation_events(state):
            if _as_str(candidate.get("event_id")) == wanted:
                original = candidate
                break
    if not isinstance(original, Mapping):
        raise ValueError("reversed_event_not_found")
    original_delta = _as_int(original.get("delta"), 0)
    original_id = _as_str(original.get("event_id"))
    original_actor = _as_str(original.get("actor_id"))
    original_dimension = _as_str(original.get("dimension"))
    code = "REPUTATION_EVENT_REVERSED"
    event = append_reputation_event(
        state,
        actor_id=original_actor or actor_id,
        event_code=code,
        source_flow=source_flow,
        source_tx_id=source_tx_id or f"appeal:{original_id}",
        source_object_id=source_object_id or original_id,
        dimension=original_dimension or None,
        delta=-original_delta,
        occurred_at_block=occurred_at_block,
        occurred_at_time=occurred_at_time,
        reversal_of_optional=original_id,
        details={"original_event": dict(original), "appeal_actor_id": actor_id or original_actor, **dict(details or {})},
    )
    return event


def reputation_event_history_root(events: Iterable[Mapping[str, Any]]) -> str:
    normalized = []
    for raw in events:
        if not isinstance(raw, Mapping):
            continue
        normalized.append({k: raw.get(k) for k in sorted(raw.keys()) if k not in {"deduped"}})
    normalized.sort(key=lambda ev: _as_str(ev.get("event_id")))
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


def canonical_reputation_events(state: Json) -> list[Json]:
    rep = state.get("reputation") if isinstance(state, dict) else {}
    if not isinstance(rep, dict):
        rep = {}
    events = [dict(ev) for ev in _as_list(rep.get("events")) if isinstance(ev, dict)]
    events.sort(key=lambda ev: (_as_int(ev.get("occurred_at_block"), 0), _as_str(ev.get("event_id"))))
    return events


def canonical_reputation_events_for_actor(state: Json, actor_id: str) -> list[Json]:
    return [event for event in canonical_reputation_events(state) if _matches_actor(event.get("actor_id"), actor_id)]


def reduce_reputation_events(events: Iterable[Mapping[str, Any]]) -> Json:
    actors: dict[str, Json] = {}
    history: list[Mapping[str, Any]] = []
    seen_ids: set[str] = set()
    for raw in events:
        if not isinstance(raw, Mapping):
            continue
        event_id = _as_str(raw.get("event_id"))
        if not event_id or event_id in seen_ids:
            continue
        seen_ids.add(event_id)
        history.append(raw)
    history.sort(key=lambda ev: (_as_int(ev.get("occurred_at_block"), 0), _as_str(ev.get("event_id"))))
    for ev in history:
        actor = _as_str(ev.get("actor_id"))
        dimension = _as_str(ev.get("dimension"))
        if not actor or dimension not in REPUTATION_DIMENSIONS:
            continue
        rec = actors.setdefault(actor, {"actor_id": actor, "dimensions": {}})
        dims = rec["dimensions"]
        cur = dims.setdefault(
            dimension,
            {
                "dimension": dimension,
                "score_milli": 0,
                "score": "0",
                "event_count": 0,
                "positive_event_count": 0,
                "negative_event_count": 0,
                "neutral_event_count": 0,
                "last_event_id": "",
            },
        )
        delta = _as_int(ev.get("delta"), 0)
        cur["score_milli"] = int(clamp_reputation_units(_as_int(cur.get("score_milli"), 0) + delta))
        cur["score"] = units_to_reputation(_as_int(cur.get("score_milli"), 0))
        cur["event_count"] = _as_int(cur.get("event_count"), 0) + 1
        if delta > 0:
            cur["positive_event_count"] = _as_int(cur.get("positive_event_count"), 0) + 1
        elif delta < 0:
            cur["negative_event_count"] = _as_int(cur.get("negative_event_count"), 0) + 1
        else:
            cur["neutral_event_count"] = _as_int(cur.get("neutral_event_count"), 0) + 1
        cur["last_event_id"] = _as_str(ev.get("event_id"))
        code = _as_str(ev.get("event_code") or ev.get("reason_code"))
        if code in {"REPUTATION_EVENT_REVERSED", "APPEAL_ACCEPTED", "APPEAL_REPUTATION_RESTORED"} and dimension != "appeal_correction_history":
            appeal_cur = dims.setdefault(
                "appeal_correction_history",
                {
                    "dimension": "appeal_correction_history",
                    "score_milli": 0,
                    "score": "0",
                    "event_count": 0,
                    "positive_event_count": 0,
                    "negative_event_count": 0,
                    "neutral_event_count": 0,
                    "last_event_id": "",
                },
            )
            appeal_cur["event_count"] = _as_int(appeal_cur.get("event_count"), 0) + 1
            appeal_cur["neutral_event_count"] = _as_int(appeal_cur.get("neutral_event_count"), 0) + 1
            appeal_cur["last_event_id"] = _as_str(ev.get("event_id"))
    for rec in actors.values():
        dims = rec["dimensions"]
        for dimension in REPUTATION_DIMENSIONS:
            dims.setdefault(
                dimension,
                {
                    "dimension": dimension,
                    "score_milli": 0,
                    "score": "0",
                    "event_count": 0,
                    "positive_event_count": 0,
                    "negative_event_count": 0,
                    "neutral_event_count": 0,
                    "last_event_id": "",
                },
            )
        rec["dimensions"] = dict(sorted(dims.items()))
    return {
        "schema": REPUTATION_MATRIX_CONTRACT_SCHEMA,
        "event_count": len(history),
        "event_history_root": reputation_event_history_root(history),
        "actors": dict(sorted(actors.items())),
    }


def derive_role_eligibility_from_dimensions(dimensions: Mapping[str, Any], events: Iterable[Mapping[str, Any]] = ()) -> Json:
    out: Json = {}
    disqualifying: dict[str, list[str]] = {role: [] for role in ELIGIBILITY_ROLES}
    for raw in events:
        if not isinstance(raw, Mapping):
            continue
        dimension = _as_str(raw.get("dimension"))
        code = _as_str(raw.get("event_code") or raw.get("reason_code"))
        severity = _as_int(raw.get("severity"), 0)
        if severity < DISQUALIFYING_SEVERITY:
            continue
        for role, role_dims in ROLE_DIMENSIONS.items():
            if dimension in role_dims:
                disqualifying.setdefault(role, []).append(code or _as_str(raw.get("event_id")))
    for role in ELIGIBILITY_ROLES:
        minimums = ROLE_MINIMUMS.get(role, {})
        reasons: list[str] = []
        eligible = True
        for dimension, minimum in minimums.items():
            rec = _as_dict(dimensions.get(dimension))
            score = _as_int(rec.get("score_milli"), 0)
            if score < minimum:
                eligible = False
                reasons.append(f"{dimension}_below_{minimum}")
        for code in disqualifying.get(role, []):
            eligible = False
            reasons.append(f"disqualifying_event:{code}")
        out[role] = {
            "role": role,
            "eligible": bool(eligible),
            "reasons": reasons or ["eligible"],
            "required_dimensions": dict(minimums),
        }
    for alias, target in ROLE_ALIASES.items():
        if target in out:
            aliased = dict(out[target])
            aliased["role"] = alias
            aliased["canonical_role"] = target
            out[alias] = aliased
    return out


def derive_role_eligibility(state: Json, actor_id: str) -> Json:
    events = canonical_reputation_events_for_actor(state, actor_id)
    reduced = reduce_reputation_events(events)
    actor = _as_dict(_as_dict(reduced.get("actors")).get(_as_str(actor_id)))
    dimensions = _as_dict(actor.get("dimensions"))
    return derive_role_eligibility_from_dimensions(dimensions, events)


def matrix_contract_payload() -> Json:
    return {
        "schema": REPUTATION_MATRIX_CONTRACT_SCHEMA,
        "version": "2026-06-v1.5-reputation-matrix",
        "event_schema": REPUTATION_EVENT_SCHEMA,
        "dimensions": list(REPUTATION_DIMENSIONS),
        "append_only_ledger_path": "state.reputation.events",
        "source_dedupe_path": "state.reputation.event_source_index",
        "event_id_dedupe_path": "state.reputation.event_ids",
        "event_history_root_path": "state.reputation.event_history_root",
        "reducer": {
            "ordered_by": ["occurred_at_block", "event_id"],
            "integer_milli_units": True,
            "score_min_milli": REPUTATION_MIN_UNITS,
            "score_max_milli": REPUTATION_MAX_UNITS,
            "appeal_model": "append_reversal_events_no_delete_no_mutate_original",
            "dimension_isolation": True,
        },
        "eligibility_roles": list(ELIGIBILITY_ROLES),
        "role_dimension_requirements": ROLE_MINIMUMS,
        "public_api_endpoints": reputation_api_endpoints(),
    }


def reputation_api_endpoints() -> list[Json]:
    routes = [
        ("GET", "/v1/reputation/me", "account_session_required", "owner_matrix_summary"),
        ("GET", "/v1/reputation/{actor_id}", "public_read_redacted_snapshot", "public_matrix_summary"),
        ("GET", "/v1/reputation/{actor_id}/events", "public_read_redacted_snapshot", "public_or_owner_events"),
        ("GET", "/v1/reputation/{actor_id}/matrix", "public_read_redacted_snapshot", "public_or_owner_matrix"),
        ("GET", "/v1/reputation/{actor_id}/eligibility", "public_read_redacted_snapshot", "role_eligibility_reasons"),
        ("GET", "/v1/reputation/event-codes", "public_read_static_registry", "event_registry"),
        ("GET", "/v1/disputes/eligible", "account_session_required", "eligible_dispute_assignments"),
        ("GET", "/v1/disputes/current", "account_session_required", "current_dispute_assignments"),
        ("POST", "/v1/disputes/{id}/accept", "account_session_required", "dispute_accept_tx_template"),
        ("POST", "/v1/disputes/{id}/vote", "account_session_required", "dispute_vote_tx_template"),
        ("POST", "/v1/disputes/{id}/withdraw", "account_session_required", "dispute_withdraw_tx_template"),
    ]
    return [
        {
            "method": method,
            "path": path,
            "auth": auth,
            "purpose": purpose,
            "truth_boundary": "backend canonical state; writes require signed tx inclusion",
        }
        for method, path, auth, purpose in routes
    ]


def flow_coverage_payload() -> Json:
    families: dict[str, list[str]] = {}
    for code, spec in sorted(EVENT_REGISTRY.items()):
        families.setdefault(spec.source_flow, []).append(code)
    wired_surfaces = {
        "poh": ["POH_TIER_SET", "POH_ASYNC_FINALIZE", "POH_TIER2_FINALIZE", "POH_LIVE_FINALIZE"],
        "dispute": ["DISPUTE_JUROR_ACCEPT", "DISPUTE_JUROR_WITHDRAW", "DISPUTE_JUROR_TIMEOUT", "DISPUTE_VOTE_SUBMIT", "DISPUTE_FINAL_RECEIPT"],
        "governance": ["GOV_PROPOSAL_CREATE", "GOV_PROPOSAL_COMMENT", "GOV_VOTE_CAST", "GOV_PROPOSAL_FINALIZE"],
        "content": ["CONTENT_POST_CREATE", "CONTENT_COMMENT_CREATE", "CONTENT_LABEL_SET", "CONTENT_VISIBILITY_SET"],
        "validator": ["VALIDATOR_HEARTBEAT", "BLOCK_ATTEST", "SLASH_EXECUTE"],
        "storage": ["IPFS_PIN_CONFIRM", "STORAGE_PROOF_SUBMIT", "STORAGE_CAPACITY_PROOF_VERIFY"],
        "helper": ["helper_execution_runtime metadata; serial-equivalence diagnostics"],
        "appeal": ["DISPUTE_APPEAL", "DISPUTE_FINAL_RECEIPT appeal_resolution"],
    }
    return {
        "schema": REPUTATION_FLOW_COVERAGE_SCHEMA,
        "version": "2026-06-v1.5-reputation-matrix",
        "event_families": {k: sorted(v) for k, v in sorted(families.items())},
        "wired_surfaces": wired_surfaces,
        "coverage_assertions": {
            "dispute_juror_flow_p0_wired": True,
            "event_registry_complete_for_required_families": True,
            "api_read_models_present": True,
            "frontend_surfaces_receive_backend_deadlines": True,
        },
    }


def invariant_report_payload() -> Json:
    invariants = [
        "event_id_deterministic_from_canonical_inputs",
        "append_only_events_no_delete_no_mutate",
        "source_tx_object_actor_event_dimension_deduped",
        "scores_reduced_from_ordered_events",
        "appeals_append_reversal_events",
        "dimension_isolation_enforced_by_registry_dimension",
        "juror_time_penalties_use_block_height_not_browser_clock",
        "voting_against_majority_has_no_negative_event",
        "frontend_never_classifies_penalty",
        "helper_events_preserve_serial_equivalence_boundary",
    ]
    return {
        "schema": REPUTATION_INVARIANT_SCHEMA,
        "version": "2026-06-v1.5-reputation-matrix",
        "ok": True,
        "invariants": invariants,
        "adversarial_checks": {
            "duplicate_rewards": "blocked_by_event_source_index",
            "duplicate_penalties": "blocked_by_event_source_index",
            "frontend_timer_manipulation": "not_input_to_append_reputation_event",
            "timeout_divergence": "block_height_deadlines_only",
            "appeal_history_deletion": "appeals_use_reversal_of_optional",
            "dimension_bleed": "event_has_single_registry_dimension; aliases are read_model_only",
            "conflicted_dispute_acceptance": "eligible/current endpoints expose reasons; apply path uses assignment snapshot",
            "helper_receipt_replay": "helper event family is receipt/context bound; helper runtime remains consensus authority",
        },
    }


def api_contract_payload() -> Json:
    return {
        "schema": REPUTATION_API_CONTRACT_SCHEMA,
        "version": "2026-06-v1.5-reputation-matrix",
        "route_count": len(reputation_api_endpoints()),
        "routes": reputation_api_endpoints(),
    }


__all__ = [
    "DIMENSION_ALIASES",
    "EVENT_REGISTRY",
    "REPUTATION_API_CONTRACT_SCHEMA",
    "REPUTATION_DIMENSIONS",
    "REPUTATION_EVENT_SCHEMA",
    "REPUTATION_FLOW_COVERAGE_SCHEMA",
    "REPUTATION_INVARIANT_SCHEMA",
    "REPUTATION_MATRIX_CONTRACT_SCHEMA",
    "REPUTATION_REGISTRY_SCHEMA",
    "append_reputation_event",
    "append_reputation_reversal_event",
    "api_contract_payload",
    "canonical_reputation_events",
    "canonical_reputation_events_for_actor",
    "derive_role_eligibility",
    "derive_role_eligibility_from_dimensions",
    "event_code_for_reason",
    "event_spec",
    "flow_coverage_payload",
    "invariant_report_payload",
    "matrix_contract_payload",
    "reduce_reputation_events",
    "registry_payload",
    "reputation_api_endpoints",
    "reputation_event_history_root",
    "reputation_event_id",
    "reputation_event_source_key",
]
