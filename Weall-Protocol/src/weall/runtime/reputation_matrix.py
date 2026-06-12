from __future__ import annotations

"""Deterministic Reputation Matrix read model.

The matrix is intentionally derived from canonical protocol state and committed
helper metadata. It does not mutate ledger state, does not read wall-clock time,
and does not introduce floating-point scoring. New protocol-critical gating must
consume state-rooted reputation events before it affects consensus behavior; this
read model is the public/API bridge for the matrix dimensions.
"""

from dataclasses import dataclass
from typing import Any, Iterable

from weall.runtime.reputation_events import (
    DIMENSION_ALIASES,
    REPUTATION_DIMENSIONS,
    canonical_reputation_events_for_actor,
    derive_role_eligibility_from_dimensions,
    reduce_reputation_events,
)
from weall.runtime.reputation_units import (
    REPUTATION_MAX_UNITS,
    REPUTATION_MIN_UNITS,
    account_reputation_units,
    clamp_reputation_units,
    reputation_to_units,
    units_to_reputation,
)

Json = dict[str, Any]

MATRIX_VERSION = 1
MATRIX_SCORE_MIN = REPUTATION_MIN_UNITS
MATRIX_SCORE_MAX = REPUTATION_MAX_UNITS

LEGACY_PUBLIC_DIMENSIONS: tuple[str, ...] = (
    "juror",
    "dispute_participation",
    "validator",
    "helper",
    "storage",
    "creator",
    "governance",
    "identity_poh",
    "social_trust",
)

PUBLIC_DIMENSIONS: tuple[str, ...] = REPUTATION_DIMENSIONS + LEGACY_PUBLIC_DIMENSIONS
PRIVATE_DIMENSIONS: tuple[str, ...] = ("abuse_risk",)
ALL_DIMENSIONS: tuple[str, ...] = PUBLIC_DIMENSIONS + PRIVATE_DIMENSIONS

# Conservative default weights. These are read-model weights, not economic value.
BASELINE_DIMENSION_WEIGHTS: dict[str, int] = {
    "poh_reputation": 100,
    "civic_reputation": 100,
    "juror_reputation": 100,
    "governance_reputation": 100,
    "creator_reputation": 100,
    "safety_reputation": 100,
    "validator_reputation": 100,
    "storage_reputation": 100,
    "helper_reputation": 100,
    "appeal_correction_history": 0,
    "juror": 100,
    "dispute_participation": 100,
    "validator": 100,
    "helper": 100,
    "storage": 100,
    "creator": 100,
    "governance": 100,
    "identity_poh": 100,
    "social_trust": 100,
    "abuse_risk": 0,  # internal signal, never raises the public aggregate
}

REASON_DIMENSION_MAP: dict[str, tuple[str, ...]] = {
    "content_post_matured": ("creator", "social_trust"),
    "content_media_matured": ("creator",),
    "equivocation": ("validator", "abuse_risk"),
    "validator_equivocation": ("validator", "abuse_risk"),
    "late_withdraw_light_penalty": ("juror", "dispute_participation"),
    "dispute_timeout_penalty": ("juror", "dispute_participation"),
    "missed_dispute_vote": ("juror", "dispute_participation"),
    "false_report": ("social_trust", "abuse_risk"),
    "spam": ("creator", "social_trust", "abuse_risk"),
    "abuse": ("creator", "social_trust", "abuse_risk"),
}


@dataclass(frozen=True)
class MatrixEvent:
    event_id: str
    account_id: str
    dimension: str
    event_type: str
    delta_milli: int
    source: str
    source_ref: str
    visibility: str = "public"
    polarity: str = "neutral"
    details: Json | None = None

    def as_dict(self) -> Json:
        return {
            "event_id": self.event_id,
            "account_id": self.account_id,
            "dimension": self.dimension,
            "event_type": self.event_type,
            "delta_milli": int(self.delta_milli),
            "source": self.source,
            "source_ref": self.source_ref,
            "visibility": self.visibility,
            "polarity": self.polarity,
            "details": dict(self.details or {}),
        }


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


def _identity_variants(account_id: str) -> set[str]:
    acct = _as_str(account_id)
    if not acct:
        return set()
    bare = acct[1:] if acct.startswith("@") else acct
    out = {acct, bare}
    if bare:
        out.add(f"@{bare}")
    return {x for x in out if x}


def _matches_account(value: Any, account_id: str) -> bool:
    return _as_str(value) in _identity_variants(account_id)


def _stable_event_id(
    *,
    account_id: str,
    dimension: str,
    event_type: str,
    source: str,
    source_ref: str,
) -> str:
    return f"rep:v{MATRIX_VERSION}:{dimension}:{event_type}:{source}:{source_ref}:{account_id}"


def _polarity(delta_milli: int) -> str:
    if int(delta_milli) > 0:
        return "positive"
    if int(delta_milli) < 0:
        return "negative"
    return "neutral"


def _event(
    *,
    account_id: str,
    dimension: str,
    event_type: str,
    delta_milli: int,
    source: str,
    source_ref: str,
    visibility: str | None = None,
    details: Json | None = None,
) -> MatrixEvent:
    vis = visibility or ("private" if dimension in PRIVATE_DIMENSIONS else "public")
    return MatrixEvent(
        event_id=_stable_event_id(
            account_id=account_id,
            dimension=dimension,
            event_type=event_type,
            source=source,
            source_ref=source_ref,
        ),
        account_id=account_id,
        dimension=dimension,
        event_type=event_type,
        delta_milli=int(delta_milli),
        source=source,
        source_ref=source_ref,
        visibility=vis,
        polarity=_polarity(delta_milli),
        details=details or {},
    )


def _dedupe_events(events: Iterable[MatrixEvent]) -> list[MatrixEvent]:
    out: dict[str, MatrixEvent] = {}
    for event in events:
        if event.event_id not in out:
            out[event.event_id] = event
    return [out[k] for k in sorted(out.keys())]


def _score_level(score_milli: int) -> str:
    score = int(score_milli)
    if score <= -50_000:
        return "critical"
    if score < 0:
        return "at_risk"
    if score < 1_000:
        return "neutral"
    if score < 5_000:
        return "building"
    return "strong"


def _dimensions_from_events(events: list[MatrixEvent]) -> Json:
    dimensions: Json = {}
    for dimension in ALL_DIMENSIONS:
        dims_events = [event for event in events if event.dimension == dimension]
        score = clamp_reputation_units(sum(int(event.delta_milli) for event in dims_events))
        dimensions[dimension] = {
            "dimension": dimension,
            "score_milli": int(score),
            "score": units_to_reputation(score),
            "level": _score_level(score),
            "visibility": "private" if dimension in PRIVATE_DIMENSIONS else "public",
            "weight_bps": int(BASELINE_DIMENSION_WEIGHTS.get(dimension, 0)),
            "event_count": len(dims_events),
            "positive_event_count": sum(1 for event in dims_events if event.polarity == "positive"),
            "negative_event_count": sum(1 for event in dims_events if event.polarity == "negative"),
            "neutral_event_count": sum(1 for event in dims_events if event.polarity == "neutral"),
        }
    return dimensions


def _aggregate_public_score(dimensions: Json) -> int:
    total_weight = 0
    weighted = 0
    for dimension in PUBLIC_DIMENSIONS:
        rec = _as_dict(dimensions.get(dimension))
        weight = _as_int(rec.get("weight_bps"), 0)
        if weight <= 0:
            continue
        total_weight += weight
        weighted += _as_int(rec.get("score_milli"), 0) * weight
    if total_weight <= 0:
        return 0
    return int(clamp_reputation_units(weighted // total_weight))


def _canonical_ledger_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    for rec in canonical_reputation_events_for_actor(state, account_id):
        dimension = _as_str(rec.get("dimension"))
        event_type = _as_str(rec.get("event_code") or rec.get("reason_code") or "REPUTATION_EVENT")
        delta_milli = _as_int(rec.get("delta"), 0)
        source_ref = _as_str(rec.get("event_id"))
        details = {
            "source_flow": _as_str(rec.get("source_flow")),
            "source_tx_id": _as_str(rec.get("source_tx_id")),
            "source_object_id": _as_str(rec.get("source_object_id")),
            "severity": _as_int(rec.get("severity"), 0),
            "appealable": bool(rec.get("appealable", False)),
            "reversal_of_optional": _as_str(rec.get("reversal_of_optional")),
            "explanation": _as_str(rec.get("explanation")),
            "eligibility_impact": _as_str(rec.get("eligibility_impact")),
        }
        visibility = _as_str(rec.get("visibility") or "public")
        if visibility == "permissioned":
            visibility = "private"
        if dimension in ALL_DIMENSIONS:
            events.append(
                _event(
                    account_id=account_id,
                    dimension=dimension,
                    event_type=event_type,
                    delta_milli=delta_milli,
                    source="reputation_event_ledger",
                    source_ref=source_ref,
                    visibility=visibility,
                    details=details,
                )
            )
        for alias in DIMENSION_ALIASES.get(dimension, ()):
            if alias not in ALL_DIMENSIONS:
                continue
            # Alias dimensions keep old UI/tests working while the canonical
            # matrix dimensions remain the protocol source of truth.
            events.append(
                _event(
                    account_id=account_id,
                    dimension=alias,
                    event_type=event_type,
                    delta_milli=delta_milli,
                    source="reputation_event_ledger_alias",
                    source_ref=source_ref,
                    visibility=visibility,
                    details={**details, "canonical_dimension": dimension},
                )
            )
    return events


def _scalar_reputation_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    for idx, raw in enumerate(_as_list(_as_dict(state.get("reputation")).get("deltas"))):
        rec = _as_dict(raw)
        if not _matches_account(rec.get("account_id"), account_id):
            continue
        reason = _as_str(rec.get("reason") or "reputation_delta") or "reputation_delta"
        delta_milli = _as_int(rec.get("delta_milli"), reputation_to_units(rec.get("delta")))
        dims = REASON_DIMENSION_MAP.get(reason, ())
        if not dims:
            source = _as_dict(rec.get("payload")).get("source")
            if source == "consensus":
                dims = ("validator", "abuse_risk") if delta_milli < 0 else ("validator",)
            elif reason.startswith("content_"):
                dims = ("creator", "social_trust")
            else:
                dims = ("social_trust", "abuse_risk") if delta_milli < 0 else ("social_trust",)
        source_ref = _as_str(rec.get("delta_id") or f"delta:{idx}")
        for dimension in dims:
            events.append(
                _event(
                    account_id=account_id,
                    dimension=dimension,
                    event_type=reason.upper(),
                    delta_milli=delta_milli,
                    source="reputation_delta",
                    source_ref=source_ref,
                    details={"reason": reason},
                )
            )
    return events


def _dispute_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    variants = _identity_variants(account_id)

    # Protocol-state juror reputation events are the canonical source for
    # withdrawal and timeout scoring.  They are state-rooted and deduped by
    # event id by the derive layer.
    juror_rep = _as_dict(state.get("dispute_juror_reputation_events"))
    for event_id, raw in sorted(juror_rep.items(), key=lambda item: str(item[0])):
        rec = _as_dict(raw)
        if not _matches_account(rec.get("account_id") or rec.get("juror"), account_id):
            continue
        delta = _as_int(rec.get("delta_milli"), 0)
        etype = _as_str(rec.get("event_type") or "DISPUTE_JUROR_REPUTATION_EVENT")
        source_ref = _as_str(rec.get("event_id") or event_id)
        details = {
            "dispute_id": _as_str(rec.get("dispute_id")),
            "reason": _as_str(rec.get("reason")),
            "at_height": _as_int(rec.get("at_height"), 0),
        }
        for dimension in ("juror", "dispute_participation"):
            events.append(
                _event(
                    account_id=account_id,
                    dimension=dimension,
                    event_type=etype,
                    delta_milli=delta,
                    source="dispute_juror_reputation",
                    source_ref=source_ref,
                    visibility=_as_str(rec.get("visibility") or "public"),
                    details=details,
                )
            )

    disputes = _as_dict(state.get("disputes_by_id"))
    for dispute_id, raw in sorted(disputes.items(), key=lambda item: str(item[0])):
        dispute = _as_dict(raw)
        did = _as_str(dispute.get("dispute_id") or dispute.get("id") or dispute_id)
        juror_records = _as_dict(dispute.get("jurors"))
        legacy_assigned = _as_dict(dispute.get("assigned_jurors"))
        votes = _as_dict(dispute.get("votes"))
        stage = _as_str(dispute.get("stage") or dispute.get("status")).lower()
        assignment: Json | None = None
        signer_key = ""
        for key, value in juror_records.items():
            if _as_str(key) in variants:
                assignment = _as_dict(value)
                signer_key = _as_str(key)
                break
        if assignment is None:
            for key, value in legacy_assigned.items():
                if _as_str(key) in variants:
                    assignment = _as_dict(value)
                    signer_key = _as_str(key)
                    break
        if assignment is not None:
            status = _as_str(assignment.get("status") or "assigned").lower()
            source_ref = f"{did}:{signer_key or account_id}"
            if status in {"accepted", "attended", "present"}:
                has_vote = any(_as_str(key) in variants for key in votes.keys())
                if has_vote:
                    delta = 250
                    etype = "DISPUTE_VOTE_COMPLETED"
                elif stage in {"resolved", "finalized", "closed", "report_upheld", "report_not_upheld"}:
                    delta = -1_000
                    etype = "DISPUTE_ASSIGNED_NO_VOTE"
                else:
                    delta = 0
                    etype = "DISPUTE_ACCEPTED_ACTIVE"
                for dimension in ("juror", "dispute_participation"):
                    events.append(
                        _event(
                            account_id=account_id,
                            dimension=dimension,
                            event_type=etype,
                            delta_milli=delta,
                            source="dispute",
                            source_ref=source_ref,
                            details={
                                "dispute_id": did,
                                "stage": stage,
                                "vote_deadline_height": _as_int(assignment.get("vote_deadline_height"), 0),
                                "safe_withdraw_until_height": _as_int(assignment.get("safe_withdraw_until_height"), 0),
                            },
                        )
                    )
            elif status == "declined":
                events.append(
                    _event(
                        account_id=account_id,
                        dimension="dispute_participation",
                        event_type="DISPUTE_JUROR_DECLINED",
                        delta_milli=0,
                        source="dispute",
                        source_ref=source_ref,
                        details={"dispute_id": did},
                    )
                )
            elif status in {"withdrawn", "timed_out"}:
                events.append(
                    _event(
                        account_id=account_id,
                        dimension="dispute_participation",
                        event_type=f"DISPUTE_JUROR_{status.upper()}",
                        delta_milli=0,
                        source="dispute",
                        source_ref=source_ref,
                        details={"dispute_id": did, "status": status},
                    )
                )
            else:
                events.append(
                    _event(
                        account_id=account_id,
                        dimension="dispute_participation",
                        event_type="DISPUTE_JUROR_ASSIGNED",
                        delta_milli=0,
                        source="dispute",
                        source_ref=source_ref,
                        details={"dispute_id": did, "status": status},
                    )
                )
        reporter = dispute.get("reporter") or dispute.get("created_by") or dispute.get("account_id")
        if _matches_account(reporter, account_id):
            resolution = _as_dict(dispute.get("resolution") or dispute.get("final_resolution"))
            outcome = _as_str(resolution.get("outcome") or resolution.get("decision") or stage).lower()
            delta = 100 if outcome in {"report_upheld", "uphold", "upheld", "remove", "hidden"} else 0
            events.append(
                _event(
                    account_id=account_id,
                    dimension="social_trust",
                    event_type="DISPUTE_REPORT_CREATED",
                    delta_milli=delta,
                    source="dispute",
                    source_ref=f"{did}:reporter",
                    details={"dispute_id": did, "outcome": outcome},
                )
            )
    acct = _as_dict(_as_dict(state.get("accounts")).get(account_id))
    missed = _as_int(acct.get("missed_vote_count") or acct.get("dispute_missed_vote_count"), 0)
    if missed > 0:
        for dimension in ("juror", "dispute_participation"):
            events.append(
                _event(
                    account_id=account_id,
                    dimension=dimension,
                    event_type="DISPUTE_MISSED_VOTE_COUNT",
                    delta_milli=-500 * missed,
                    source="account_state",
                    source_ref=f"missed_vote_count:{missed}",
                    details={"missed_vote_count": missed},
                )
            )
    return events


def _governance_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    proposals = _as_dict(state.get("gov_proposals_by_id"))
    variants = _identity_variants(account_id)
    for proposal_id, raw in sorted(proposals.items(), key=lambda item: str(item[0])):
        proposal = _as_dict(raw)
        pid = _as_str(proposal.get("proposal_id") or proposal.get("id") or proposal_id)
        if _matches_account(proposal.get("creator"), account_id):
            stage = _as_str(proposal.get("stage") or "draft").lower()
            delta = -100 if stage == "withdrawn" else 100
            events.append(
                _event(
                    account_id=account_id,
                    dimension="governance",
                    event_type="GOV_PROPOSAL_CREATED" if delta >= 0 else "GOV_PROPOSAL_WITHDRAWN",
                    delta_milli=delta,
                    source="governance",
                    source_ref=f"{pid}:creator",
                    details={"proposal_id": pid, "stage": stage},
                )
            )
        for vote_bucket_name in ("votes", "poll_votes"):
            vote_bucket = _as_dict(proposal.get(vote_bucket_name))
            for voter in vote_bucket.keys():
                if _as_str(voter) in variants:
                    events.append(
                        _event(
                            account_id=account_id,
                            dimension="governance",
                            event_type="GOV_VOTE_CAST",
                            delta_milli=50,
                            source="governance",
                            source_ref=f"{pid}:{vote_bucket_name}:{voter}",
                            details={"proposal_id": pid, "vote_bucket": vote_bucket_name},
                        )
                    )
        for idx, raw_comment in enumerate(_as_list(proposal.get("comments"))):
            comment = _as_dict(raw_comment)
            if _matches_account(comment.get("by") or comment.get("author") or comment.get("account_id"), account_id):
                events.append(
                    _event(
                        account_id=account_id,
                        dimension="governance",
                        event_type="GOV_COMMENT_ADDED",
                        delta_milli=10,
                        source="governance",
                        source_ref=f"{pid}:comment:{idx}",
                        details={"proposal_id": pid},
                    )
                )
    return events


def _identity_poh_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    accounts = _as_dict(state.get("accounts"))
    acct = _as_dict(accounts.get(account_id))
    tier = _as_int(acct.get("poh_tier"), 0)
    if tier > 0:
        events.append(
            _event(
                account_id=account_id,
                dimension="identity_poh",
                event_type="POH_TIER_ATTAINED",
                delta_milli=1_000 * min(tier, 2),
                source="account_state",
                source_ref=f"poh_tier:{tier}",
                details={"poh_tier": tier},
            )
        )
    if bool(acct.get("poh_reviewer_eligible", True)) is False:
        events.append(
            _event(
                account_id=account_id,
                dimension="identity_poh",
                event_type="POH_REVIEWER_INELIGIBLE",
                delta_milli=-1_000,
                source="account_state",
                source_ref="poh_reviewer_ineligible",
                details={},
            )
        )
    poh = _as_dict(state.get("poh"))
    for root_name in ("async_cases", "tier2_cases", "live_cases"):
        cases = _as_dict(poh.get(root_name))
        for case_id, raw in sorted(cases.items(), key=lambda item: str(item[0])):
            case = _as_dict(raw)
            subject = case.get("account_id") or case.get("subject") or case.get("user")
            if _matches_account(subject, account_id):
                status = _as_str(case.get("status") or case.get("outcome")).lower()
                delta = 500 if status in {"approved", "passed", "verified", "finalized"} else 0
                events.append(
                    _event(
                        account_id=account_id,
                        dimension="identity_poh",
                        event_type="POH_CASE_RECORDED",
                        delta_milli=delta,
                        source="poh",
                        source_ref=f"{root_name}:{case_id}",
                        details={"case_id": _as_str(case_id), "status": status},
                    )
                )
            for bucket in ("assigned_jurors", "reviewers", "votes", "reviews"):
                value = case.get(bucket)
                if isinstance(value, dict):
                    for actor in value.keys():
                        if _as_str(actor) in _identity_variants(account_id):
                            events.append(
                                _event(
                                    account_id=account_id,
                                    dimension="identity_poh",
                                    event_type="POH_REVIEW_PARTICIPATION",
                                    delta_milli=100,
                                    source="poh",
                                    source_ref=f"{root_name}:{case_id}:{bucket}:{actor}",
                                    details={"case_id": _as_str(case_id), "bucket": bucket},
                                )
                            )
                elif isinstance(value, list):
                    for idx, actor in enumerate(value):
                        if _matches_account(actor, account_id):
                            events.append(
                                _event(
                                    account_id=account_id,
                                    dimension="identity_poh",
                                    event_type="POH_REVIEW_PARTICIPATION",
                                    delta_milli=100,
                                    source="poh",
                                    source_ref=f"{root_name}:{case_id}:{bucket}:{idx}",
                                    details={"case_id": _as_str(case_id), "bucket": bucket},
                                )
                            )
    return events


def _validator_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    roles_validators = _as_dict(_as_dict(state.get("roles")).get("validators"))
    active = {_as_str(v) for v in _as_list(roles_validators.get("active_set")) if _as_str(v)}
    validators_root = _as_dict(state.get("validators"))
    registry = _as_dict(validators_root.get("registry"))
    rec = _as_dict(registry.get(account_id))
    if rec or account_id in active:
        status = _as_str(rec.get("status") or ("active" if account_id in active else "registered"))
        delta = 1_000 if status in {"active", "pending_activation", "candidate"} else 0
        events.append(
            _event(
                account_id=account_id,
                dimension="validator",
                event_type="VALIDATOR_STATUS_RECORDED",
                delta_milli=delta,
                source="validator_state",
                source_ref=f"status:{status or 'unknown'}",
                details={"status": status, "active": account_id in active},
            )
        )
    slashing = _as_dict(state.get("slashing"))
    for slash_id, raw in sorted(_as_dict(slashing.get("executions")).items(), key=lambda item: str(item[0])):
        rec = _as_dict(raw)
        if _matches_account(rec.get("validator") or rec.get("account"), account_id):
            for dimension in ("validator", "abuse_risk"):
                events.append(
                    _event(
                        account_id=account_id,
                        dimension=dimension,
                        event_type="VALIDATOR_SLASH_EXECUTED",
                        delta_milli=-25_000,
                        source="slashing",
                        source_ref=_as_str(slash_id),
                        details={"type": _as_str(rec.get("type") or rec.get("reason"))},
                    )
                )
    return events


def _helper_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    meta = _as_dict(state.get("meta"))
    roots = [state.get("helper_reputation"), meta.get("helper_reputation")]
    for root in roots:
        helper_root = _as_dict(root)
        if not helper_root:
            continue
        rec = _as_dict(helper_root.get(account_id))
        if not rec:
            helpers = _as_dict(helper_root.get("helpers"))
            rec = _as_dict(helpers.get(account_id))
        if not rec:
            continue
        score = _as_int(rec.get("score") or rec.get("score_milli"), 0)
        if -100 <= score <= 100:
            score *= 1000
        events.append(
            _event(
                account_id=account_id,
                dimension="helper",
                event_type="HELPER_REPUTATION_RECORDED",
                delta_milli=score,
                source="helper_metadata",
                source_ref="helper_reputation",
                details={
                    "success": _as_int(rec.get("success"), 0),
                    "timeout": _as_int(rec.get("timeout"), 0),
                    "fraud": _as_int(rec.get("fraud"), 0),
                },
            )
        )
    return events


def _storage_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    roles = _as_dict(state.get("roles"))
    node_ops = _as_dict(roles.get("node_operators"))
    node_rec = _as_dict(_as_dict(node_ops.get("by_id")).get(account_id))
    storage_rec = _as_dict(_as_dict(node_rec.get("responsibilities")).get("storage"))
    storage_root = _as_dict(state.get("storage"))
    operator_rec = _as_dict(_as_dict(storage_root.get("operators")).get(account_id))
    merged = dict(operator_rec)
    merged.update(storage_rec)
    if merged:
        active = bool(merged.get("active") or merged.get("enabled"))
        availability = _as_int(merged.get("availability_score_milli"), 1000 if active else 0)
        delta = max(0, min(1000, availability)) if active else 0
        events.append(
            _event(
                account_id=account_id,
                dimension="storage",
                event_type="STORAGE_RESPONSIBILITY_RECORDED",
                delta_milli=delta,
                source="storage_state",
                source_ref="operator_status",
                details={
                    "active": active,
                    "proof_status": _as_str(merged.get("proof_status")),
                    "availability_score_milli": availability,
                },
            )
        )
        failed = _as_int(merged.get("failed_challenge_count"), 0)
        missed = _as_int(merged.get("missed_challenge_count"), 0)
        if failed or missed:
            events.append(
                _event(
                    account_id=account_id,
                    dimension="storage",
                    event_type="STORAGE_PROOF_FAILURES",
                    delta_milli=-(250 * failed + 500 * missed),
                    source="storage_state",
                    source_ref=f"failures:{failed}:missed:{missed}",
                    details={"failed_challenge_count": failed, "missed_challenge_count": missed},
                )
            )
    return events


def _creator_social_events(state: Json, account_id: str) -> list[MatrixEvent]:
    events: list[MatrixEvent] = []
    content = _as_dict(state.get("content"))
    posts = _as_dict(content.get("posts"))
    comments = _as_dict(content.get("comments"))
    post_count = 0
    hidden_count = 0
    for post_id, raw in sorted(posts.items(), key=lambda item: str(item[0])):
        post = _as_dict(raw)
        if not _matches_account(post.get("author") or post.get("owner") or post.get("account_id"), account_id):
            continue
        deleted = bool(post.get("deleted", False))
        vis = _as_str(post.get("visibility") or "public").lower()
        if deleted or vis in {"hidden", "deleted", "removed"}:
            hidden_count += 1
            continue
        post_count += 1
        events.append(
            _event(
                account_id=account_id,
                dimension="creator",
                event_type="CONTENT_POST_PRESENT",
                delta_milli=25,
                source="content",
                source_ref=_as_str(post.get("post_id") or post.get("id") or post_id),
                details={"visibility": vis or "public"},
            )
        )
    comment_count = 0
    for comment_id, raw in sorted(comments.items(), key=lambda item: str(item[0])):
        comment = _as_dict(raw)
        if _matches_account(comment.get("author") or comment.get("owner") or comment.get("account_id"), account_id):
            comment_count += 1
    if comment_count:
        events.append(
            _event(
                account_id=account_id,
                dimension="social_trust",
                event_type="CONTENT_COMMENTS_PRESENT",
                delta_milli=min(500, comment_count * 10),
                source="content",
                source_ref=f"comments:{comment_count}",
                details={"comment_count": comment_count},
            )
        )
    if hidden_count:
        for dimension in ("creator", "social_trust", "abuse_risk"):
            events.append(
                _event(
                    account_id=account_id,
                    dimension=dimension,
                    event_type="CONTENT_HIDDEN_OR_REMOVED",
                    delta_milli=-250 * hidden_count,
                    source="content",
                    source_ref=f"hidden:{hidden_count}",
                    details={"hidden_count": hidden_count, "post_count": post_count},
                )
            )
    return events


def collect_reputation_matrix_events(state: Json, account_id: str) -> list[Json]:
    """Return deterministic matrix events for an account.

    Events are derived from committed state surfaces. The list is sorted by stable
    event id so callers get replay-stable output independent of Python dict
    insertion order.
    """
    acct = _as_str(account_id)
    if not acct:
        return []
    events: list[MatrixEvent] = []
    events.extend(_canonical_ledger_events(state, acct))
    events.extend(_scalar_reputation_events(state, acct))
    events.extend(_dispute_events(state, acct))
    events.extend(_governance_events(state, acct))
    events.extend(_identity_poh_events(state, acct))
    events.extend(_validator_events(state, acct))
    events.extend(_helper_events(state, acct))
    events.extend(_storage_events(state, acct))
    events.extend(_creator_social_events(state, acct))
    return [event.as_dict() for event in _dedupe_events(events)]


def derive_reputation_matrix(
    state: Json,
    account_id: str,
    *,
    reveal_private: bool = False,
    include_events: bool = False,
) -> Json:
    """Derive the Reputation Matrix for ``account_id`` from canonical state."""
    acct_id = _as_str(account_id)
    raw_events = collect_reputation_matrix_events(state, acct_id)
    events = [MatrixEvent(**event) for event in raw_events]
    dimensions = _dimensions_from_events(events)
    scalar_units = account_reputation_units(_as_dict(_as_dict(state.get("accounts")).get(acct_id)), default=0)
    aggregate = _aggregate_public_score(dimensions)
    public_dims = {name: dimensions[name] for name in PUBLIC_DIMENSIONS}
    exposed_dimensions = dict(dimensions) if reveal_private else public_dims
    exposed_events = [event.as_dict() for event in events if reveal_private or event.visibility == "public"]
    canonical_events = canonical_reputation_events_for_actor(state, acct_id)
    canonical_reduction = reduce_reputation_events(canonical_events)
    canonical_actor = _as_dict(_as_dict(canonical_reduction.get("actors")).get(acct_id))
    canonical_dimensions = _as_dict(canonical_actor.get("dimensions"))
    eligibility = derive_role_eligibility_from_dimensions(canonical_dimensions, canonical_events)
    out: Json = {
        "ok": True,
        "version": MATRIX_VERSION,
        "account_id": acct_id,
        "deterministic": True,
        "state_source": "canonical_state_read_model",
        "formula": {
            "version": MATRIX_VERSION,
            "score_min_milli": MATRIX_SCORE_MIN,
            "score_max_milli": MATRIX_SCORE_MAX,
            "integer_milli_units": True,
            "float_scoring": False,
            "wall_clock_time": False,
        },
        "scalar_reputation": {
            "score_milli": int(scalar_units),
            "score": units_to_reputation(scalar_units),
            "level": _score_level(scalar_units),
        },
        "aggregate_public_score_milli": int(aggregate),
        "aggregate_public_score": units_to_reputation(aggregate),
        "aggregate_public_level": _score_level(aggregate),
        "dimensions": exposed_dimensions,
        "canonical_dimensions": canonical_dimensions,
        "eligibility": eligibility,
        "event_history_root": canonical_reduction.get("event_history_root"),
        "visibility": {
            "public_dimensions": list(PUBLIC_DIMENSIONS),
            "private_dimensions": list(PRIVATE_DIMENSIONS),
            "private_revealed": bool(reveal_private),
        },
        "event_count": len(exposed_events),
    }
    if include_events:
        out["events"] = exposed_events
    return out


__all__ = [
    "ALL_DIMENSIONS",
    "MATRIX_VERSION",
    "PRIVATE_DIMENSIONS",
    "PUBLIC_DIMENSIONS",
    "collect_reputation_matrix_events",
    "derive_reputation_matrix",
]
