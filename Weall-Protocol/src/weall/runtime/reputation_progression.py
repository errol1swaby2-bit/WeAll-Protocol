from __future__ import annotations

"""Public reputation progression and anti-farming read model."""

from typing import Any

from weall.runtime.reputation_events import EVENT_REGISTRY, derive_role_eligibility
from weall.runtime.reputation_matrix import derive_reputation_matrix
from weall.runtime.reputation_units import account_reputation_units
from weall.runtime.node_operator_responsibilities import VALIDATOR_REPUTATION_REQUIRED_MILLI

Json = dict[str, Any]

BASELINE_CIVIC_REPUTATION_MILLI = 1000
VALIDATOR_REPUTATION_MILLI = VALIDATOR_REPUTATION_REQUIRED_MILLI


def _d(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _s(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:
        return ""


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def reputation_action_map() -> list[Json]:
    out: list[Json] = []
    for code, spec in sorted(EVENT_REGISTRY.items()):
        positive = int(spec.default_delta) > 0
        negative = int(spec.default_delta) < 0
        farming_policy = _s(spec.farming_policy or "none")
        out.append({
            "action_name": code,
            "event_code": code,
            "source_flow": spec.source_flow,
            "transaction_type": "canonical_reputation_event",
            "reputation_bucket": spec.dimension,
            "direction": "positive" if positive else ("negative" if negative else "neutral"),
            "amount_milli": int(spec.default_delta),
            "severity": int(spec.severity),
            "cap_per_account": "source_key_dedupe",
            "cap_per_epoch_or_window": farming_policy if farming_policy != "none" else "not_applicable_or_external_policy",
            "cooldown": farming_policy if "cooldown" in farming_policy else "none",
            "duplicate_or_repeated_actions_count": False,
            "requires_independent_confirmation": spec.source_flow in {"poh", "dispute", "appeal", "validator", "storage", "helper"},
            "self_farming_risk": "capped_or_deduped" if positive else "not_positive",
            "collusive_farming_risk": "requires_review_in_public_state" if spec.source_flow in {"poh", "dispute", "appeal"} else "requires_followup_hardening_review",
            "spam_risk": "positive_cap_or_source_dedupe_required" if positive else "penalty_or_neutral",
            "affects_governance_eligibility": spec.dimension in {"governance_reputation", "poh_reputation", "civic_reputation", "safety_reputation"},
            "affects_dispute_or_juror_eligibility": spec.dimension in {"juror_reputation", "poh_reputation", "safety_reputation"},
            "affects_operator_readiness": spec.dimension in {"validator_reputation", "storage_reputation", "helper_reputation", "civic_reputation"},
            "explanation": spec.explanation,
            "visibility": spec.visibility,
        })
    return out


def _account_record(state: Json, account_id: str) -> Json:
    accounts = _d(state.get("accounts"))
    for key in (account_id, account_id.lstrip("@"), f"@{account_id.lstrip('@')}"):
        rec = accounts.get(key)
        if isinstance(rec, dict):
            return rec
    return {}


def reputation_progression_status(state: Json, account_id: str) -> Json:
    acct = _account_record(state, account_id)
    matrix = derive_reputation_matrix(state, account_id, reveal_restricted=False, include_events=True)
    total_milli = int(account_reputation_units(acct, default=0)) if acct else int(matrix.get("aggregate_public_score_milli") or 0)
    dims = _d(matrix.get("dimensions")) or _d(matrix.get("canonical_dimensions"))
    events = _l(matrix.get("events"))
    eligibility = matrix.get("eligibility") or derive_role_eligibility(state, account_id)
    next_thresholds = [
        {"name": "baseline_civic_participation", "required_milli": BASELINE_CIVIC_REPUTATION_MILLI, "actual_milli": total_milli, "met": total_milli >= BASELINE_CIVIC_REPUTATION_MILLI},
        {"name": "validator_reputation_readiness", "required_milli": VALIDATOR_REPUTATION_MILLI, "actual_milli": total_milli, "met": total_milli >= VALIDATOR_REPUTATION_MILLI},
    ]
    recent_codes = [_s(ev.get("event_code") or ev.get("reason_code")) for ev in events if isinstance(ev, dict)]
    capped: list[Json] = []
    rep = _d(state.get("reputation"))
    for key, rec in sorted(_d(rep.get("accrual_windows")).items()):
        if isinstance(rec, dict) and _s(rec.get("account_id")) in {account_id, account_id.lstrip("@"), f"@{account_id.lstrip('@')}"}:
            capped.append({"window": key, **rec})
    blockers: list[str] = []
    if bool(acct.get("banned")) or bool(acct.get("locked")):
        blockers.append("account_restricted")
    if total_milli < BASELINE_CIVIC_REPUTATION_MILLI:
        blockers.append("baseline_civic_reputation_building")
    return {
        "ok": True,
        "account_id": account_id,
        "tier": _i(acct.get("poh_tier"), 0),
        "unrestricted": not bool(acct.get("banned")) and not bool(acct.get("locked")),
        "reputation_total_milli": int(total_milli),
        "reputation_by_domain": dims,
        "next_relevant_thresholds": next_thresholds,
        "actions_available_without_spam": [
            "complete Tier 2 verification",
            "cast eligible governance votes once per proposal phase",
            "complete assigned dispute review duties on time",
            "publish clean public content within maturity/cap limits",
            "register node/operator responsibilities only after account and node readiness",
        ],
        "actions_recently_counted": sorted(set(code for code in recent_codes if code)),
        "actions_capped_or_on_cooldown": capped,
        "penalties_active": [code for code in recent_codes if any(token in code for token in ("SPAM", "FRAUD", "TIMED_OUT", "VIOLATION", "SLASH", "DOUBLE"))],
        "eligibility_summary": eligibility,
        "next_step": "Reputation progress: use meaningful capped civic actions; repeated low-value activity does not count again.",
        "blocking_reasons": sorted(set(blockers)),
        "anti_farming_policy": "source-key dedupe, content maturity, per-window accrual caps, public dispute penalties",
        "truth_boundary": "WeAll is a pre-public-testnet protocol implementation under active hardening.",
    }
