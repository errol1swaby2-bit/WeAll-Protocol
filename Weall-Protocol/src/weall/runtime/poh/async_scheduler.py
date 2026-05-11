from __future__ import annotations

from typing import Any

from weall.runtime.poh.bootstrap_quorum import (
    adaptive_bootstrap_review_policy,
    poh_bootstrap_quorum_allowed,
)
from weall.runtime.reputation_units import threshold_to_units
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]

DEFAULT_ASYNC_N_JURORS = 3
DEFAULT_ASYNC_MIN_REVIEWS = 3
DEFAULT_ASYNC_APPROVAL_THRESHOLD = 2
DEFAULT_ASYNC_REJECTION_THRESHOLD = 2
DEFAULT_ASYNC_EXPIRY_WINDOW_BLOCKS = 100000
DEFAULT_ASYNC_MIN_REP_UNITS = 0


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _poh_root(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    return poh


def _async_cases(state: Json) -> Json:
    poh = _poh_root(state)
    cases = poh.get("async_cases")
    if not isinstance(cases, dict):
        cases = {}
        poh["async_cases"] = cases
    return cases


def _poh_params(state: Json) -> Json:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    poh = params.get("poh")
    return poh if isinstance(poh, dict) else {}


def _param_int(state: Json, key: str, default: int) -> int:
    try:
        return int(_poh_params(state).get(key))
    except Exception:
        return int(default)


def _param_rep_units(state: Json, *, units_key: str, legacy_key: str, default_units: int) -> int:
    poh = _poh_params(state)
    try:
        return max(0, int(poh.get(units_key)))
    except Exception:
        return max(0, threshold_to_units(poh.get(legacy_key), default=default_units))


def _case_has_evidence(case: Json) -> bool:
    # Assignment locks evidence, so a request-open response commitment alone is
    # not enough. Wait for an explicit declared/bound evidence record.
    if isinstance(case.get("evidence_commitments"), dict) and bool(case.get("evidence_commitments")):
        return True
    if isinstance(case.get("public_evidence_ids"), list) and bool(case.get("public_evidence_ids")):
        return True
    if isinstance(case.get("evidence_binds"), dict) and bool(case.get("evidence_binds")):
        return True
    return False


def _case_needs_assign(case: Json) -> bool:
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("open", "evidence_submitted"):
        return False
    if not _case_has_evidence(case):
        return False
    assigned = case.get("assigned_jurors")
    return not isinstance(assigned, list) or len([j for j in assigned if _as_str(j).strip()]) == 0


def _review_counts(case: Json) -> tuple[int, int, int, bool]:
    reviews = case.get("reviews")
    reviews = reviews if isinstance(reviews, dict) else {}
    approvals = 0
    rejections = 0
    counted = 0
    needs_followup = False
    for rec_any in reviews.values():
        rec = _as_dict(rec_any)
        verdict = _as_str(rec.get("verdict") or "").strip().lower()
        if verdict == "approve":
            approvals += 1
            counted += 1
        elif verdict in ("reject", "invalid_evidence"):
            rejections += 1
            counted += 1
        elif verdict == "needs_followup":
            needs_followup = True
    return approvals, rejections, counted, needs_followup


def _case_ready_to_finalize(case: Json, *, height: int) -> bool:
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("approved", "rejected", "expired", "finalized"):
        return False
    approvals, rejections, counted, needs_followup = _review_counts(case)
    if needs_followup:
        return False
    minimum_reviews = _as_int(case.get("minimum_reviews") or DEFAULT_ASYNC_MIN_REVIEWS, DEFAULT_ASYNC_MIN_REVIEWS)
    approval_threshold = _as_int(case.get("approval_threshold") or DEFAULT_ASYNC_APPROVAL_THRESHOLD, DEFAULT_ASYNC_APPROVAL_THRESHOLD)
    rejection_threshold = _as_int(case.get("rejection_threshold") or DEFAULT_ASYNC_REJECTION_THRESHOLD, DEFAULT_ASYNC_REJECTION_THRESHOLD)
    if counted >= minimum_reviews and approvals >= approval_threshold:
        return True
    if counted >= minimum_reviews and rejections >= rejection_threshold:
        return True
    expires_height = _as_int(case.get("expires_height") or 0, 0)
    return bool(expires_height and int(height) > expires_height)


def _case_needs_receipt(case: Json) -> bool:
    if _as_str(case.get("receipt_id") or "").strip():
        return False
    outcome = _as_str(case.get("outcome") or "").strip().lower()
    return outcome in ("approved", "rejected", "expired")


def schedule_poh_async_system_txs(state: Json, *, next_height: int) -> int:
    """Schedule native async Tier-1 system txs deterministically.

    The scheduler only progresses system-owned lifecycle steps. Applicant
    evidence and juror reviews still arrive as signed user transactions.
    """

    enq = 0
    cases = _async_cases(state)
    configured_n_jurors = max(1, _param_int(state, "async_n_jurors", DEFAULT_ASYNC_N_JURORS))
    configured_min_reviews = max(1, _param_int(state, "async_min_reviews", DEFAULT_ASYNC_MIN_REVIEWS))
    configured_approval_threshold = max(1, _param_int(state, "async_approval_threshold", DEFAULT_ASYNC_APPROVAL_THRESHOLD))
    configured_rejection_threshold = max(1, _param_int(state, "async_rejection_threshold", DEFAULT_ASYNC_REJECTION_THRESHOLD))
    bootstrap_quorum_allowed = poh_bootstrap_quorum_allowed(state, height=int(next_height))
    min_rep_units = _param_rep_units(
        state,
        units_key="async_min_rep_milli",
        legacy_key="async_min_rep",
        default_units=DEFAULT_ASYNC_MIN_REP_UNITS,
    )

    for case_id_raw, case_any in list(cases.items()):
        case = _as_dict(case_any)
        case_id = _as_str(case.get("case_id") or case_id_raw).strip() or _as_str(case_id_raw).strip()
        if not case_id:
            continue
        account_id = _as_str(case.get("account_id") or "").strip()

        if _case_needs_assign(case) and account_id:
            policy = adaptive_bootstrap_review_policy(
                state,
                configured_jurors=_as_int(case.get("configured_assigned_juror_count") or case.get("assigned_juror_count") or configured_n_jurors, configured_n_jurors),
                configured_min_reviews=_as_int(case.get("configured_minimum_reviews") or case.get("minimum_reviews") or configured_min_reviews, configured_min_reviews),
                configured_approval_threshold=_as_int(case.get("configured_approval_threshold") or case.get("approval_threshold") or configured_approval_threshold, configured_approval_threshold),
                configured_rejection_threshold=_as_int(case.get("configured_rejection_threshold") or case.get("rejection_threshold") or configured_rejection_threshold, configured_rejection_threshold),
                height=int(next_height),
            )
            n_jurors = int(policy["assigned_jurors"])
            try:
                from weall.runtime.poh.juror_select import pick_async_jurors  # type: ignore

                jurors = pick_async_jurors(
                    state=state,
                    case_id=case_id,
                    target_account=account_id,
                    n_jurors=int(n_jurors),
                    min_rep_units=int(min_rep_units),
                    allow_partial=bool(bootstrap_quorum_allowed),
                    allow_roleless_bootstrap=bool(bootstrap_quorum_allowed),
                )
            except Exception:
                jurors = []
            if isinstance(jurors, list) and len(jurors) == int(n_jurors):
                enqueue_system_tx(
                    state,
                    tx_type="POH_ASYNC_JUROR_ASSIGN",
                    payload={
                        "case_id": case_id,
                        "jurors": jurors,
                        "min_rep_milli": int(min_rep_units),
                        "bootstrap_adaptive_quorum": {
                            "active_validators": int(policy["active_validators"]),
                            "bft_min_validators": int(policy["bft_min_validators"]),
                            "assigned_jurors": int(policy["assigned_jurors"]),
                            "minimum_reviews": int(policy["minimum_reviews"]),
                            "approval_threshold": int(policy["approval_threshold"]),
                            "rejection_threshold": int(policy["rejection_threshold"]),
                        }
                        if bool(policy.get("bootstrap_adaptive"))
                        else None,
                    },
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent=None,
                    phase="post",
                )
                enq += 1

        if _case_ready_to_finalize(case, height=int(next_height)):
            enqueue_system_tx(
                state,
                tx_type="POH_ASYNC_FINALIZE",
                payload={"case_id": case_id, "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enqueue_system_tx(
                state,
                tx_type="POH_ASYNC_RECEIPT",
                payload={"case_id": case_id, "receipt_id": f"poh_async_rcpt:{case_id}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent="POH_ASYNC_FINALIZE",
                phase="post",
            )
            enq += 2

        if _case_needs_receipt(case):
            enqueue_system_tx(
                state,
                tx_type="POH_ASYNC_RECEIPT",
                payload={"case_id": case_id, "receipt_id": f"poh_async_rcpt:{case_id}", "ts_ms": 0},
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent="POH_ASYNC_FINALIZE",
                phase="post",
            )
            enq += 1

    return enq
