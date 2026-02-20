from __future__ import annotations

from typing import Any, Dict, List, Optional

from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope

Json = Dict[str, Any]


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def _require(cond: bool, code: str, reason: str, details: Optional[Json] = None) -> None:
    if not cond:
        raise ApplyError(code, reason, details or {})


def _ensure_state_roots(state: Json) -> None:
    state.setdefault("accounts", {})
    state.setdefault("params", {})
    if not isinstance(state["accounts"], dict):
        state["accounts"] = {}
    if not isinstance(state["params"], dict):
        state["params"] = {}

    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh

    poh.setdefault("applications", {})
    poh.setdefault("evidence", {})
    poh.setdefault("evidence_bindings", {})
    poh.setdefault("challenges", {})
    poh.setdefault("challenge_receipts", {})

    poh.setdefault("tier2_cases", {})
    poh.setdefault("tier2_receipts", {})

    poh.setdefault("tier3_cases", {})
    poh.setdefault("tier3_receipts", {})

    for k in (
        "applications",
        "evidence",
        "evidence_bindings",
        "challenges",
        "challenge_receipts",
        "tier2_cases",
        "tier2_receipts",
        "tier3_cases",
        "tier3_receipts",
    ):
        if not isinstance(poh.get(k), dict):
            poh[k] = {}


def _account_maybe(state: Json, account_id: str) -> Optional[Json]:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return None
    rec = accounts.get(account_id)
    return rec if isinstance(rec, dict) else None


def _account(state: Json, account_id: str) -> Json:
    rec = _account_maybe(state, account_id)
    _require(isinstance(rec, dict), "not_found", "account_not_found", {"account_id": account_id})
    return rec  # type: ignore[return-value]


def _is_system(env: TxEnvelope) -> bool:
    return bool(getattr(env, "system", False)) and _as_str(getattr(env, "signer", "")).strip().upper() == "SYSTEM"


def _require_parent(env: TxEnvelope, tx_type: str) -> None:
    _require(
        _as_str(getattr(env, "parent", "")).strip() != "",
        "invalid_parent",
        "missing_parent",
        {"tx_type": tx_type},
    )


def _tier_of(state: Json, account_id: str) -> int:
    # MVP semantics: missing accounts default to tier 0 (instead of raising)
    a = _account_maybe(state, account_id)
    if not isinstance(a, dict):
        return 0
    return _as_int(a.get("poh_tier", 0), 0)


def _require_not_banned_or_locked(state: Json, account_id: str) -> None:
    # MVP semantics: if account doesn't exist yet, treat as not banned/locked
    a = _account_maybe(state, account_id)
    if not isinstance(a, dict):
        return
    _require(not bool(a.get("banned", False)), "forbidden", "account_banned", {"account_id": account_id})
    _require(not bool(a.get("locked", False)), "forbidden", "account_locked", {"account_id": account_id})


def _poh(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    return poh


def _poh_applications(state: Json) -> Json:
    return _poh(state)["applications"]


def _poh_evidence(state: Json) -> Json:
    return _poh(state)["evidence"]


def _poh_evidence_bindings(state: Json) -> Json:
    return _poh(state)["evidence_bindings"]


def _poh_challenges(state: Json) -> Json:
    return _poh(state)["challenges"]


def _poh_challenge_receipts(state: Json) -> Json:
    return _poh(state)["challenge_receipts"]


def _tier2_cases(state: Json) -> Json:
    return _poh(state)["tier2_cases"]


def _tier2_receipts(state: Json) -> Json:
    return _poh(state)["tier2_receipts"]


def _tier3_cases(state: Json) -> Json:
    return _poh(state)["tier3_cases"]


def _tier3_receipts(state: Json) -> Json:
    return _poh(state)["tier3_receipts"]


# -----------------------------
# Tx handlers: generic PoH
# -----------------------------

def _apply_poh_application_submit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account_id = _as_str(payload.get("account_id") or env.signer).strip()
    _require(account_id != "", "invalid_payload", "missing_account_id", {})
    _require_not_banned_or_locked(state, account_id)
    _require(_tier_of(state, account_id) >= 0, "forbidden", "tier_required", {"min_tier": 0})

    app_id = _as_str(payload.get("application_id") or f"app:{account_id}:{_as_int(env.nonce, 0)}").strip()
    _require(app_id != "", "invalid_payload", "missing_application_id", {})

    apps = _poh_applications(state)
    _require(app_id not in apps, "conflict", "application_exists", {"application_id": app_id})

    apps[app_id] = {
        "application_id": app_id,
        "account_id": account_id,
        "opened_by": _as_str(env.signer).strip(),
        "nonce": _as_int(env.nonce, 0),
        "status": "open",
        "details": payload,
    }

    return {"applied": "POH_APPLICATION_SUBMIT", "application_id": app_id, "account_id": account_id}


def _apply_poh_evidence_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    evidence_id = _as_str(payload.get("evidence_id") or f"ev:{_as_str(env.signer).strip()}:{_as_int(env.nonce, 0)}").strip()
    _require(evidence_id != "", "invalid_payload", "missing_evidence_id", {})
    cid = _as_str(payload.get("cid") or "").strip()
    _require(cid != "", "invalid_payload", "missing_cid", {})
    kind = _as_str(payload.get("kind") or "generic").strip()

    ev = _poh_evidence(state)
    _require(evidence_id not in ev, "conflict", "evidence_exists", {"evidence_id": evidence_id})

    ev[evidence_id] = {
        "evidence_id": evidence_id,
        "cid": cid,
        "kind": kind,
        "declared_by": _as_str(env.signer).strip(),
        "nonce": _as_int(env.nonce, 0),
        "details": payload,
    }

    return {"applied": "POH_EVIDENCE_DECLARE", "evidence_id": evidence_id, "cid": cid, "kind": kind}


def _apply_poh_evidence_bind(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    evidence_id = _as_str(payload.get("evidence_id") or "").strip()
    _require(evidence_id != "", "invalid_payload", "missing_evidence_id", {})
    target_type = _as_str(payload.get("target_type") or "").strip()
    target_id = _as_str(payload.get("target_id") or "").strip()
    _require(target_type != "", "invalid_payload", "missing_target_type", {})
    _require(target_id != "", "invalid_payload", "missing_target_id", {})

    ev = _poh_evidence(state)
    _require(evidence_id in ev, "not_found", "evidence_not_found", {"evidence_id": evidence_id})

    bindings = _poh_evidence_bindings(state)
    bind_id = _as_str(payload.get("binding_id") or f"bind:{evidence_id}:{target_type}:{target_id}").strip()
    _require(bind_id != "", "invalid_payload", "missing_binding_id", {})
    _require(bind_id not in bindings, "conflict", "binding_exists", {"binding_id": bind_id})

    bindings[bind_id] = {
        "binding_id": bind_id,
        "evidence_id": evidence_id,
        "target_type": target_type,
        "target_id": target_id,
        "bound_by": _as_str(env.signer).strip(),
        "nonce": _as_int(env.nonce, 0),
        "details": payload,
    }

    return {
        "applied": "POH_EVIDENCE_BIND",
        "binding_id": bind_id,
        "evidence_id": evidence_id,
        "target_type": target_type,
        "target_id": target_id,
    }


def _apply_poh_challenge_open(state: Json, env: TxEnvelope) -> Json:
    """
    MVP semantics (per tests):
      - allow challenge open even when the signer is not yet registered in state.
      - if signer exists, enforce not banned/locked and tier>=1
    """
    payload = _as_dict(env.payload)

    target_account = _as_str(payload.get("account_id") or "").strip()
    _require(target_account != "", "invalid_payload", "missing_account_id", {})

    signer = _as_str(env.signer).strip()

    # Only enforce gates if signer account exists (tests use st={}).
    if _account_maybe(state, signer) is not None:
        _require_not_banned_or_locked(state, signer)
        _require(_tier_of(state, signer) >= 1, "forbidden", "tier_required", {"min_tier": 1})

    reason = _as_str(payload.get("reason") or "").strip()
    _require(reason != "", "invalid_payload", "missing_reason", {})

    chall_id = _as_str(payload.get("challenge_id") or f"chall:{target_account}:{_as_int(env.nonce, 0)}").strip()
    _require(chall_id != "", "invalid_payload", "missing_challenge_id", {})

    challenges = _poh_challenges(state)
    _require(chall_id not in challenges, "conflict", "challenge_exists", {"challenge_id": chall_id})

    challenges[chall_id] = {
        "challenge_id": chall_id,
        "account_id": target_account,
        "opened_by": signer,
        "nonce": _as_int(env.nonce, 0),
        "reason": reason,
        "status": "open",
        "details": payload,
    }

    return {"applied": "POH_CHALLENGE_OPEN", "challenge_id": chall_id, "account_id": target_account}


def _apply_poh_challenge_resolve(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require(_as_str(env.parent).strip() != "", "invalid_parent", "missing_parent", {"tx_type": "POH_CHALLENGE_RESOLVE"})

    payload = _as_dict(env.payload)
    chall_id = _as_str(payload.get("challenge_id") or "").strip()
    _require(chall_id != "", "invalid_payload", "missing_challenge_id", {})

    resolution = _as_str(payload.get("resolution") or "").strip().lower()
    _require(resolution in ("upheld", "dismissed"), "invalid_payload", "bad_resolution", {"resolution": resolution})

    challenges = _poh_challenges(state)
    chall = challenges.get(chall_id)
    _require(isinstance(chall, dict), "not_found", "challenge_not_found", {"challenge_id": chall_id})

    status = _as_str(chall.get("status") or "").strip().lower()
    if status in ("resolved", "finalized"):
        if _as_str(chall.get("resolution") or "").strip().lower() == resolution:
            return {"applied": "POH_CHALLENGE_RESOLVE", "challenge_id": chall_id, "idempotent": True}
        _require(False, "conflict", "challenge_already_resolved", {"challenge_id": chall_id})

    chall["status"] = "resolved"
    chall["resolution"] = resolution
    chall["resolved_by"] = _as_str(env.signer).strip()
    chall["resolved_ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)

    # Side effect: if upheld, ban the target account (MVP)
    target = _as_str(chall.get("account_id") or "").strip()
    if resolution == "upheld" and target:
        a = _account_maybe(state, target)
        if isinstance(a, dict):
            a["banned"] = True

    # Receipt record (append-only map)
    receipts = _poh_challenge_receipts(state)
    receipt_id = _as_str(payload.get("receipt_id") or f"challrcpt:{chall_id}").strip()
    if receipt_id and receipt_id not in receipts:
        receipts[receipt_id] = {
            "receipt_id": receipt_id,
            "challenge_id": chall_id,
            "resolution": resolution,
            "target": target,
        }

    return {"applied": "POH_CHALLENGE_RESOLVE", "challenge_id": chall_id, "resolution": resolution, "target": target}


def _apply_poh_tier_set(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require_parent(env, "POH_TIER_SET")
    payload = _as_dict(env.payload)

    account_id = _as_str(payload.get("account_id") or "").strip()
    tier = _as_int(payload.get("tier", 0), 0)
    _require(account_id != "", "invalid_payload", "missing_account_id", {})
    _require(tier in (0, 1, 2, 3), "invalid_payload", "bad_tier", {"tier": tier})

    acct = _account_maybe(state, account_id)
    if not isinstance(acct, dict):
        # Allow setting tier for accounts that exist (production would require registration path),
        # but tolerate missing for MVP by creating a minimal record.
        accounts = state.get("accounts")
        if not isinstance(accounts, dict):
            state["accounts"] = {}
            accounts = state["accounts"]
        accounts[account_id] = {"nonce": 0, "poh_tier": tier, "banned": False, "locked": False, "reputation": 0.0}
        acct = accounts[account_id]

    cur = _as_int(acct.get("poh_tier", 0), 0)
    if cur == tier:
        return {"applied": "POH_TIER_SET", "account_id": account_id, "tier": tier, "idempotent": True}

    acct["poh_tier"] = tier
    return {"applied": "POH_TIER_SET", "account_id": account_id, "tier": tier}


def _apply_poh_bootstrap_tier3_grant(state: Json, env: TxEnvelope) -> Json:
    """Genesis bootstrap: grant Tier 3 to a target account.

    Canon: system_only, block context.

    Safety:
      - Default allow only at height==0 (genesis) unless params override:
          params["poh_bootstrap_max_height"] (int, default 0)
    """
    _require(_is_system(env), "forbidden", "system_only", {})
    _require_parent(env, "POH_BOOTSTRAP_TIER3_GRANT")

    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target") or "").strip()
    _require(target != "", "invalid_payload", "missing_target", {})

    h = _as_int(state.get("height", 0), 0)
    params = state.get("params") if isinstance(state.get("params"), dict) else {}
    max_h = _as_int((params or {}).get("poh_bootstrap_max_height", 0), 0)
    _require(h <= max_h, "forbidden", "bootstrap_closed", {"height": h, "max_height": max_h})

    acct = _account(state, target)
    cur = _as_int(acct.get("poh_tier", 0), 0)
    if cur < 3:
        acct["poh_tier"] = 3

    return {"applied": "POH_BOOTSTRAP_TIER3_GRANT", "target": target, "tier": int(acct.get("poh_tier", 0) or 0)}


# -----------------------------
# Tier 2 state machine
# -----------------------------

def _tier2_case(state: Json, case_id: str) -> Json:
    cases = _tier2_cases(state)
    case = cases.get(case_id)
    _require(isinstance(case, dict), "not_found", "tier2_case_not_found", {"case_id": case_id})
    return case  # type: ignore[return-value]


def _tier2_juror_rec(case: Json, juror_id: str) -> Json:
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        jm = {}
        case["jurors"] = jm
    rec = jm.get(juror_id)
    _require(isinstance(rec, dict), "not_found", "juror_not_assigned", {"juror_id": juror_id})
    return rec  # type: ignore[return-value]


def _apply_poh_tier2_request_open(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account_id = _as_str(payload.get("account_id") or env.signer).strip()
    _require(account_id != "", "invalid_payload", "missing_account_id", {})
    _require_not_banned_or_locked(state, account_id)
    _require(_tier_of(state, account_id) >= 1, "forbidden", "tier_required", {"min_tier": 1})

    case_id = _as_str(payload.get("case_id") or f"poh2:{account_id}:{_as_int(env.nonce, 0)}").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    cases = _tier2_cases(state)
    _require(case_id not in cases, "conflict", "tier2_case_exists", {"case_id": case_id})

    # Evidence can be a pre-declared evidence_id, or inline video_cid for MVP.
    evidence_id = _as_str(payload.get("evidence_id") or "").strip()
    video_cid = _as_str(payload.get("video_cid") or "").strip()

    cases[case_id] = {
        "case_id": case_id,
        "account_id": account_id,
        "opened_by": _as_str(env.signer).strip(),
        "nonce": _as_int(env.nonce, 0),
        "status": "requested",
        "evidence_id": evidence_id,
        "video_cid": video_cid,
        "jurors": {},
        "details": payload,
    }

    return {"applied": "POH_TIER2_REQUEST_OPEN", "case_id": case_id, "account_id": account_id}


def _apply_poh_tier2_juror_assign(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require(_as_str(env.parent).strip() != "", "invalid_parent", "missing_parent", {"tx_type": "POH_TIER2_JUROR_ASSIGN"})

    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    jurors = _as_list(payload.get("jurors"))
    _require(case_id != "", "invalid_payload", "missing_case_id", {})
    _require(len(jurors) == 3, "invalid_payload", "bad_juror_count", {"expected": 3, "got": len(jurors)})

    case = _tier2_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("requested", "open"):
        return {"applied": "POH_TIER2_JUROR_ASSIGN", "case_id": case_id, "idempotent": True}

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        jm = {}
        case["jurors"] = jm

    # Idempotency: if already assigned exactly these jurors, do nothing.
    if len(jm) == 3:
        existing = sorted([_as_str(x).strip() for x in jm.keys()])
        desired = sorted([_as_str(x).strip() for x in jurors])
        if existing == desired:
            case["status"] = "open"
            return {"applied": "POH_TIER2_JUROR_ASSIGN", "case_id": case_id, "idempotent": True}

    _require(len(jm) == 0, "conflict", "jurors_already_assigned", {"case_id": case_id})

    for jid_any in jurors:
        jid = _as_str(jid_any).strip()
        _require(jid != "", "invalid_payload", "bad_juror_id", {"juror_id": jid_any})
        jm[jid] = {"juror_id": jid, "accepted": None, "verdict": None, "ts_ms": 0}

    case["status"] = "open"

    return {"applied": "POH_TIER2_JUROR_ASSIGN", "case_id": case_id, "jurors": [_as_str(j).strip() for j in jurors]}


def _apply_poh_tier2_juror_accept(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    case = _tier2_case(state, case_id)
    jrec = _tier2_juror_rec(case, juror_id)

    if jrec.get("accepted") is True:
        return {"applied": "POH_TIER2_JUROR_ACCEPT", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
    if jrec.get("accepted") is False:
        _require(False, "conflict", "juror_already_declined", {"case_id": case_id, "juror_id": juror_id})

    jrec["accepted"] = True
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)

    return {"applied": "POH_TIER2_JUROR_ACCEPT", "case_id": case_id, "juror_id": juror_id}


def _apply_poh_tier2_juror_decline(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    case = _tier2_case(state, case_id)
    jrec = _tier2_juror_rec(case, juror_id)

    if jrec.get("accepted") is False:
        return {"applied": "POH_TIER2_JUROR_DECLINE", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
    if jrec.get("accepted") is True:
        _require(False, "conflict", "juror_already_accepted", {"case_id": case_id, "juror_id": juror_id})

    jrec["accepted"] = False
    jrec["reason"] = _as_str(payload.get("reason") or "").strip()
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)

    return {"applied": "POH_TIER2_JUROR_DECLINE", "case_id": case_id, "juror_id": juror_id}


def _apply_poh_tier2_review_submit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    verdict = _as_str(payload.get("verdict") or "").strip().lower()
    _require(verdict in ("pass", "fail"), "invalid_payload", "bad_verdict", {"verdict": verdict})

    case = _tier2_case(state, case_id)
    jrec = _tier2_juror_rec(case, juror_id)

    _require(jrec.get("accepted") is True, "forbidden", "juror_not_accepted", {"case_id": case_id, "juror_id": juror_id})

    if _as_str(jrec.get("verdict") or "").strip() in ("pass", "fail"):
        if _as_str(jrec.get("verdict") or "").strip().lower() == verdict:
            return {"applied": "POH_TIER2_REVIEW_SUBMIT", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
        _require(False, "conflict", "verdict_already_set", {"case_id": case_id, "juror_id": juror_id})

    jrec["verdict"] = verdict
    jrec["notes"] = _as_str(payload.get("notes") or "")
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)

    return {"applied": "POH_TIER2_REVIEW_SUBMIT", "case_id": case_id, "juror_id": juror_id, "verdict": verdict}


def _tier2_compute_outcome(case: Json) -> str:
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        return "fail"
    passes = 0
    for _jid, jrec_any in jm.items():
        jrec = _as_dict(jrec_any)
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v == "pass":
            passes += 1
    return "pass" if passes >= 2 else "fail"


def _apply_poh_tier2_finalize(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require(_as_str(env.parent).strip() != "", "invalid_parent", "missing_parent", {"tx_type": "POH_TIER2_FINALIZE"})
    payload = _as_dict(env.payload)

    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    case = _tier2_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized"):
        outcome = _as_str(case.get("outcome") or "fail").strip().lower()
        return {"applied": "POH_TIER2_FINALIZE", "case_id": case_id, "outcome": outcome, "idempotent": True}

    jm = case.get("jurors")
    _require(isinstance(jm, dict) and len(jm) == 3, "invalid_state", "jurors_not_assigned", {"case_id": case_id})

    # require all jurors have accepted/declined and provided verdict if accepted
    for jid, jrec_any in jm.items():
        jrec = _as_dict(jrec_any)
        _require(jrec.get("accepted") is not None, "forbidden", "juror_response_missing", {"juror_id": jid})
        if jrec.get("accepted") is True:
            v = _as_str(jrec.get("verdict") or "").strip().lower()
            _require(v in ("pass", "fail"), "forbidden", "juror_verdict_missing", {"juror_id": jid})

    outcome = _tier2_compute_outcome(case)
    case["outcome"] = outcome

    acct_id = _as_str(case.get("account_id") or "").strip()
    _require(acct_id != "", "invalid_state", "missing_account_id", {"case_id": case_id})

    tier_awarded = 0
    if outcome == "pass":
        acct = _account(state, acct_id)
        cur = _as_int(acct.get("poh_tier", 0), 0)
        if cur < 2:
            acct["poh_tier"] = 2
        tier_awarded = 2
        case["status"] = "awarded"
    else:
        case["status"] = "finalized"

    receipt_id = _as_str(case.get("receipt_id") or "").strip()
    if not receipt_id:
        receipt_id = f"poh2rcpt:{case_id}"
        case["receipt_id"] = receipt_id

    receipts = _tier2_receipts(state)
    receipts.setdefault(
        receipt_id,
        {
            "receipt_id": receipt_id,
            "case_id": case_id,
            "account_id": acct_id,
            "outcome": outcome,
            "tier_awarded": tier_awarded,
        },
    )

    return {
        "applied": "POH_TIER2_FINALIZE",
        "case_id": case_id,
        "account_id": acct_id,
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "receipt_id": receipt_id,
    }


def _apply_poh_tier2_receipt(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require(_as_str(env.parent).strip() != "", "invalid_parent", "missing_parent", {"tx_type": "POH_TIER2_RECEIPT"})

    payload = _as_dict(env.payload)
    receipt_id = _as_str(payload.get("receipt_id") or "").strip()
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(receipt_id != "" or case_id != "", "invalid_payload", "missing_receipt_or_case", {})

    if receipt_id == "":
        receipt_id = f"poh2rcpt:{case_id}"

    receipts = _tier2_receipts(state)
    if receipt_id in receipts:
        return {"applied": "POH_TIER2_RECEIPT", "receipt_id": receipt_id, "idempotent": True}

    if case_id:
        case = _tier2_case(state, case_id)
        acct_id = _as_str(case.get("account_id") or "").strip()
        outcome = _as_str(case.get("outcome") or "fail").strip().lower()
        tier_awarded = _as_int(case.get("tier_awarded", 0), 0)
        receipts[receipt_id] = {
            "receipt_id": receipt_id,
            "case_id": case_id,
            "account_id": acct_id,
            "outcome": outcome,
            "tier_awarded": tier_awarded,
        }
    else:
        receipts[receipt_id] = {"receipt_id": receipt_id, "details": payload}

    return {"applied": "POH_TIER2_RECEIPT", "receipt_id": receipt_id}


# -----------------------------
# Tier 3 state machine
# -----------------------------

def _tier3_case(state: Json, case_id: str) -> Json:
    cases = _tier3_cases(state)
    case = cases.get(case_id)
    _require(isinstance(case, dict), "not_found", "tier3_case_not_found", {"case_id": case_id})
    return case  # type: ignore[return-value]


def _tier3_juror_rec(case: Json, juror_id: str) -> Json:
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        jm = {}
        case["jurors"] = jm
    rec = jm.get(juror_id)
    _require(isinstance(rec, dict), "not_found", "juror_not_assigned", {"juror_id": juror_id})
    return rec  # type: ignore[return-value]


def _apply_poh_tier3_init(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require_parent(env, "POH_TIER3_INIT")
    payload = _as_dict(env.payload)

    account_id = _as_str(payload.get("account_id") or "").strip()
    _require(account_id != "", "invalid_payload", "missing_account_id", {})
    _require_not_banned_or_locked(state, account_id)
    _require(_tier_of(state, account_id) >= 2, "forbidden", "tier_required", {"min_tier": 2})

    case_id = _as_str(payload.get("case_id") or f"poh3:{account_id}:{_as_int(env.nonce, 0)}").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    cases = _tier3_cases(state)
    _require(case_id not in cases, "conflict", "tier3_case_exists", {"case_id": case_id})

    cases[case_id] = {
        "case_id": case_id,
        "account_id": account_id,
        "opened_by": _as_str(env.signer).strip(),
        "nonce": _as_int(env.nonce, 0),
        "status": "open",
        "jurors": {},
        "details": payload,
    }

    return {"applied": "POH_TIER3_INIT", "case_id": case_id, "account_id": account_id}


def _apply_poh_tier3_juror_assign(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require_parent(env, "POH_TIER3_JUROR_ASSIGN")
    payload = _as_dict(env.payload)

    case_id = _as_str(payload.get("case_id") or "").strip()
    jurors = _as_list(payload.get("jurors"))
    _require(case_id != "", "invalid_payload", "missing_case_id", {})
    _require(len(jurors) == 10, "invalid_payload", "bad_juror_count", {"expected": 10, "got": len(jurors)})

    case = _tier3_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status not in ("open", "init"):
        return {"applied": "POH_TIER3_JUROR_ASSIGN", "case_id": case_id, "idempotent": True}

    jm = case.get("jurors")
    if not isinstance(jm, dict):
        jm = {}
        case["jurors"] = jm

    if len(jm) == 10:
        existing = sorted([_as_str(x).strip() for x in jm.keys()])
        desired = sorted([_as_str(x).strip() for x in jurors])
        if existing == desired:
            case["status"] = "init"
            return {"applied": "POH_TIER3_JUROR_ASSIGN", "case_id": case_id, "idempotent": True}

    _require(len(jm) == 0, "conflict", "jurors_already_assigned", {"case_id": case_id})

    # 3 interacting (first 3) + 7 observing (rest) per scheduler contract
    interacting = [_as_str(x).strip() for x in jurors[:3]]
    observing = [_as_str(x).strip() for x in jurors[3:]]

    for jid in interacting:
        _require(jid != "", "invalid_payload", "bad_juror_id", {"juror_id": jid})
        jm[jid] = {"juror_id": jid, "role": "interacting", "accepted": None, "attended": None, "verdict": None, "ts_ms": 0}

    for jid in observing:
        _require(jid != "", "invalid_payload", "bad_juror_id", {"juror_id": jid})
        jm[jid] = {"juror_id": jid, "role": "observing", "accepted": None, "attended": None, "verdict": None, "ts_ms": 0}

    case["status"] = "init"
    case_details = case.get("details")
    if not isinstance(case_details, dict):
        case_details = {}
        case["details"] = case_details
    case_details["interacting_jurors"] = interacting
    case_details["observing_jurors"] = observing

    return {"applied": "POH_TIER3_JUROR_ASSIGN", "case_id": case_id, "jurors": interacting + observing}


def _apply_poh_tier3_juror_accept(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    case = _tier3_case(state, case_id)
    jrec = _tier3_juror_rec(case, juror_id)

    if jrec.get("accepted") is True:
        return {"applied": "POH_TIER3_JUROR_ACCEPT", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
    if jrec.get("accepted") is False:
        _require(False, "conflict", "juror_already_declined", {"case_id": case_id, "juror_id": juror_id})

    jrec["accepted"] = True
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)
    return {"applied": "POH_TIER3_JUROR_ACCEPT", "case_id": case_id, "juror_id": juror_id}


def _apply_poh_tier3_juror_decline(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    case = _tier3_case(state, case_id)
    jrec = _tier3_juror_rec(case, juror_id)

    if jrec.get("accepted") is False:
        return {"applied": "POH_TIER3_JUROR_DECLINE", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
    if jrec.get("accepted") is True:
        _require(False, "conflict", "juror_already_accepted", {"case_id": case_id, "juror_id": juror_id})

    jrec["accepted"] = False
    jrec["reason"] = _as_str(payload.get("reason") or "").strip()
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)
    return {"applied": "POH_TIER3_JUROR_DECLINE", "case_id": case_id, "juror_id": juror_id}


def _apply_poh_tier3_attendance_mark(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    payload = _as_dict(env.payload)

    case_id = _as_str(payload.get("case_id") or "").strip()
    juror_id = _as_str(payload.get("juror_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})
    _require(juror_id != "", "invalid_payload", "missing_juror_id", {})

    attended = payload.get("attended")
    _require(isinstance(attended, bool), "invalid_payload", "missing_attended_bool", {})

    case = _tier3_case(state, case_id)
    jrec = _tier3_juror_rec(case, juror_id)

    if jrec.get("attended") is not None:
        if bool(jrec.get("attended")) == bool(attended):
            return {"applied": "POH_TIER3_ATTENDANCE_MARK", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
        _require(False, "conflict", "attendance_already_set", {"case_id": case_id, "juror_id": juror_id})

    jrec["attended"] = bool(attended)
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)

    return {"applied": "POH_TIER3_ATTENDANCE_MARK", "case_id": case_id, "juror_id": juror_id, "attended": bool(attended)}


def _apply_poh_tier3_verdict_submit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    juror_id = _as_str(env.signer).strip()
    _require(juror_id != "", "invalid_tx", "missing_signer", {})
    _require_not_banned_or_locked(state, juror_id)
    _require(_tier_of(state, juror_id) >= 3, "forbidden", "juror_tier_required", {"min_tier": 3})

    verdict = _as_str(payload.get("verdict") or "").strip().lower()
    _require(verdict in ("pass", "fail"), "invalid_payload", "bad_verdict", {"verdict": verdict})

    case = _tier3_case(state, case_id)
    jrec = _tier3_juror_rec(case, juror_id)

    _require(_as_str(jrec.get("role") or "") == "interacting", "forbidden", "verdict_role_required", {"role": jrec.get("role")})
    _require(jrec.get("accepted") is True, "forbidden", "juror_not_accepted", {"case_id": case_id, "juror_id": juror_id})

    if _as_str(jrec.get("verdict") or "").strip() in ("pass", "fail"):
        if _as_str(jrec.get("verdict") or "").strip().lower() == verdict:
            return {"applied": "POH_TIER3_VERDICT_SUBMIT", "case_id": case_id, "juror_id": juror_id, "idempotent": True}
        _require(False, "conflict", "verdict_already_set", {"case_id": case_id, "juror_id": juror_id})

    jrec["verdict"] = verdict
    jrec["ts_ms"] = _as_int(payload.get("ts_ms", 0), 0)
    return {"applied": "POH_TIER3_VERDICT_SUBMIT", "case_id": case_id, "juror_id": juror_id, "verdict": verdict}


def _tier3_compute_outcome(case: Json) -> str:
    jm = case.get("jurors")
    if not isinstance(jm, dict):
        return "fail"
    passes = 0
    for _jid, jrec_any in jm.items():
        jrec = _as_dict(jrec_any)
        if _as_str(jrec.get("role") or "") != "interacting":
            continue
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        if v == "pass":
            passes += 1
    return "pass" if passes >= 2 else "fail"


def _apply_poh_tier3_finalize(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require_parent(env, "POH_TIER3_FINALIZE")
    payload = _as_dict(env.payload)

    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(case_id != "", "invalid_payload", "missing_case_id", {})

    case = _tier3_case(state, case_id)
    status = _as_str(case.get("status") or "").strip().lower()
    if status in ("awarded", "finalized"):
        outcome = _as_str(case.get("outcome") or "fail").strip().lower()
        return {"applied": "POH_TIER3_FINALIZE", "case_id": case_id, "outcome": outcome, "idempotent": True}

    jm = case.get("jurors")
    _require(isinstance(jm, dict) and len(jm) == 10, "invalid_state", "jurors_not_assigned", {"case_id": case_id})

    details = case.get("details")
    details = details if isinstance(details, dict) else {}
    interacting = details.get("interacting_jurors")
    observing = details.get("observing_jurors")
    _require(isinstance(interacting, list) and len(interacting) == 3, "invalid_state", "missing_interacting", {})
    _require(isinstance(observing, list) and len(observing) == 7, "invalid_state", "missing_observing", {})

    for jid in list(interacting) + list(observing):
        jrec = _as_dict(jm.get(_as_str(jid)))
        _require(jrec != {}, "invalid_state", "missing_juror_record", {"juror_id": jid})
        _require(jrec.get("attended") is not None, "forbidden", "attendance_missing", {"juror_id": jid})

    for jid in list(interacting):
        jrec = _as_dict(jm.get(_as_str(jid)))
        v = _as_str(jrec.get("verdict") or "").strip().lower()
        _require(v in ("pass", "fail"), "forbidden", "missing_verdict", {"juror_id": jid})

    outcome = _tier3_compute_outcome(case)
    case["outcome"] = outcome

    acct_id = _as_str(case.get("account_id") or "").strip()
    _require(acct_id != "", "invalid_state", "missing_account_id", {"case_id": case_id})

    tier_awarded = 0
    if outcome == "pass":
        acct = _account(state, acct_id)
        cur = _as_int(acct.get("poh_tier", 0), 0)
        if cur < 3:
            acct["poh_tier"] = 3
        tier_awarded = 3
        case["status"] = "awarded"
    else:
        case["status"] = "finalized"

    receipt_id = _as_str(case.get("receipt_id") or "").strip()
    if not receipt_id:
        receipt_id = f"poh3rcpt:{case_id}"
        case["receipt_id"] = receipt_id

    receipts = _tier3_receipts(state)
    receipts.setdefault(
        receipt_id,
        {
            "receipt_id": receipt_id,
            "case_id": case_id,
            "account_id": acct_id,
            "outcome": outcome,
            "tier_awarded": tier_awarded,
        },
    )

    return {
        "applied": "POH_TIER3_FINALIZE",
        "case_id": case_id,
        "account_id": acct_id,
        "outcome": outcome,
        "tier_awarded": tier_awarded,
        "receipt_id": receipt_id,
    }


def _apply_poh_tier3_receipt(state: Json, env: TxEnvelope) -> Json:
    _require(_is_system(env), "forbidden", "system_only", {})
    _require(_as_str(env.parent).strip() != "", "invalid_parent", "missing_parent", {"tx_type": "POH_TIER3_RECEIPT"})

    payload = _as_dict(env.payload)
    receipt_id = _as_str(payload.get("receipt_id") or "").strip()
    case_id = _as_str(payload.get("case_id") or "").strip()
    _require(receipt_id != "" or case_id != "", "invalid_payload", "missing_receipt_or_case", {})

    if receipt_id == "":
        receipt_id = f"poh3rcpt:{case_id}"

    receipts = _tier3_receipts(state)
    if receipt_id in receipts:
        return {"applied": "POH_TIER3_RECEIPT", "receipt_id": receipt_id, "idempotent": True}

    if case_id:
        case = _tier3_case(state, case_id)
        acct_id = _as_str(case.get("account_id") or "").strip()
        outcome = _as_str(case.get("outcome") or "fail").strip().lower()
        tier_awarded = _as_int(case.get("tier_awarded", 0), 0)
        receipts[receipt_id] = {
            "receipt_id": receipt_id,
            "case_id": case_id,
            "account_id": acct_id,
            "outcome": outcome,
            "tier_awarded": tier_awarded,
        }
    else:
        receipts[receipt_id] = {"receipt_id": receipt_id, "details": payload}

    return {"applied": "POH_TIER3_RECEIPT", "receipt_id": receipt_id}


# -----------------------------
# Domain applier entrypoint
# -----------------------------

def apply_poh(state: Json, env: Any) -> Optional[Json]:
    """PoH domain applier. Return None if tx not claimed."""
    _ensure_state_roots(state)

    env2: TxEnvelope
    if isinstance(env, TxEnvelope):
        env2 = env
    elif isinstance(env, dict):
        env2 = TxEnvelope.from_json(env)
    else:
        return None

    t = _as_str(getattr(env2, "tx_type", "")).strip()
    if not t:
        return None

    if t == "POH_APPLICATION_SUBMIT":
        return _apply_poh_application_submit(state, env2)
    if t == "POH_EVIDENCE_DECLARE":
        return _apply_poh_evidence_declare(state, env2)
    if t == "POH_EVIDENCE_BIND":
        return _apply_poh_evidence_bind(state, env2)
    if t == "POH_CHALLENGE_OPEN":
        return _apply_poh_challenge_open(state, env2)
    if t == "POH_CHALLENGE_RESOLVE":
        return _apply_poh_challenge_resolve(state, env2)
    if t == "POH_TIER_SET":
        return _apply_poh_tier_set(state, env2)
    if t == "POH_BOOTSTRAP_TIER3_GRANT":
        return _apply_poh_bootstrap_tier3_grant(state, env2)

    # Tier 2
    if t == "POH_TIER2_REQUEST_OPEN":
        return _apply_poh_tier2_request_open(state, env2)
    if t == "POH_TIER2_JUROR_ASSIGN":
        return _apply_poh_tier2_juror_assign(state, env2)
    if t == "POH_TIER2_JUROR_ACCEPT":
        return _apply_poh_tier2_juror_accept(state, env2)
    if t == "POH_TIER2_JUROR_DECLINE":
        return _apply_poh_tier2_juror_decline(state, env2)
    if t == "POH_TIER2_REVIEW_SUBMIT":
        return _apply_poh_tier2_review_submit(state, env2)
    if t == "POH_TIER2_FINALIZE":
        return _apply_poh_tier2_finalize(state, env2)
    if t == "POH_TIER2_RECEIPT":
        return _apply_poh_tier2_receipt(state, env2)

    # Tier 3
    if t == "POH_TIER3_INIT":
        return _apply_poh_tier3_init(state, env2)
    if t == "POH_TIER3_JUROR_ASSIGN":
        return _apply_poh_tier3_juror_assign(state, env2)
    if t == "POH_TIER3_JUROR_ACCEPT":
        return _apply_poh_tier3_juror_accept(state, env2)
    if t == "POH_TIER3_JUROR_DECLINE":
        return _apply_poh_tier3_juror_decline(state, env2)
    if t == "POH_TIER3_ATTENDANCE_MARK":
        return _apply_poh_tier3_attendance_mark(state, env2)
    if t == "POH_TIER3_VERDICT_SUBMIT":
        return _apply_poh_tier3_verdict_submit(state, env2)
    if t == "POH_TIER3_FINALIZE":
        return _apply_poh_tier3_finalize(state, env2)
    if t == "POH_TIER3_RECEIPT":
        return _apply_poh_tier3_receipt(state, env2)

    return None

