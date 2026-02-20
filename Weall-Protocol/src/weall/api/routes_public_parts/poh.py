# src/weall/api/routes_public_parts/poh.py
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from weall.poh.email_verification import EmailVerificationService
from weall.runtime.executor import WeAllExecutor

router = APIRouter()

Json = Dict[str, Any]


def _executor(request: Request) -> WeAllExecutor:
    ex = getattr(request.app.state, "executor", None)
    if not isinstance(ex, WeAllExecutor):
        raise HTTPException(status_code=500, detail={"code": "no_executor"})
    return ex


def _snapshot(ex: WeAllExecutor) -> Json:
    try:
        st = ex.read_state()
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


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


class PohEmailBeginRequest(BaseModel):  # type: ignore
    email: str = Field(..., min_length=3)  # type: ignore
    account: str = Field(..., min_length=1)  # type: ignore


class PohEmailBeginResponse(BaseModel):  # type: ignore
    ok: bool
    request_id: str
    expires_ms: int


class PohEmailConfirmRequest(BaseModel):  # type: ignore
    request_id: str = Field(..., min_length=3)  # type: ignore
    code: str = Field(..., min_length=3)  # type: ignore
    account: str = Field(..., min_length=1)  # type: ignore


class PohTier2StartRequest(BaseModel):  # type: ignore
    account_id: str = Field(..., min_length=1)  # type: ignore
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None


class PohTier2JurorAcceptRequest(BaseModel):  # type: ignore
    case_id: str = Field(..., min_length=1)  # type: ignore
    signer: str = Field(..., min_length=1)  # type: ignore
    nonce: int = Field(..., ge=0)  # type: ignore
    sig: str = Field(..., min_length=0)  # type: ignore
    ts_ms: Optional[int] = None


class PohTier2JurorDeclineRequest(BaseModel):  # type: ignore
    case_id: str = Field(..., min_length=1)  # type: ignore
    signer: str = Field(..., min_length=1)  # type: ignore
    nonce: int = Field(..., ge=0)  # type: ignore
    sig: str = Field(..., min_length=0)  # type: ignore
    reason: Optional[str] = None
    ts_ms: Optional[int] = None


class PohTier2ReviewSubmitRequest(BaseModel):  # type: ignore
    case_id: str = Field(..., min_length=1)  # type: ignore
    signer: str = Field(..., min_length=1)  # type: ignore
    nonce: int = Field(..., ge=0)  # type: ignore
    sig: str = Field(..., min_length=0)  # type: ignore
    verdict: str = Field(..., min_length=1)  # type: ignore  # "pass"|"fail"
    notes: Optional[str] = None
    ts_ms: Optional[int] = None


class PohTier3StartRequest(BaseModel):  # type: ignore
    account_id: str = Field(..., min_length=1)  # type: ignore


class PohTier3StartResponse(BaseModel):  # type: ignore
    ok: bool
    case_id: str
    jurors_assigned: int


def _svc(request: Request) -> EmailVerificationService:
    svc = getattr(request.app.state, "poh_email_svc", None)
    if isinstance(svc, EmailVerificationService):
        return svc

    secret = str(os.environ.get("WEALL_POH_EMAIL_SECRET") or "").strip()
    if not secret:
        # fallback secret for local dev; production must set env
        secret = secrets.token_hex(16)

    ttl_ms = _as_int(os.environ.get("WEALL_POH_EMAIL_TTL_MS"), 15 * 60 * 1000)
    svc = EmailVerificationService(secret=secret, ttl_ms=ttl_ms)

    setattr(request.app.state, "poh_email_svc", svc)
    return svc


@router.post("/poh/email/begin", response_model=PohEmailBeginResponse)
def poh_email_begin(request: Request, req: PohEmailBeginRequest) -> PohEmailBeginResponse:
    svc = _svc(request)
    email = str(req.email).strip()
    account = str(req.account).strip()

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail={"code": "bad_email"})

    if not account:
        raise HTTPException(status_code=400, detail={"code": "bad_account"})

    # NOTE: in production, send email via oracle/service.
    # For MVP, we return request_id and code in logs only (not in response).
    res = svc.begin(email=email, account=account)

    return PohEmailBeginResponse(ok=True, request_id=res["request_id"], expires_ms=res["expires_ms"])


@router.post("/poh/email/confirm")
def poh_email_confirm(request: Request, req: PohEmailConfirmRequest) -> dict[str, object]:
    svc = _svc(request)
    ex = _executor(request)

    ok = svc.confirm(request_id=str(req.request_id).strip(), code=str(req.code).strip(), account=str(req.account).strip())
    if not ok:
        raise HTTPException(status_code=400, detail={"code": "invalid_code"})

    # If the account is not registered yet, auto-register a minimal record.
    st = _snapshot(ex)
    accounts = st.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
        st["accounts"] = accounts

    acct = accounts.get(str(req.account))
    if not isinstance(acct, dict):
        # Emit ACCOUNT_REGISTER (user-origin in canon), but for MVP we allow a system helper.
        # In production, this should be done by the frontend with proper signatures.
        register_env: Dict[str, Any] = {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": str(req.account),
            "nonce": 0,
            "sig": "",
            "payload": {"account_id": str(req.account), "pubkey": "email_bootstrap"},
        }
        r1 = ex.submit_tx(register_env)
        if not r1.get("ok"):
            raise HTTPException(status_code=500, detail={"code": "register_failed", "details": r1})

    # Set Tier 1 via system tx.
    poh_tier_set_env: Dict[str, Any] = {
        "tx_type": "POH_TIER_SET",
        "signer": "SYSTEM",
        "nonce": 0,
        "sig": "",
        "system": True,
        "parent": "DISPUTE_RESOLVE",
        "payload": {"account_id": str(req.account), "tier": 1},
    }
    r2 = ex.submit_tx(poh_tier_set_env)
    if not r2.get("ok"):
        raise HTTPException(status_code=500, detail={"code": "tier_set_failed", "details": r2})

    return {"ok": True, "account": str(req.account), "tier": 1}


@router.post("/poh/tier2/start")
def poh_tier2_start(request: Request, req: PohTier2StartRequest) -> dict[str, object]:
    """Open a Tier 2 review case (user tx).

    Juror assignment + finalize are handled by the block-path scheduler.
    """
    ex = _executor(request)
    st = _snapshot(ex)

    account_id = str(req.account_id).strip()
    if not account_id:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "account_id is required"})

    accounts = st.get("accounts")
    if not isinstance(accounts, dict) or account_id not in accounts:
        raise HTTPException(status_code=403, detail={"code": "not_registered", "message": "account not registered"})
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise HTTPException(status_code=403, detail={"code": "not_registered", "message": "account not registered"})
    if bool(acct.get("banned", False)) or bool(acct.get("locked", False)):
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "account is banned or locked"})
    if int(acct.get("poh_tier", 0) or 0) < 1:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "tier>=1 required to start tier2 flow"})

    case_id = (str(req.case_id).strip() if req.case_id else "").strip()
    if not case_id:
        height = int(st.get("height", 0) or 0)
        case_id = f"poh2:{account_id}:{height + 1}"

    evidence_id = (str(req.evidence_id).strip() if req.evidence_id else "").strip()

    env: Dict[str, Any] = {
        "tx_type": "POH_TIER2_REQUEST_OPEN",
        "signer": account_id,
        "nonce": 0,
        "sig": "",
        "payload": {"account_id": account_id, "case_id": case_id, "evidence_id": evidence_id},
    }

    r = ex.submit_tx(env)
    if not r.get("ok"):
        raise HTTPException(status_code=403, detail={"code": "tx_submit_failed", "which": "POH_TIER2_REQUEST_OPEN", "details": r})

    return {"ok": True, "case_id": case_id, "account_id": account_id, "tx_id": str(r.get("tx_id") or "")}


@router.get("/poh/tier2/case/{case_id}")
def poh_tier2_case_get(request: Request, case_id: str) -> dict[str, object]:
    ex = _executor(request)
    st = _snapshot(ex)

    cid = (case_id or "").strip()
    if not cid:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "case_id required"})

    poh = st.get("poh")
    if not isinstance(poh, dict):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "case not found"})

    cases = poh.get("tier2_cases")
    if not isinstance(cases, dict):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "case not found"})

    case = cases.get(cid)
    if not isinstance(case, dict):
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "case not found"})

    receipts = poh.get("tier2_receipts")
    receipt_id = str(case.get("receipt_id") or "").strip()
    receipt = None
    if isinstance(receipts, dict) and receipt_id:
        r = receipts.get(receipt_id)
        if isinstance(r, dict):
            receipt = r

    return {"ok": True, "case": case, "receipt": receipt}


@router.get("/poh/tier2/juror/tasks/{juror_id}")
def poh_tier2_juror_tasks(request: Request, juror_id: str) -> dict[str, object]:
    ex = _executor(request)
    st = _snapshot(ex)

    jid = (juror_id or "").strip()
    if not jid:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "juror_id required"})

    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {"ok": True, "juror_id": jid, "tasks": []}

    cases = poh.get("tier2_cases")
    if not isinstance(cases, dict):
        return {"ok": True, "juror_id": jid, "tasks": []}

    receipts = poh.get("tier2_receipts")
    receipts = receipts if isinstance(receipts, dict) else {}

    tasks: list[dict[str, object]] = []

    for case_id, case in cases.items():
        if not isinstance(case, dict):
            continue
        jurors = case.get("jurors")
        if not isinstance(jurors, dict):
            continue
        jrec = jurors.get(jid)
        if not isinstance(jrec, dict):
            continue

        accepted = jrec.get("accepted")
        verdict = _as_str(jrec.get("verdict") or "")

        status = _as_str(case.get("status") or "")
        account_id = _as_str(case.get("account_id") or "")
        cid2 = _as_str(case.get("case_id") or case_id) or _as_str(case_id)

        receipt_id = _as_str(case.get("receipt_id") or "")
        receipt = None
        if receipt_id and receipt_id in receipts and isinstance(receipts.get(receipt_id), dict):
            receipt = receipts.get(receipt_id)

        needs_response = accepted is None
        needs_review = (accepted is True and verdict not in ("pass", "fail"))

        tasks.append(
            {
                "case_id": cid2,
                "account_id": account_id,
                "case_status": status,
                "juror": {"accepted": accepted, "verdict": verdict if verdict else None},
                "todo": {"needs_response": bool(needs_response), "needs_review": bool(needs_review)},
                "receipt": receipt,
            }
        )

    tasks.sort(key=lambda x: (_as_str(x.get("case_id") or "")))

    return {"ok": True, "juror_id": jid, "tasks": tasks}


@router.post("/poh/tier2/juror/accept")
def poh_tier2_juror_accept(request: Request, req: PohTier2JurorAcceptRequest) -> dict[str, object]:
    ex = _executor(request)
    env: Dict[str, Any] = {
        "tx_type": "POH_TIER2_JUROR_ACCEPT",
        "signer": str(req.signer).strip(),
        "nonce": int(req.nonce),
        "sig": str(req.sig or ""),
        "payload": {"case_id": str(req.case_id).strip(), "ts_ms": int(req.ts_ms or 0)},
    }
    r = ex.submit_tx(env)
    if not r.get("ok"):
        raise HTTPException(status_code=403, detail={"code": "tx_submit_failed", "which": "POH_TIER2_JUROR_ACCEPT", "details": r})
    return {"ok": True, "tx_id": str(r.get("tx_id") or ""), "case_id": str(req.case_id).strip()}


@router.post("/poh/tier2/juror/decline")
def poh_tier2_juror_decline(request: Request, req: PohTier2JurorDeclineRequest) -> dict[str, object]:
    ex = _executor(request)
    env: Dict[str, Any] = {
        "tx_type": "POH_TIER2_JUROR_DECLINE",
        "signer": str(req.signer).strip(),
        "nonce": int(req.nonce),
        "sig": str(req.sig or ""),
        "payload": {"case_id": str(req.case_id).strip(), "reason": (str(req.reason).strip() if req.reason else ""), "ts_ms": int(req.ts_ms or 0)},
    }
    r = ex.submit_tx(env)
    if not r.get("ok"):
        raise HTTPException(status_code=403, detail={"code": "tx_submit_failed", "which": "POH_TIER2_JUROR_DECLINE", "details": r})
    return {"ok": True, "tx_id": str(r.get("tx_id") or ""), "case_id": str(req.case_id).strip()}


@router.post("/poh/tier2/juror/review")
def poh_tier2_juror_review(request: Request, req: PohTier2ReviewSubmitRequest) -> dict[str, object]:
    ex = _executor(request)

    verdict = str(req.verdict).strip().lower()
    if verdict not in ("pass", "fail"):
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "verdict must be 'pass' or 'fail'"})

    env: Dict[str, Any] = {
        "tx_type": "POH_TIER2_REVIEW_SUBMIT",
        "signer": str(req.signer).strip(),
        "nonce": int(req.nonce),
        "sig": str(req.sig or ""),
        "payload": {"case_id": str(req.case_id).strip(), "verdict": verdict, "notes": (str(req.notes) if req.notes else ""), "ts_ms": int(req.ts_ms or 0)},
    }

    r = ex.submit_tx(env)
    if not r.get("ok"):
        raise HTTPException(status_code=403, detail={"code": "tx_submit_failed", "which": "POH_TIER2_REVIEW_SUBMIT", "details": r})

    return {"ok": True, "tx_id": str(r.get("tx_id") or ""), "case_id": str(req.case_id).strip(), "verdict": verdict}


@router.post("/poh/tier3/start", response_model=PohTier3StartResponse)
def poh_tier3_start(request: Request, req: PohTier3StartRequest) -> PohTier3StartResponse:
    ex = _executor(request)

    account_id = str(req.account_id).strip()
    if not account_id:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "account_id is required"})

    st = _snapshot(ex)
    accounts = st.get("accounts")
    if not isinstance(accounts, dict) or account_id not in accounts:
        raise HTTPException(status_code=403, detail={"code": "not_registered", "message": "account not registered"})
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        raise HTTPException(status_code=403, detail={"code": "not_registered", "message": "account not registered"})
    if bool(acct.get("banned", False)) or bool(acct.get("locked", False)):
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "account is banned or locked"})
    if int(acct.get("poh_tier", 0) or 0) < 2:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "tier>=2 required to start tier3 flow"})

    # Create a case id.
    height = int(st.get("height", 0) or 0)
    case_id = f"poh3:{account_id}:{height + 1}"

    # Select jurors from local state snapshot (MVP deterministic selection).
    # In production, selection must be deterministic across validators; we will migrate this
    # into the scheduler/consensus path. For now, we pick based on state ordering + reputation.
    from weall.runtime.poh.juror_select import pick_tier3_jurors

    interacting, observing = pick_tier3_jurors(state=st, case_id=case_id, target_account=account_id, n_interacting=3, n_observing=7)
    jurors = list(interacting) + list(observing)
    if len(jurors) != 10:
        raise HTTPException(status_code=500, detail={"code": "juror_select_failed"})

    # Emit system txs to init + assign (receipt-only in canon).
    init_env: Dict[str, Any] = {
        "tx_type": "POH_TIER3_INIT",
        "signer": "SYSTEM",
        "nonce": 0,
        "sig": "",
        "system": True,
        "parent": "POH_TIER_SET",
        "payload": {"account_id": account_id, "case_id": case_id},
    }
    r1 = ex.submit_tx(init_env)
    if not r1.get("ok"):
        raise HTTPException(status_code=500, detail={"code": "tier3_init_failed", "details": r1})

    assign_env: Dict[str, Any] = {
        "tx_type": "POH_TIER3_JUROR_ASSIGN",
        "signer": "SYSTEM",
        "nonce": 0,
        "sig": "",
        "system": True,
        "parent": "POH_TIER3_INIT",
        "payload": {"case_id": case_id, "jurors": jurors},
    }
    r2 = ex.submit_tx(assign_env)
    if not r2.get("ok"):
        raise HTTPException(status_code=500, detail={"code": "tier3_assign_failed", "details": r2})

    return PohTier3StartResponse(ok=True, case_id=case_id, jurors_assigned=len(jurors))
