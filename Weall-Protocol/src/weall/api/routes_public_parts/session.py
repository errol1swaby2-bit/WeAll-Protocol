from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _executor, _read_json_limited, _snapshot

router = APIRouter()


Json = Dict[str, Any]


def _norm_account(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return ""
    return s if s.startswith("@") else f"@{s}"


def _norm_session_key(v: Any) -> str:
    return str(v or "").strip()


def _ttl_s(v: Any, default: int = 24 * 60 * 60) -> int:
    try:
        n = int(v)
    except Exception:
        n = int(default)
    if n <= 0:
        n = int(default)
    return n


def _state_now_ts(st: Json) -> int:
    raw = st.get("time")
    if isinstance(raw, int) and raw >= 0:
        return raw
    return int(time.time())


@router.post("/session/create")
async def v1_session_create(request: Request):
    """
    Dev/local helper to create a browser session record directly in the ledger snapshot.

    Expected body:
      {
        "account": "@demo",
        "session_key": "<opaque session key>",
        "ttl_s": 86400
      }

    This endpoint is intentionally narrow:
      - it only creates or refreshes a session entry for an existing account
      - it does not create accounts
      - it does not mint keys
      - it does not bypass PoH or role gates
    """
    body = await _read_json_limited(
        request,
        max_bytes_env="WEALL_MAX_JSON_BYTES",
        default_max_bytes=128 * 1024,
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "invalid JSON body", {})

    account = _norm_account(body.get("account"))
    session_key = _norm_session_key(body.get("session_key"))
    ttl_s = _ttl_s(body.get("ttl_s", 24 * 60 * 60))

    if not account:
        raise ApiError.bad_request("account_required", "account is required", {})
    if not session_key:
        raise ApiError.bad_request("session_key_required", "session_key is required", {})

    ex = _executor(request)

    ledger_store = getattr(ex, "_ledger_store", None)
    if ledger_store is None or not hasattr(ledger_store, "update"):
        raise ApiError.internal("not_ready", "ledger store update primitive unavailable", {})

    result: Dict[str, Any] = {}

    def _mutate(st: Json) -> Json:
        accounts = st.get("accounts")
        if not isinstance(accounts, dict):
            raise ApiError.internal("state_invalid", "accounts subtree missing", {})

        acct = accounts.get(account)
        if not isinstance(acct, dict):
            raise ApiError.not_found("account_not_found", "account does not exist", {"account": account})

        sessions = acct.get("session_keys")
        if not isinstance(sessions, dict):
            sessions = {}
            acct["session_keys"] = sessions

        issued_at_ts = _state_now_ts(st)
        sessions[session_key] = {
            "active": True,
            "issued_at_ts": int(issued_at_ts),
            "ttl_s": int(ttl_s),
        }

        result["issued_at_ts"] = int(issued_at_ts)
        result["account"] = account
        result["session_key"] = session_key
        result["ttl_s"] = int(ttl_s)
        return st

    ledger_store.update(_mutate)

    # keep the in-process executor view warm after cross-process snapshot update
    try:
        ex.read_state()
    except Exception:
        pass

    return {
        "ok": True,
        "account": result["account"],
        "session": {
            "session_key": result["session_key"],
            "issued_at_ts": result["issued_at_ts"],
            "ttl_s": result["ttl_s"],
            "active": True,
        },
    }


@router.get("/session/me")
def v1_session_me(request: Request):
    """
    Small helper for debugging whether the client currently has a valid session.
    """
    st = _snapshot(request)

    acct = (request.headers.get("x-weall-account") or "").strip()
    sk = (request.headers.get("x-weall-session-key") or "").strip()

    if not acct or not sk:
        return {
            "ok": True,
            "authenticated": False,
            "reason": "session_missing",
        }

    accounts = st.get("accounts")
    if not isinstance(accounts, dict):
        return {
            "ok": True,
            "authenticated": False,
            "reason": "session_invalid",
        }

    arec = accounts.get(acct)
    if not isinstance(arec, dict):
        return {
            "ok": True,
            "authenticated": False,
            "reason": "session_invalid",
        }

    sessions = arec.get("session_keys")
    if not isinstance(sessions, dict):
        return {
            "ok": True,
            "authenticated": False,
            "reason": "session_invalid",
        }

    srec = sessions.get(sk)
    if not isinstance(srec, dict):
        return {
            "ok": True,
            "authenticated": False,
            "reason": "session_invalid",
        }

    active = bool(srec.get("active", False))
    issued_at_ts = int(srec.get("issued_at_ts", 0) or 0)
    ttl_s = int(srec.get("ttl_s", 0) or 0)

    expired = False
    now = _state_now_ts(st)
    if ttl_s > 0 and issued_at_ts > 0 and now > (issued_at_ts + ttl_s):
        expired = True

    return {
        "ok": True,
        "authenticated": bool(active and not expired),
        "account": acct,
        "session": {
            "active": active,
            "issued_at_ts": issued_at_ts,
            "ttl_s": ttl_s,
            "expired": expired,
        },
    }

