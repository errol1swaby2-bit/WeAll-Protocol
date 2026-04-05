from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts import common
from weall.crypto.sig import _decode_bytes, verify_ed25519_signature

router = APIRouter()


Json = dict[str, Any]


def _norm_account(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return ""
    return s if s.startswith("@") else f"@{s}"


def _norm_session_key(v: Any) -> str:
    return str(v or "").strip()


def _norm_device_id(v: Any) -> str:
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


def _canonical_session_login_message(*, account: str, session_key: str, ttl_s: int, issued_at_ms: int, device_id: str) -> bytes:
    payload = {
        "t": "SESSION_LOGIN",
        "account": str(account),
        "session_key": str(session_key),
        "ttl_s": int(ttl_s),
        "issued_at_ms": int(issued_at_ms),
        "device_id": str(device_id),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _active_account_pubkeys(arec: Json) -> set[str]:
    keys = arec.get("keys")
    if not isinstance(keys, dict):
        return set()
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        return set()
    out: set[str] = set()
    for rec in by_id.values():
        if not isinstance(rec, dict):
            continue
        if bool(rec.get("revoked", False)):
            continue
        pk = str(rec.get("pubkey") or "").strip()
        if pk:
            out.add(pk)
    return out


def _normalize_pubkey_bytes(pubkey: str) -> bytes | None:
    s = str(pubkey or "").strip()
    if not s:
        return None
    try:
        raw = _decode_bytes(s)
    except Exception:
        return None
    return raw if len(raw) == 32 else None


def _pubkey_is_authorized(pubkey: str, active_pubkeys: set[str]) -> bool:
    raw = _normalize_pubkey_bytes(pubkey)
    if raw is None:
        return False
    for candidate in active_pubkeys:
        cand_raw = _normalize_pubkey_bytes(candidate)
        if cand_raw is not None and cand_raw == raw:
            return True
    return False


def _session_device_record(*, account: str, pubkey: str, issued_at_ts: int, device_id: str) -> Json:
    fp = hashlib.sha256(f"{account}|{pubkey}|{device_id}".encode("utf-8")).hexdigest()[:16]
    return {
        "device_id": device_id,
        "device_type": "browser",
        "pubkey": pubkey,
        "revoked": False,
        "registered_at": issued_at_ts,
        "fingerprint": fp,
    }


@router.post("/session/login")
async def v1_session_login(request: Request):
    """Create a real backend-recognized device session from a signed login proof.

    Expected body:
      {
        "account": "@demo",
        "session_key": "<opaque session key>",
        "ttl_s": 86400,
        "issued_at_ms": 1770000000000,
        "device_id": "browser:...",   # optional but recommended
        "pubkey": "<account key pubkey>",
        "sig": "<detached signature over canonical SESSION_LOGIN payload>"
      }

    Security posture:
      - verifies account exists
      - verifies pubkey is an active key on that account
      - verifies detached signature over a canonical login message
      - persists both session_keys[...] and devices.by_id[device_id]
      - returns session material the browser can replay on protected routes
    """
    body = await common._read_json_limited(
        request,
        max_bytes_env="WEALL_MAX_JSON_BYTES",
        default_max_bytes=128 * 1024,
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "invalid JSON body", {})

    account = _norm_account(body.get("account"))
    session_key = _norm_session_key(body.get("session_key"))
    ttl_s = _ttl_s(body.get("ttl_s", 24 * 60 * 60))
    device_id = _norm_device_id(body.get("device_id") or f"browser:{account}")
    pubkey = str(body.get("pubkey") or "").strip()
    sig = str(body.get("sig") or "").strip()

    try:
        issued_at_ms = int(body.get("issued_at_ms") or 0)
    except Exception:
        issued_at_ms = 0

    if not account:
        raise ApiError.bad_request("account_required", "account is required", {})
    if not session_key:
        raise ApiError.bad_request("session_key_required", "session_key is required", {})
    if not pubkey:
        raise ApiError.bad_request("pubkey_required", "pubkey is required", {})
    if not sig:
        raise ApiError.bad_request("sig_required", "sig is required", {})
    if issued_at_ms <= 0:
        raise ApiError.bad_request("issued_at_ms_required", "issued_at_ms is required", {})

    st = common._snapshot(request)
    now_ms = _state_now_ts(st) * 1000
    max_skew_ms = 5 * 60 * 1000
    if now_ms > 0 and abs(now_ms - issued_at_ms) > max_skew_ms:
        raise ApiError.forbidden(
            "login_proof_stale",
            "login proof timestamp is outside the accepted clock skew window",
            {"max_skew_ms": max_skew_ms, "now_ms": now_ms, "issued_at_ms": issued_at_ms},
        )

    accounts = st.get("accounts")
    if not isinstance(accounts, dict):
        raise ApiError.internal("state_invalid", "accounts subtree missing", {})
    arec = accounts.get(account)
    if not isinstance(arec, dict):
        raise ApiError.not_found("account_not_found", "account does not exist", {"account": account})

    active_pubkeys = _active_account_pubkeys(arec)
    if not _pubkey_is_authorized(pubkey, active_pubkeys):
        raise ApiError.forbidden(
            "pubkey_not_authorized",
            "pubkey is not an active key on this account",
            {"account": account},
        )

    msg = _canonical_session_login_message(
        account=account,
        session_key=session_key,
        ttl_s=ttl_s,
        issued_at_ms=issued_at_ms,
        device_id=device_id,
    )
    if not verify_ed25519_signature(message=msg, sig=sig, pubkey=pubkey):
        raise ApiError.forbidden(
            "bad_sig",
            "session login signature verification failed",
            {"account": account},
        )

    ex = common._executor(request)
    ledger_store = getattr(ex, "_ledger_store", None)
    if ledger_store is None or not hasattr(ledger_store, "update"):
        raise ApiError.internal("not_ready", "ledger store update primitive unavailable", {})

    result: dict[str, Any] = {}

    def _mutate(st2: Json) -> Json:
        accounts2 = st2.get("accounts")
        if not isinstance(accounts2, dict):
            raise ApiError.internal("state_invalid", "accounts subtree missing", {})

        acct = accounts2.get(account)
        if not isinstance(acct, dict):
            raise ApiError.not_found("account_not_found", "account does not exist", {"account": account})

        sessions = acct.get("session_keys")
        if not isinstance(sessions, dict):
            sessions = {}
            acct["session_keys"] = sessions

        devices = acct.get("devices")
        if not isinstance(devices, dict):
            devices = {"by_id": {}}
            acct["devices"] = devices
        by_id = devices.get("by_id")
        if not isinstance(by_id, dict):
            by_id = {}
            devices["by_id"] = by_id

        issued_at_ts = _state_now_ts(st2)
        sessions[session_key] = {
            "active": True,
            "issued_at_ts": int(issued_at_ts),
            "ttl_s": int(ttl_s),
            "issued_at_height": int(st2.get("height") or 0),
            "pubkey": pubkey,
            "device_id": device_id,
        }
        by_id[device_id] = _session_device_record(
            account=account,
            pubkey=pubkey,
            issued_at_ts=int(issued_at_ts),
            device_id=device_id,
        )

        result.update(
            {
                "issued_at_ts": int(issued_at_ts),
                "account": account,
                "session_key": session_key,
                "ttl_s": int(ttl_s),
                "device_id": device_id,
                "pubkey": pubkey,
            }
        )
        return st2

    ledger_store.update(_mutate)

    try:
        ex.read_state()
    except Exception:
        pass

    return {
        "ok": True,
        "account": result["account"],
        "device": {
            "device_id": result["device_id"],
            "pubkey": result["pubkey"],
        },
        "session": {
            "session_key": result["session_key"],
            "issued_at_ts": result["issued_at_ts"],
            "ttl_s": result["ttl_s"],
            "active": True,
        },
    }


@router.post("/session/create")
async def v1_session_create(request: Request):
    """Dev/local helper to create a browser session record directly in the ledger snapshot."""
    body = await common._read_json_limited(
        request,
        max_bytes_env="WEALL_MAX_JSON_BYTES",
        default_max_bytes=128 * 1024,
    )
    if not isinstance(body, dict):
        raise ApiError.bad_request("bad_request", "invalid JSON body", {})

    account = _norm_account(body.get("account"))
    session_key = _norm_session_key(body.get("session_key"))
    ttl_s = _ttl_s(body.get("ttl_s", 24 * 60 * 60))
    device_id = _norm_device_id(body.get("device_id") or f"browser:{account}")

    if not account:
        raise ApiError.bad_request("account_required", "account is required", {})
    if not session_key:
        raise ApiError.bad_request("session_key_required", "session_key is required", {})

    ex = common._executor(request)
    ledger_store = getattr(ex, "_ledger_store", None)
    if ledger_store is None or not hasattr(ledger_store, "update"):
        raise ApiError.internal("not_ready", "ledger store update primitive unavailable", {})

    result: dict[str, Any] = {}

    def _mutate(st: Json) -> Json:
        accounts = st.get("accounts")
        if not isinstance(accounts, dict):
            raise ApiError.internal("state_invalid", "accounts subtree missing", {})

        acct = accounts.get(account)
        if not isinstance(acct, dict):
            raise ApiError.not_found(
                "account_not_found", "account does not exist", {"account": account}
            )

        sessions = acct.get("session_keys")
        if not isinstance(sessions, dict):
            sessions = {}
            acct["session_keys"] = sessions

        devices = acct.get("devices")
        if not isinstance(devices, dict):
            devices = {"by_id": {}}
            acct["devices"] = devices
        by_id = devices.get("by_id")
        if not isinstance(by_id, dict):
            by_id = {}
            devices["by_id"] = by_id

        issued_at_ts = _state_now_ts(st)
        sessions[session_key] = {
            "active": True,
            "issued_at_ts": int(issued_at_ts),
            "ttl_s": int(ttl_s),
            "device_id": device_id,
        }
        by_id.setdefault(
            device_id,
            {
                "device_id": device_id,
                "device_type": "browser",
                "revoked": False,
                "registered_at": int(issued_at_ts),
            },
        )

        result["issued_at_ts"] = int(issued_at_ts)
        result["account"] = account
        result["session_key"] = session_key
        result["ttl_s"] = int(ttl_s)
        result["device_id"] = device_id
        return st

    ledger_store.update(_mutate)

    try:
        ex.read_state()
    except Exception:
        pass

    return {
        "ok": True,
        "account": result["account"],
        "device": {"device_id": result["device_id"]},
        "session": {
            "session_key": result["session_key"],
            "issued_at_ts": result["issued_at_ts"],
            "ttl_s": result["ttl_s"],
            "active": True,
        },
    }


@router.get("/session/me")
def v1_session_me(request: Request):
    """Small helper for debugging whether the client currently has a valid session."""
    st = common._snapshot(request)

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
            "device_id": str(srec.get("device_id") or ""),
        },
    }
