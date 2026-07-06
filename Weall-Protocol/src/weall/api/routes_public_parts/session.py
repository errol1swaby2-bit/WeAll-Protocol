from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.mode_isolation import direct_session_mutation_issue
from weall.api.routes_public_parts import common
from weall.crypto.sig import _decode_bytes, verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, normalize_signature_profile_id, profile_allowed_for_context
from weall.runtime.session_keys import session_record_for, store_session_record

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


def _canonical_session_login_message(
    *,
    account: str,
    session_key: str,
    ttl_s: int,
    issued_at_ms: int,
    device_id: str,
    sig_profile: str | None = None,
    chain_id: str | None = None,
    network_id: str | None = None,
) -> bytes:
    profile = normalize_signature_profile_id(sig_profile)
    payload = {
        "t": "SESSION_LOGIN",
        "account": str(account),
        "session_key": str(session_key),
        "ttl_s": int(ttl_s),
        "issued_at_ms": int(issued_at_ms),
        "device_id": str(device_id),
    }
    if profile:
        payload.update(
            {
                "domain_separator": "weall.session.login.v1",
                "object_kind": "session_login",
                "sig_profile": profile,
            }
        )
        if chain_id:
            payload["chain_id"] = str(chain_id)
        if network_id:
            payload["network_id"] = str(network_id)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _state_chain_context(st: Json) -> tuple[str, str]:
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    chain = st.get("chain") if isinstance(st.get("chain"), dict) else {}
    cfg = st.get("config") if isinstance(st.get("config"), dict) else {}
    chain_id = str(meta.get("chain_id") or chain.get("chain_id") or cfg.get("chain_id") or "").strip()
    network_id = str(meta.get("network_id") or chain.get("network_id") or cfg.get("network_id") or "").strip()
    return chain_id, network_id


def _active_account_pubkeys(arec: Json, *, sig_profile: str = "") -> set[str]:
    wanted = normalize_signature_profile_id(sig_profile)
    keys = arec.get("keys")
    records: list[Json] = []
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            records.extend(rec for rec in by_id.values() if isinstance(rec, dict))
    elif isinstance(keys, list):
        records.extend(rec for rec in keys if isinstance(rec, dict))

    out: set[str] = set()
    for rec in records:
        if bool(rec.get("revoked", False)) or bool(rec.get("revoked_at") not in (None, "")):
            continue
        rec_profile = normalize_signature_profile_id(rec.get("sig_profile"))
        effective_profile = rec_profile or PQ_MLDSA_V1
        if wanted and effective_profile != wanted:
            continue
        pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
        pk = ""
        if effective_profile == PQ_MLDSA_V1:
            pk = str(pubkeys.get("mldsa") or rec.get("mldsa_pubkey") or rec.get("pubkey") or "").strip()
        else:
            pk = ""
        if pk:
            out.add(pk)
    return out


def _normalize_pubkey_bytes(pubkey: str) -> bytes | None:
    s = str(pubkey or "").strip()
    if not s:
        return None
    try:
        return _decode_bytes(s)
    except Exception:
        return None


def _pubkey_is_authorized(pubkey: str, active_pubkeys: set[str]) -> bool:
    raw = _normalize_pubkey_bytes(pubkey)
    if raw is None:
        return False
    for candidate in active_pubkeys:
        cand_raw = _normalize_pubkey_bytes(candidate)
        if cand_raw is not None and cand_raw == raw:
            return True
    return False


def _reject_direct_session_mutation_if_forbidden() -> None:
    issue = direct_session_mutation_issue()
    if issue:
        raise ApiError.forbidden(
            issue,
            "direct session mutation is disabled in this runtime profile; issue session/device state through canonical transactions",
            {"required_flow": "ACCOUNT_SESSION_KEY_ISSUE or ACCOUNT_DEVICE_REGISTER"},
        )


def _session_device_record(*, account: str, pubkey: str, sig_profile: str, issued_at_ts: int, device_id: str) -> Json:
    fp = hashlib.sha256(f"{account}|{sig_profile}|{pubkey}|{device_id}".encode("utf-8")).hexdigest()[:16]
    return {
        "device_id": device_id,
        "device_type": "browser",
        "pubkey": pubkey,
        "sig_profile": sig_profile,
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
        "sig_profile": "pq-mldsa-v1",
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
    _reject_direct_session_mutation_if_forbidden()
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
    sig_profile = normalize_signature_profile_id(body.get("sig_profile"))
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
    if not sig_profile:
        raise ApiError.bad_request("sig_profile_required", "sig_profile is required", {})
    allowed, allowed_reason = profile_allowed_for_context(sig_profile, require_verifier=True)
    if not allowed:
        raise ApiError.forbidden(
            allowed_reason,
            "session login signature profile is not allowed in this runtime profile",
            {"sig_profile": sig_profile},
        )
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

    active_pubkeys = _active_account_pubkeys(arec, sig_profile=sig_profile)
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
        sig_profile=sig_profile,
        chain_id=_state_chain_context(st)[0],
        network_id=_state_chain_context(st)[1],
    )
    if not verify_signature_for_profile(sig_profile=sig_profile, message=msg, sig=sig, pubkey=pubkey):
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
        store_session_record(
            sessions,
            session_key,
            {
                "active": True,
                "issued_at_ts": int(issued_at_ts),
                "ttl_s": int(ttl_s),
                "issued_at_height": int(st2.get("height") or 0),
                "pubkey": pubkey,
                "sig_profile": sig_profile,
                "device_id": device_id,
            },
        )
        by_id[device_id] = _session_device_record(
            account=account,
            pubkey=pubkey,
            sig_profile=sig_profile,
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
                "sig_profile": sig_profile,
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
            "sig_profile": sig_profile,
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
    _reject_direct_session_mutation_if_forbidden()
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
        store_session_record(
            sessions,
            session_key,
            {
                "active": True,
                "issued_at_ts": int(issued_at_ts),
                "ttl_s": int(ttl_s),
                "device_id": device_id,
            },
        )
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

    srec = session_record_for(sessions, sk)
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
