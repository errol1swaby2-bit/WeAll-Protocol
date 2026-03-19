from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Request

from weall.api.errors import ApiError
from weall.ledger.state import LedgerView
from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled

Json = Dict[str, Any]


class PublicRouteConfigError(ValueError):
    """Raised when explicit public-route config is malformed in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        v = str(raw or "").strip()
        return int(v) if v else int(default)
    except Exception as exc:
        if _is_prod():
            raise PublicRouteConfigError(f"invalid_integer_env:{name}") from exc
        return int(default)


async def _read_json_limited(
    request: Request,
    *,
    max_bytes_env: str,
    default_max_bytes: int,
) -> Any:
    """Read and parse JSON with a hard byte cap.

    This protects the public HTTP surface from huge payloads before JSON parsing.
    """
    max_bytes = int(_env_int(max_bytes_env, default_max_bytes))
    if max_bytes > 0:
        try:
            cl = request.headers.get("content-length")
            if cl is not None and int(cl) > max_bytes:
                raise ApiError.payload_too_large(
                    "payload_too_large",
                    "request body exceeds size limit",
                    {"bytes": int(cl), "max_bytes": int(max_bytes)},
                )
        except Exception:
            # Ignore malformed content-length; we still enforce after reading.
            pass

    raw = await request.body()
    if max_bytes > 0 and len(raw) > max_bytes:
        raise ApiError.payload_too_large(
            "payload_too_large",
            "request body exceeds size limit",
            {"bytes": int(len(raw)), "max_bytes": int(max_bytes)},
        )

    try:
        s = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
        return json.loads(s)
    except Exception:
        raise ApiError.bad_request("bad_request", "invalid JSON body", {})


def _executor(request: Request):
    ex = getattr(request.app.state, "executor", None)
    if ex is None:
        raise ApiError.internal("not_ready", "executor not attached to app.state", {})
    return ex


def _snapshot(request: Request) -> Json:
    """Return a dict snapshot of the current state.

    Supports:
      - SQLite executor: ex.read_state()
      - Legacy executor: ex.snapshot()
    """
    ex = _executor(request)

    if hasattr(ex, "read_state"):
        st = ex.read_state()
        return st if isinstance(st, dict) else dict(st)

    st = ex.snapshot()
    return st.to_dict() if hasattr(st, "to_dict") else (st if isinstance(st, dict) else dict(st))


def _mempool(request: Request):
    """Prefer executor-backed mempool (SQLite).

    Fall back to app.state.mempool only if an older boot path still sets it.
    """
    ex = _executor(request)
    mp = getattr(ex, "mempool", None)
    if mp is not None:
        return mp
    mp = getattr(request.app.state, "mempool", None)
    if mp is None:
        raise ApiError.internal("not_ready", "mempool not available", {})
    return mp


def _att_pool(request: Request):
    """Prefer executor-backed attestation pool (SQLite).

    Fall back to app.state.attestation_pool.
    """
    ex = _executor(request)
    ap = getattr(ex, "attestation_pool", None)
    if ap is not None:
        return ap
    ap = getattr(request.app.state, "attestation_pool", None)
    if ap is None:
        raise ApiError.internal("not_ready", "attestation_pool not available", {})
    return ap


def _int_param(v: Any, default: int) -> int:
    """Parse an int-ish query param safely."""
    if v is None:
        return int(default)
    try:
        s = str(v).strip()
        if s == "":
            return int(default)
        return int(s)
    except Exception:
        return int(default)


def _str_param(v: Any, default: str = "") -> str:
    """Parse a string-ish query param safely."""
    if v is None:
        return str(default)
    try:
        return str(v)
    except Exception:
        return str(default)


def _cursor_pack(*, created_at_nonce: int, content_id: str) -> str:
    """Encode pagination cursor as urlsafe base64."""
    raw = f"{int(created_at_nonce)}|{str(content_id)}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _cursor_unpack(cursor: Any) -> Tuple[Optional[int], Optional[str]]:
    """Decode pagination cursor. Returns (nonce, content_id) or (None, None)."""
    if cursor is None:
        return (None, None)
    s = _str_param(cursor).strip()
    if not s:
        return (None, None)

    # Restore base64 padding.
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode((s + pad).encode("ascii")).decode("utf-8", errors="strict")
    except Exception:
        return (None, None)

    if "|" not in raw:
        return (None, None)

    a, b = raw.split("|", 1)
    try:
        n = int(a)
    except Exception:
        return (None, None)

    cid = b.strip()
    if cid == "":
        return (None, None)

    return (n, cid)


def _normalize_tags_param(v: Any) -> List[str]:
    """Normalize tags query param into a list of unique, non-empty tags."""
    s = _str_param(v).strip()
    if not s:
        return []

    # split on comma primarily; also accept whitespace
    parts: List[str] = []
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        for p in chunk.split():
            p = p.strip()
            if p:
                parts.append(p)

    out: List[str] = []
    seen: set[str] = set()
    for t in parts:
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _groups_by_id(st: Dict[str, Any]) -> Dict[str, Any]:
    by_id = st.get("groups_by_id")
    if isinstance(by_id, dict):
        return by_id

    groups = st.get("groups")
    if isinstance(groups, dict):
        by_id2 = groups.get("by_id")
        if isinstance(by_id2, dict):
            return by_id2

    return {}


def _group_roles_by_id(st: Dict[str, Any]) -> Dict[str, Any]:
    by_id = st.get("group_roles_by_id")
    if isinstance(by_id, dict):
        return by_id

    by_id = st.get("groups_roles_by_id")
    if isinstance(by_id, dict):
        return by_id

    groups = st.get("groups")
    if isinstance(groups, dict):
        by_id2 = groups.get("roles_by_id")
        if isinstance(by_id2, dict):
            return by_id2

    return {}


def _require_valid_signer_format(*, signer: str, tx_type: str) -> None:
    """Fail-closed signer format enforcement for public HTTP."""
    s = str(signer or "").strip()
    if not s:
        raise ApiError.bad_request("invalid_payload", "missing signer", {})

    if strict_account_ids_enabled() and not is_valid_account_id(s):
        raise ApiError.bad_request(
            "invalid_signer",
            "signer does not match required account id format",
            {"signer": s, "tx_type": str(tx_type or "")},
        )


def _require_registered_account(ledger: LedgerView, account: str) -> Dict[str, Any]:
    acct = ledger.accounts.get(account)
    if not isinstance(acct, dict):
        raise ApiError.forbidden("not_registered", "signer account is not registered", {"account": account})
    if bool(acct.get("banned", False)):
        raise ApiError.forbidden("banned", "account is banned", {"account": account})
    if bool(acct.get("locked", False)):
        raise ApiError.forbidden("locked", "account is locked", {"account": account})
    return acct


def _require_registered_signer_for_user_tx(*, ledger: LedgerView, tx_type: str, signer: str) -> None:
    """Gatekeeper for user-submitted txs entering the mempool via HTTP."""

    tx_type = str(tx_type or "").strip()
    signer = str(signer or "").strip()

    if not tx_type:
        raise ApiError.bad_request("invalid_payload", "missing tx_type", {})

    _require_valid_signer_format(signer=signer, tx_type=tx_type)

    if signer == "SYSTEM":
        raise ApiError.forbidden(
            "system_tx_forbidden",
            "SYSTEM-signed txs are not accepted via public submission endpoints",
            {"tx_type": tx_type, "signer": signer},
        )

    # Signup flow: allow register even if the account does not exist yet.
    if tx_type == "ACCOUNT_REGISTER":
        return

    acct = _require_registered_account(ledger, signer)

    # PoH tier gating for content posting.
    # Posting content is intentionally conservative (Tier 3) to align with the
    # graduated trust model.
    #
    # IMPORTANT:
    #   Some clients submit the shorter aliases (POST_CREATE/POST_EDIT/POST_DELETE).
    #   Apply-time enforcement also gates these, but we must fail early at the HTTP
    #   boundary to keep the mempool clean and UX consistent.
    post_txs = {
        "CONTENT_POST_CREATE",
        "CONTENT_POST_EDIT",
        "CONTENT_POST_DELETE",
        # Back-compat aliases
        "CONTENT_POST_UPDATE",
        "POST_CREATE",
        "POST_EDIT",
        "POST_DELETE",
        "POST_UPDATE",
    }
    if tx_type in post_txs:
        tier = int(acct.get("poh_tier", 0) or 0)
        if tier < 3:
            raise ApiError.forbidden(
                "insufficient_poh_tier",
                "PoH Tier 3 is required to create/edit/delete posts",
                {"account": signer, "poh_tier": tier, "required": 3, "tx_type": tx_type},
            )


def _require_registered_signer_for_attestation(*, ledger: LedgerView, signer: str) -> None:
    signer = str(signer or "").strip()
    if not signer:
        raise ApiError.bad_request("invalid_payload", "missing signer", {})

    if strict_account_ids_enabled() and not is_valid_account_id(signer):
        raise ApiError.bad_request(
            "invalid_signer",
            "signer does not match required account id format",
            {"signer": signer},
        )

    _require_registered_account(ledger, signer)

    aset = ledger.get_active_validator_set() or []
    if signer not in aset:
        raise ApiError.forbidden(
            "not_validator",
            "signer is not in the active validator set",
            {"signer": signer, "active_set_size": int(len(aset))},
        )
