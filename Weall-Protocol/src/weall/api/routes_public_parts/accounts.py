from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.public_redaction import redact_account_state
from weall.api.routes_public_parts.common import (
    _cursor_pack,
    _cursor_unpack,
    _int_param,
    _snapshot,
    _str_param,
)
from weall.api.security import require_account_session
from weall.api.routes_public_parts.content import _content_target_hidden_by_review, _with_media_summaries
from weall.ledger.state import LedgerView
from weall.runtime.node_operator_responsibilities import evaluate_node_operator_responsibilities
from weall.runtime.reviewer_responsibilities import REVIEWER_LANES, reviewer_lane_active, reviewer_lane_record

router = APIRouter()


def _iter_posts_by_author(st: dict[str, Any], *, author: str) -> list[dict[str, Any]]:
    content = st.get("content")
    if not isinstance(content, dict):
        return []
    posts = content.get("posts")
    if not isinstance(posts, dict):
        return []

    out: list[dict[str, Any]] = []
    for pid, obj in posts.items():
        if not isinstance(obj, dict):
            continue
        if bool(obj.get("deleted", False)):
            continue
        post_id = _str_param(obj.get("post_id") or obj.get("id") or pid).strip()
        if post_id and _content_post_hidden_by_moderation(st, obj, post_id):
            continue
        if _str_param(obj.get("author")).strip() != author:
            continue

        row = dict(obj)
        row.setdefault("id", post_id)
        row.setdefault("created_at_nonce", int(row.get("created_nonce", 0) or 0))
        row.setdefault("visibility", "public")
        out.append(row)

    return out


def _content_post_hidden_by_moderation(st: dict[str, Any], post: dict[str, Any], post_id: str = "") -> bool:
    """Return True when moderation/dispute outcome removes a post from normal reads."""

    pid = _str_param(post_id or post.get("post_id") or post.get("id") or "").strip()
    return _content_target_hidden_by_review(st, pid, post)


def _normalize_keys(acct: dict[str, Any]) -> list[dict]:
    ks = acct.get("keys")
    out: list[dict] = []

    if isinstance(ks, dict):
        for pubkey, rec in ks.items():
            p = str(pubkey or "").strip()
            if not p:
                continue
            active = bool(rec.get("active", True)) if isinstance(rec, dict) else bool(rec)
            out.append({"pubkey": p, "active": active})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    if isinstance(ks, list):
        for it in ks:
            p = str(it or "").strip()
            if p:
                out.append({"pubkey": p, "active": True})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    return out


class AccountRegisterTxRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    pubkey: str = Field(..., min_length=1, max_length=256)
    parent: str | None = Field(default=None, max_length=256)


@router.post("/accounts/tx/register")
def v1_account_tx_register(req: AccountRegisterTxRequest) -> dict[str, Any]:
    """Return a canonical ACCOUNT_REGISTER tx skeleton.

    This route does not create an account and does not bypass signature, nonce,
    mempool, consensus, or execution. It exists so controlled devnet scripts and
    external clients can construct the same normal onboarding transaction without
    depending on seeded-demo helpers.
    """
    account_id = str(req.account_id or "").strip()
    pubkey = str(req.pubkey or "").strip()
    parent = str(req.parent).strip() if req.parent is not None else None
    if not account_id:
        raise ApiError.bad_request("bad_request", "missing account_id", {})
    if not pubkey:
        raise ApiError.bad_request("bad_request", "missing pubkey", {})
    return {
        "ok": True,
        "tx": {
            "tx_type": "ACCOUNT_REGISTER",
            "signer_hint": account_id,
            "parent": parent,
            "payload": {"pubkey": pubkey},
        },
    }


@router.get("/accounts/{account}")
def v1_account_get(account: str, request: Request):
    """Get the canonical on-chain account state.

    Mounted under /v1 by routes_public.py:
      GET /v1/accounts/{account}
    """

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    a = ledger.accounts.get(account)

    reveal_restricted = False
    if a:
        try:
            reveal_restricted = require_account_session(request, st) == account
        except PermissionError:
            reveal_restricted = False

    safe_state = redact_account_state(
        a or {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "reputation": 0},
        reveal_restricted=reveal_restricted,
    )
    return {"ok": True, "account": account, "state": safe_state}


@router.get("/accounts/{account}/registered")
def v1_account_registered(account: str, request: Request):
    """Return whether an account is "registered" for content posting.

    Node eligibility rule:
      - Account exists
      - PoH tier >= 2 / Live Verified Human
      - Not banned

    Mounted under /v1:
      GET /v1/accounts/{account}/registered
    """

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    acct = ledger.accounts.get(account)
    if not acct:
        return {"ok": True, "account": account, "registered": False}

    tier = int(acct.get("poh_tier", 0) or 0)
    banned = bool(acct.get("banned", False))

    registered = tier >= 2 and not banned

    return {"ok": True, "account": account, "registered": registered}






@router.get("/accounts/{account}/reviewer-status")
def v1_account_reviewer_status(account: str, request: Request):
    """Return backend-derived reviewer lane responsibility status.

    This route is the frontend source of truth for optional human-review
    responsibilities.  It reads the canonical roles.jurors namespace through
    runtime reviewer-responsibility helpers instead of asking clients to infer
    responsibility state from the public account record.
    """

    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    acct = ledger.accounts.get(account) if isinstance(ledger.accounts, dict) else None
    tier = int(acct.get("poh_tier", 0) or 0) if isinstance(acct, dict) else 0
    banned = bool(acct.get("banned", False)) if isinstance(acct, dict) else False
    locked = bool(acct.get("locked", False)) if isinstance(acct, dict) else False
    eligibility_blockers: list[str] = []
    if not isinstance(acct, dict):
        eligibility_blockers.append("account_not_found")
    if tier < 2:
        eligibility_blockers.append("trusted_verified_person_required")
    if banned:
        eligibility_blockers.append("account_banned")
    if locked:
        eligibility_blockers.append("account_locked")

    lanes: dict[str, Any] = {}
    active_lanes: list[str] = []
    opted_in_lanes: list[str] = []
    for lane in REVIEWER_LANES:
        rec = reviewer_lane_record(st, account, lane)
        active = reviewer_lane_active(st, account, lane)
        opted_in = bool(rec.get("opted_in", False)) if isinstance(rec, dict) else False
        if opted_in:
            opted_in_lanes.append(lane)
        if active:
            active_lanes.append(lane)
        lanes[lane] = {
            "lane": lane,
            "opted_in": opted_in,
            "active": active,
            "status": "active" if active else ("opted_in_inactive" if opted_in else "not_opted_in"),
            "details": rec if isinstance(rec, dict) else {},
        }

    return {
        "ok": True,
        "account": account,
        "reviewer": {
            "backend_source_of_truth": True,
            "policy": "exact_lane_opt_in_required",
            "account_exists": isinstance(acct, dict),
            "poh_tier": tier,
            "eligible": not eligibility_blockers,
            "eligibility_blockers": eligibility_blockers,
            "enrolled": bool(opted_in_lanes or active_lanes),
            "active": bool(active_lanes),
            "opted_in_lanes": opted_in_lanes,
            "active_lanes": active_lanes,
            "lanes": lanes,
        },
    }


@router.get("/accounts/{account}/operator-status")
def v1_account_operator_status(account: str, request: Request):
    """Return backend-derived Node Operator responsibility readiness.

    The runtime responsibility evaluator is the source of truth for baseline
    Node Operator, validator responsibility, and storage responsibility status.
    Frontends should display this result instead of inferring authority from raw
    account/role state.
    """

    st = _snapshot(request)
    node_pubkey = _str_param(request.query_params.get("node_pubkey"), "").strip()
    status = evaluate_node_operator_responsibilities(st, account, node_pubkey=node_pubkey)
    return {"ok": True, "account": account, "node_operator": status}


@router.get("/accounts/{account}/feed")
def v1_account_feed(account: str, request: Request):
    """List posts authored by `account`.

    Mounted under /v1:
      GET /v1/accounts/{account}/feed

    Query params:
      - limit (default 25, max 100)
      - cursor (pagination)
      - visibility: public|all (default public)

    Public-only protocol model:
      - all protocol-native account content returned here is public-readable;
      - non-public/restricted-read visibility filters are rejected instead of exposing
        owner-only archives.
    """

    st = _snapshot(request)
    qp = request.query_params

    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    visibility = _str_param(qp.get("visibility"), "public").strip().lower()

    if visibility in {"private", "direct", "owner", "members", "member" + "s_only", "member_only", "scoped"}:
        raise ApiError.bad_request(
            "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
            "Protocol-native account content is public-only; private read visibility is unsupported.",
            {"account": account, "visibility": visibility},
        )

    posts = _iter_posts_by_author(st, author=account)

    filtered: list[dict[str, Any]] = []
    for obj in posts:
        obj_id = _str_param(obj.get("id") or obj.get("post_id") or "").strip()
        created_at_nonce = int(obj.get("created_at_nonce", 0) or 0)

        vis = _str_param(obj.get("visibility"), "public").strip().lower() or "public"

        publicly_readable = vis in {"public", ""} or (bool(_str_param(obj.get("group_id") or "").strip()) and vis == "group")
        if visibility in {"public", "all"}:
            if not publicly_readable:
                continue
        else:
            # Unknown -> fail closed to public-readable records.
            if not publicly_readable:
                continue

        if cursor_n is not None and cursor_id is not None:
            if created_at_nonce > cursor_n:
                continue
            if created_at_nonce == cursor_n and obj_id >= cursor_id:
                continue

        filtered.append(obj)

    filtered.sort(
        key=lambda x: (int(x.get("created_at_nonce", 0) or 0), str(x.get("id") or "")), reverse=True
    )

    page = [_with_media_summaries(st, item) for item in filtered[:limit]]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=int(last.get("created_at_nonce", 0) or 0),
            content_id=str(last.get("id") or ""),
        )

    return {"ok": True, "account": account, "items": page, "next_cursor": next_cursor}
