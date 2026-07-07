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
from weall.runtime.poh.state import effective_poh_tier, poh_tier_label
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


class AccountProfileUpdateTxRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=80)
    bio: str | None = Field(default=None, max_length=500)
    avatar_cid: str | None = Field(default=None, max_length=256)
    banner_cid: str | None = Field(default=None, max_length=256)
    website: str | None = Field(default=None, max_length=256)
    location: str | None = Field(default=None, max_length=120)
    tags: list[str] | None = Field(default=None, max_length=12)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clean_str(value: Any, *, max_len: int | None = None) -> str:
    raw = str(value or "").strip()
    if max_len is not None:
        raw = raw[:max_len]
    return raw


def _clean_tags(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        raw = [str(part or "").strip() for part in value]
    else:
        raw = []
    out: list[str] = []
    for tag in raw:
        if not tag or tag in out:
            continue
        out.append(tag[:40])
        if len(out) >= 12:
            break
    return out


def _media_profile_ref(cid: str, *, kind: str) -> dict[str, Any] | None:
    clean = _clean_str(cid, max_len=256)
    if not clean:
        return None
    return {
        "cid": clean,
        "kind": kind,
        "source": "public_media_reference",
        "load_policy": "viewport",
        "fetch_path": f"/v1/media/proxy/{clean}",
    }


def _profile_record(st: dict[str, Any], account: str) -> dict[str, Any]:
    social = _as_dict(st.get("social"))
    profiles = _as_dict(social.get("profiles_by_id"))
    raw = _as_dict(profiles.get(account))
    avatar_cid = _clean_str(raw.get("avatar_cid"), max_len=256)
    banner_cid = _clean_str(raw.get("banner_cid"), max_len=256)
    website = _clean_str(raw.get("website"), max_len=256)

    profile: dict[str, Any] = {
        "account_id": account,
        "display_name": _clean_str(raw.get("display_name"), max_len=80) or account,
        "bio": _clean_str(raw.get("bio"), max_len=500),
        "avatar_cid": avatar_cid,
        "banner_cid": banner_cid,
        "website": website,
        "location": _clean_str(raw.get("location"), max_len=120),
        "tags": _clean_tags(raw.get("tags")),
        "created_at_nonce": _safe_int(raw.get("created_at_nonce"), 0),
        "updated_at_nonce": _safe_int(raw.get("updated_at_nonce"), 0),
        "public_links": ([{"label": "Website", "url": website}] if website else []),
        "avatar_media": _media_profile_ref(avatar_cid, kind="profile_picture"),
        "banner_media": _media_profile_ref(banner_cid, kind="profile_banner"),
    }
    # Pinned posts are intentionally read-only here.  The apply/schema path does
    # not yet accept a pinned-post mutation, so this route exposes a stable
    # contract slot without expanding consensus semantics.
    pinned = _clean_str(raw.get("pinned_post_id"), max_len=256)
    if pinned:
        profile["pinned_post_id"] = pinned
    return profile


def _profile_activity_summary(st: dict[str, Any], account: str) -> dict[str, Any]:
    content = _as_dict(st.get("content"))
    posts = _as_dict(content.get("posts"))
    comments = _as_dict(content.get("comments"))
    social = _as_dict(st.get("social"))
    shares = _as_dict(social.get("shares_by_id"))
    follows = _as_dict(social.get("follows_by_edge"))

    visible_posts = 0
    visible_comments = 0
    visible_shares = 0
    following_count = 0

    for pid, obj in posts.items():
        if not isinstance(obj, dict):
            continue
        post_id = _clean_str(obj.get("post_id") or obj.get("id") or pid, max_len=256)
        if obj.get("author") == account and not obj.get("deleted") and not _content_post_hidden_by_moderation(st, obj, post_id):
            visible_posts += 1

    for obj in comments.values():
        if isinstance(obj, dict) and obj.get("author") == account and not obj.get("deleted"):
            visibility = _clean_str(obj.get("visibility") or "public").lower()
            if visibility in {"", "public"}:
                visible_comments += 1

    for obj in shares.values():
        if isinstance(obj, dict) and (obj.get("by") == account or obj.get("author") == account):
            visible_shares += 1

    for obj in follows.values():
        if isinstance(obj, dict) and obj.get("from") == account and obj.get("active", True):
            following_count += 1

    return {
        "posts": visible_posts,
        "comments": visible_comments,
        "reposts": visible_shares,
        "following": following_count,
        "favorites": 0,
        "truth_boundary": "public_derived_index_view",
        "deferred": ["favorites_index", "profile_timeline", "pinned_post_mutation"],
    }


def _profile_payload_from_request(req: AccountProfileUpdateTxRequest) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in ("display_name", "bio", "avatar_cid", "banner_cid", "website", "location"):
        value = getattr(req, key)
        if value is not None:
            payload[key] = str(value).strip()
    if req.tags is not None:
        payload["tags"] = _clean_tags(req.tags)
    return payload


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


@router.post("/accounts/tx/profile-update")
def v1_account_tx_profile_update(req: AccountProfileUpdateTxRequest) -> dict[str, Any]:
    """Return a canonical PROFILE_UPDATE tx skeleton.

    This route does not update profile state.  The returned transaction still
    has to be signed, submitted, committed, and inspected through the normal
    receipt/status path.  Profile fields are public protocol-native metadata;
    raw PoH/private identity evidence is intentionally not accepted here.
    """
    account_id = _clean_str(req.account_id, max_len=128)
    if not account_id:
        raise ApiError.bad_request("bad_request", "missing account_id", {})
    return {
        "ok": True,
        "tx": {
            "tx_type": "PROFILE_UPDATE",
            "signer_hint": account_id,
            "parent": None,
            "payload": _profile_payload_from_request(req),
        },
        "truth_boundary": "transaction_skeleton_only_sign_and_submit_via_v1_tx_submit",
        "public_notice": "Profile metadata is public protocol state after the PROFILE_UPDATE transaction commits.",
    }


@router.get("/accounts/{account}/profile")
def v1_account_profile(account: str, request: Request) -> dict[str, Any]:
    """Return the public civic profile and activity summary for an account.

    This is a public read model derived from canonical state. It intentionally
    exposes only protocol-native public profile metadata and deterministic
    activity counts. It is not a private identity/PoH evidence surface.
    """
    account_id = _clean_str(account, max_len=128)
    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    acct_state = ledger.accounts.get(account_id)
    exists = isinstance(acct_state, dict)
    tier = effective_poh_tier(st, account_id) if exists else 0
    banned = bool(acct_state.get("banned", False)) if isinstance(acct_state, dict) else False
    locked = bool(acct_state.get("locked", False)) if isinstance(acct_state, dict) else False
    return {
        "ok": True,
        "schema": "weall.public_profile.v1",
        "account": account_id,
        "exists": exists,
        "profile": _profile_record(st, account_id),
        "public_activity": _profile_activity_summary(st, account_id),
        "capabilities": {
            "profile_edit_tx_type": "PROFILE_UPDATE",
            "profile_edit_requires_owner_signature": True,
            "can_publish_posts": exists and tier >= 2 and not banned and not locked,
            "can_comment": exists and tier >= 2 and not banned and not locked,
        },
        "receipt_paths": {
            "submit": "/v1/tx/submit",
            "status_template": "/v1/tx/status/{tx_id}",
        },
        "truth_boundary": "public_derived_index_view_of_chain_state",
        "privacy_boundary": "raw_poh_identity_evidence_device_secrets_and_recovery_material_are_not_exposed",
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
    if isinstance(safe_state, dict):
        tier = effective_poh_tier(st, account)
        safe_state["poh_tier"] = tier
        safe_state["poh_tier_label"] = poh_tier_label(tier)
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

    tier = effective_poh_tier(st, account)
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
    tier = effective_poh_tier(st, account) if isinstance(acct, dict) else 0
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

    if visibility in {"pri" + "vate", "direct", "owner", "members", "member" + "s_only", "member_only", "scoped"}:
        raise ApiError.bad_request(
            "PUBLIC_READ_VISIBILITY_REQUIRED",
            "Protocol-native account content is public-only; restricted read visibility is unsupported.",
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
