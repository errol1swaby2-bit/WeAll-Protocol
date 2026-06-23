# src/weall/runtime/apply/content.py
from __future__ import annotations

"""weall.runtime.apply.content

Deterministic apply semantics for the Content domain.

This module handles state transitions for:
- posts
- comments
- reactions
- flags
- media declarations / bindings
- moderation/visibility/locking (receipt-only in canon, but stateful in runtime)
- escalation to dispute (user-triggered, stateful; may enqueue system receipts)

Design note
-----------
Several moderation-related tx types are marked `receipt_only` in canon because the
network (oracles / juror outcomes / governance execution) is expected to emit
receipts as the authoritative record. Receipt-only does NOT mean "no state".
For production correctness, a receipt MUST mutate canonical state deterministically.
"""

from dataclasses import dataclass
from typing import Any

# We import the dispute opener directly to avoid duplicating dispute schema.
# (This is intentionally a light dependency; dispute.py has no content imports.)
from weall.runtime.apply.dispute import dispute_open  # type: ignore
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.reputation_accrual import (
    content_reputation_maturity_blocks,
    media_reputation_delta_milli,
    pending_content_accrual,
    post_reputation_delta_milli,
)
from weall.runtime.reviewer_responsibilities import (
    CONTENT_REVIEW_LANE,
    eligible_reviewer_ids,
)
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class ContentApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _canonical_account_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        acct = _as_str(raw).strip()
        if not acct or acct in seen:
            continue
        seen.add(acct)
        out.append(acct)
    out.sort()
    return out


def _identity_variants(value: Any) -> list[str]:
    s = _as_str(value).strip()
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = _as_str(candidate).strip()
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _resolve_account_identity(state: Json, value: Any) -> str:
    variants = _identity_variants(value)
    if not variants:
        return ""
    accounts = state.get("accounts")
    if isinstance(accounts, dict):
        for variant in variants:
            if variant in accounts:
                return variant
    return variants[0]




def _same_account(a: str, b: str) -> bool:
    aa = _as_str(a).strip()
    bb = _as_str(b).strip()
    if not aa or not bb:
        return False
    return aa == bb or aa.lstrip("@") == bb.lstrip("@")


def _filter_target_owner_from_jurors(state: Json, *, target_author: str, jurors: list[str]) -> list[str]:
    owner = _resolve_account_identity(state, target_author) if target_author else ""
    out: list[str] = []
    for juror in _canonical_account_list([_resolve_account_identity(state, item) for item in jurors]):
        if owner and _same_account(owner, juror):
            continue
        out.append(juror)
    return _canonical_account_list(out)


def _content_target_author(state: Json, target_id: str) -> str:
    content_root = _ensure_root(state)
    posts = content_root.get("posts")
    comments = content_root.get("comments")
    post_obj = posts.get(target_id) if isinstance(posts, dict) else None
    comment_obj = comments.get(target_id) if isinstance(comments, dict) else None
    target_author = ""
    if isinstance(post_obj, dict):
        target_author = _resolve_account_identity(state, post_obj.get("author") or post_obj.get("owner") or post_obj.get("account_id") or post_obj.get("created_by"))
    elif isinstance(comment_obj, dict):
        target_author = _resolve_account_identity(state, comment_obj.get("author") or comment_obj.get("owner") or comment_obj.get("account_id") or comment_obj.get("created_by"))
    return target_author


def _canonical_tags(value: Any) -> list[str]:
    if isinstance(value, str):
        raw_values = value.replace(",", " ").split()
    elif isinstance(value, list):
        raw_values = value
    else:
        raw_values = []

    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        tag = _as_str(raw).strip().lstrip("#")
        if not tag or tag in seen:
            continue
        seen.add(tag)
        out.append(tag)
    return out


def _groups_by_id(state: Json) -> Json:
    roles = state.get("roles")
    if isinstance(roles, dict):
        gbid = roles.get("groups_by_id")
        if isinstance(gbid, dict):
            return gbid
    gbid2 = state.get("groups_by_id")
    return gbid2 if isinstance(gbid2, dict) else {}


def _group_record(state: Json, group_id: str) -> Json | None:
    gid = _as_str(group_id).strip()
    if not gid:
        return None
    g = _groups_by_id(state).get(gid)
    return g if isinstance(g, dict) else None


def _group_members(group: Json) -> Json:
    members = group.get("members")
    return members if isinstance(members, dict) else {}


def _group_role_accounts(group: Json, role_name: str) -> set[str]:
    roles = group.get("roles")
    if not isinstance(roles, dict):
        return set()
    raw = roles.get(role_name)
    if isinstance(raw, list):
        return {_as_str(x).strip() for x in raw if _as_str(x).strip()}
    if isinstance(raw, dict):
        return {_as_str(k).strip() for k in raw.keys() if _as_str(k).strip()}
    return set()


def _group_signers(group: Json) -> set[str]:
    raw = group.get("signers")
    if isinstance(raw, list):
        return {_as_str(x).strip() for x in raw if _as_str(x).strip()}
    return set()


def _group_post_authorized_accounts(group: Json) -> set[str]:
    out: set[str] = set()
    out.update(_group_members(group).keys())
    out.update(_group_signers(group))
    for role in (
        "poster",
        "posters",
        "publisher",
        "publishers",
        "moderator",
        "moderators",
        "admin",
        "admins",
        "creator",
        "creators",
        "emissary",
        "emissaries",
    ):
        out.update(_group_role_accounts(group, role))
    return {_as_str(x).strip() for x in out if _as_str(x).strip()}


def _group_tag_targets(tags: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for tag in _canonical_tags(tags):
        if not tag.startswith("group:"):
            continue
        gid = tag.split(":", 1)[1].strip()
        if gid and gid not in seen:
            seen.add(gid)
            out.append(gid)
    return out


def _require_group_post_authority(state: Json, *, signer: str, payload: Json, existing_post: Json | None = None) -> tuple[str, list[str]]:
    """Enforce protocol authority for group-scoped content.

    The frontend may guide users into group posting, but the protocol apply path
    must be the authority.  A post may not enter a group feed by direct group_id
    or by `group:<id>` tag unless the signer is a recognized member/posting
    authority for that group.
    """

    signer_id = _as_str(signer).strip()
    visibility = _as_str(payload.get("visibility", (existing_post or {}).get("visibility", "public"))).strip().lower() or "public"
    group_id = _as_str(payload.get("group_id", (existing_post or {}).get("group_id", ""))).strip()
    tags = payload.get("tags", (existing_post or {}).get("tags", []))
    tag_targets = _group_tag_targets(tags)

    if visibility in {"private", "members", "members_only", "member_only", "scoped"}:
        raise ContentApplyError(
            "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
            "protocol_content_read_visibility_must_be_public",
            {"visibility": visibility},
        )

    if visibility == "group" and not group_id:
        raise ContentApplyError("invalid_payload", "missing_group_id_for_group_visibility", {"visibility": visibility})

    if group_id and visibility not in {"group", "public"}:
        raise ContentApplyError(
            "invalid_payload",
            "group_id_requires_public_or_group_visibility",
            {"group_id": group_id, "visibility": visibility},
        )

    target_ids: list[str] = []
    if group_id:
        target_ids.append(group_id)
    for gid in tag_targets:
        if gid not in target_ids:
            target_ids.append(gid)

    if not target_ids:
        return "", []

    if group_id and any(gid != group_id for gid in tag_targets):
        raise ContentApplyError(
            "invalid_payload",
            "group_tag_target_mismatch",
            {"group_id": group_id, "tag_targets": tag_targets},
        )

    for gid in target_ids:
        group = _group_record(state, gid)
        if not isinstance(group, dict):
            raise ContentApplyError("not_found", "group_not_found", {"group_id": gid})

        authorized = _group_post_authorized_accounts(group)
        if signer_id not in authorized:
            raise ContentApplyError(
                "forbidden",
                "group_post_authority_required",
                {"group_id": gid, "signer": signer_id},
            )

    return group_id, tag_targets


def _group_permissions(group: Json) -> Json:
    perms = group.get("permissions")
    return perms if isinstance(perms, dict) else {}


def _group_comment_authorized_accounts(group: Json) -> set[str]:
    out: set[str] = set()
    out.update(_group_members(group).keys())
    out.update(_group_signers(group))
    moderators = group.get("moderators")
    if isinstance(moderators, list):
        out.update(_as_str(x).strip() for x in moderators if _as_str(x).strip())
    for role in ("moderator", "moderators", "admin", "admins", "emissary", "emissaries"):
        out.update(_group_role_accounts(group, role))
    return {_as_str(x).strip() for x in out if _as_str(x).strip()}


def _require_group_comment_authority(state: Json, *, signer: str, post: Json) -> None:
    group_id = _as_str(post.get("group_id") or "").strip()
    if not group_id:
        return
    group = _group_record(state, group_id)
    if not isinstance(group, dict):
        raise ContentApplyError("not_found", "group_not_found", {"group_id": group_id})

    policy = _as_str(_group_permissions(group).get("comment") or "members").strip().lower() or "members"
    if policy in {"public", "anyone", "all", "open"}:
        return

    signer_id = _as_str(signer).strip()
    allowed = _group_comment_authorized_accounts(group)
    if signer_id not in allowed:
        raise ContentApplyError(
            "forbidden",
            "group_comment_authority_required",
            {"group_id": group_id, "signer": signer_id, "comment_permission": policy},
        )


def _active_role_accounts(state: Json, role_name: str, active_statuses: set[str]) -> list[str]:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return []
    role_root = roles.get(role_name)
    if not isinstance(role_root, dict):
        return []

    active = _canonical_account_list(
        [_resolve_account_identity(state, item) for item in _canonical_account_list(role_root.get("active_set"))]
    )
    if active:
        return active

    by_id = role_root.get("by_id")
    if isinstance(by_id, dict):
        out: list[str] = []
        for account, rec in by_id.items():
            acct = _as_str(account).strip()
            if not acct or not isinstance(rec, dict):
                continue
            enrolled = rec.get("enrolled")
            if enrolled is not None and not bool(enrolled):
                continue
            if rec.get("active") is not None and not bool(rec.get("active")):
                continue
            status = _as_str(rec.get("status")).strip().lower()
            if status and status not in active_statuses:
                continue
            out.append(_resolve_account_identity(state, acct))
        out = _canonical_account_list(out)
        if out:
            return out

    return []


def _active_juror_accounts(state: Json) -> list[str]:
    return _active_role_accounts(
        state,
        "jurors",
        {"active", "activated", "juror", "enrolled"},
    )


def _active_validator_accounts(state: Json) -> list[str]:
    active_from_roles = _active_role_accounts(
        state,
        "validators",
        {"active", "activated", "validator"},
    )
    if active_from_roles:
        return active_from_roles

    consensus = state.get("consensus")
    if isinstance(consensus, dict):
        validator_set = consensus.get("validator_set")
        if isinstance(validator_set, dict):
            active = _canonical_account_list([_resolve_account_identity(state, item) for item in _canonical_account_list(validator_set.get("active_set"))])
            if active:
                return active
        validators = consensus.get("validators")
        if isinstance(validators, dict):
            registry = validators.get("registry")
            if isinstance(registry, dict):
                out: list[str] = []
                for account, rec in registry.items():
                    acct = _as_str(account).strip()
                    if not acct or not isinstance(rec, dict):
                        continue
                    status = _as_str(rec.get("status")).strip().lower()
                    if status and status not in {"active", "activated", "validator"}:
                        continue
                    out.append(_resolve_account_identity(state, acct))
                return _canonical_account_list(out)
    return []


def _bootstrap_reviewer_accounts(state: Json) -> list[str]:
    """Return deterministic bootstrap reviewer fallback accounts.

    Controlled genesis/local-devnet report escalation can be emitted by SYSTEM
    before a first external reviewer pool exists.  In that narrow bootstrap
    posture, use the audited genesis bootstrap account as the reviewer fallback
    instead of leaving the review unassigned.  Normal role/validator assignment
    above remains preferred.
    """

    params = state.get("params")
    if not isinstance(params, dict):
        return []
    candidates = [
        params.get("bootstrap_founder_account"),
        params.get("bootstrap_operator"),
        params.get("genesis_bootstrap_account"),
    ]
    allowlist = params.get("bootstrap_allowlist")
    if isinstance(allowlist, dict):
        candidates.extend(list(allowlist.keys()))
    return _canonical_account_list([_resolve_account_identity(state, item) for item in candidates])

def _require_system(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise ContentApplyError("forbidden", "system_only", {"tx_type": str(env.tx_type or "")})


def _ensure_root(state: Json) -> Json:
    content = state.get("content")
    if not isinstance(content, dict):
        content = {}
        state["content"] = content

    content.setdefault("posts", {})
    content.setdefault("comments", {})
    content.setdefault("reactions", {})
    content.setdefault("flags", {})

    # Media + moderation surfaces
    content.setdefault("media", {})
    content.setdefault("media_bindings", {})

    content.setdefault("moderation", {})
    mod = content["moderation"]
    if isinstance(mod, dict):
        mod.setdefault("receipts", [])
        mod.setdefault(
            "targets", {}
        )  # target_id -> {visibility, locked, labels, dispute_id, last_action}

    return content


def _ensure_account_nonce(state: Json, signer: str, nonce: int) -> None:
    accounts = state.setdefault("accounts", {})
    acct = accounts.setdefault(
        signer,
        {
            "nonce": 0,
            "poh_tier": 0,
            "balance": 0,
            "locked": False,
            "banned": False,
            "reputation": "0",
            "keys": [],
        },
    )
    acct["nonce"] = int(nonce)


def _require_min_poh_tier(state: Json, *, signer: str, min_tier: int, action: str) -> None:
    """Canonical PoH tier gate enforced at apply-time.

    Even if an upstream API layer forgets to gate a tx, the chain state must
    remain consistent.
    """

    accounts = state.get("accounts")
    acct = accounts.get(signer) if isinstance(accounts, dict) else None
    if not isinstance(acct, dict):
        raise ContentApplyError(
            "forbidden", "account_not_registered", {"account": signer, "action": action}
        )

    if bool(acct.get("banned", False)):
        raise ContentApplyError(
            "forbidden", "account_banned", {"account": signer, "action": action}
        )
    if bool(acct.get("locked", False)):
        raise ContentApplyError(
            "forbidden", "account_locked", {"account": signer, "action": action}
        )

    tier = int(acct.get("poh_tier", 0) or 0)
    if tier < int(min_tier):
        raise ContentApplyError(
            "forbidden",
            "insufficient_poh_tier",
            {"account": signer, "poh_tier": tier, "required": int(min_tier), "action": action},
        )


def _mod_targets(state: Json) -> Json:
    content = _ensure_root(state)
    mod = content.get("moderation")
    if not isinstance(mod, dict):
        mod = {}
        content["moderation"] = mod
    targets = mod.get("targets")
    if not isinstance(targets, dict):
        targets = {}
        mod["targets"] = targets
    return targets


def _touch_receipt(state: Json, env: TxEnvelope) -> None:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    mod = content.get("moderation")
    if not isinstance(mod, dict):
        mod = {}
        content["moderation"] = mod
    receipts = mod.get("receipts")
    if not isinstance(receipts, list):
        receipts = []
    receipts.append(
        {
            "tx_type": str(env.tx_type or ""),
            "nonce": int(env.nonce),
            "signer": env.signer,
            "payload": payload,
        }
    )
    mod["receipts"] = receipts


def _apply_mod_to_target(state: Json, *, target_id: str, changes: Json) -> None:
    target_id = _as_str(target_id).strip()
    if not target_id:
        return

    targets = _mod_targets(state)
    rec = targets.get(target_id)
    if not isinstance(rec, dict):
        rec = {"target_id": target_id, "labels": []}

    # Normalize labels if provided
    if "labels" in changes:
        labels = changes.get("labels")
        if isinstance(labels, list):
            rec["labels"] = [str(x) for x in labels if str(x).strip()]

    for k, v in changes.items():
        if k == "labels":
            continue
        rec[k] = v

    targets[target_id] = rec

    # Mirror into post/comment if target_id matches
    content = _ensure_root(state)
    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        if "visibility" in rec:
            post["visibility"] = rec.get("visibility")
        if "locked" in rec:
            post["locked"] = bool(rec.get("locked"))
        if "labels" in rec:
            post["labels"] = list(rec.get("labels") or [])
        if "deleted" in rec:
            post["deleted"] = bool(rec.get("deleted"))

    comments = content.get("comments")
    if (
        isinstance(comments, dict)
        and target_id in comments
        and isinstance(comments[target_id], dict)
    ):
        c = comments[target_id]
        if "visibility" in rec:
            c["visibility"] = rec.get("visibility")
        if "labels" in rec:
            c["labels"] = list(rec.get("labels") or [])
        if "deleted" in rec:
            c["deleted"] = bool(rec.get("deleted"))


# ---------------------------
# Posts
# ---------------------------


def _apply_post_create(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_post_create")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    posts = content["posts"]

    post_id = _as_str(payload.get("post_id")).strip() or f"post:{env.signer}:{env.nonce}"
    if post_id in posts:
        return {"applied": "CONTENT_POST_CREATE", "post_id": post_id, "deduped": True}

    group_id, _group_tag_targets_for_receipt = _require_group_post_authority(
        state, signer=env.signer, payload=payload
    )

    created_height = _as_int(state.get("height"), 0)
    maturity_blocks = content_reputation_maturity_blocks(state)
    posts[post_id] = {
        "post_id": post_id,
        "author": env.signer,
        "body": payload.get("body"),
        # media may contain media_ids or app-specific attachment refs
        "media": _as_list(payload.get("media")),
        "created_nonce": int(env.nonce),
        "visibility": "public" if group_id else (_as_str(payload.get("visibility", "public")).strip().lower() or "public"),
        "locked": False,
        # Feed indexing helpers
        "tags": _canonical_tags(payload.get("tags", [])),
        "group_id": group_id or None,
        "labels": [],
        "flags": [],
        "deleted": False,
        "reputation_accrual": pending_content_accrual(
            kind="post",
            source_id=post_id,
            account_id=env.signer,
            created_height=created_height,
            delta_milli=post_reputation_delta_milli(state),
            maturity_blocks=maturity_blocks,
        ),
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_POST_CREATE", "post_id": post_id}


def _apply_post_edit(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_post_edit")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    posts = content["posts"]

    post_id = _as_str(payload.get("post_id")).strip()
    if not post_id or post_id not in posts:
        raise ContentApplyError("not_found", "post_not_found", {"post_id": post_id})

    post = posts[post_id]
    if post.get("author") != env.signer:
        raise ContentApplyError("forbidden", "not_author", {"post_id": post_id})

    candidate: Json = dict(post)
    if "visibility" in payload:
        candidate["visibility"] = _as_str(payload.get("visibility")).strip().lower() or "public"
    if "tags" in payload:
        candidate["tags"] = _canonical_tags(payload.get("tags"))
    if "group_id" in payload:
        candidate["group_id"] = _as_str(payload.get("group_id")).strip() or None

    group_id, _group_tag_targets_for_receipt = _require_group_post_authority(
        state, signer=env.signer, payload=candidate, existing_post=post
    )

    post["body"] = payload.get("body", post.get("body"))
    post["media"] = _as_list(payload.get("media", post.get("media")))

    # Only mutate if explicitly provided
    if "visibility" in payload:
        post["visibility"] = "public" if group_id else candidate["visibility"]
    if "tags" in payload:
        post["tags"] = candidate["tags"]
    if "group_id" in payload:
        post["group_id"] = group_id or None

    post["edited_nonce"] = int(env.nonce)

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_POST_EDIT", "post_id": post_id}


def _apply_post_delete(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_post_delete")

    payload = _as_dict(env.payload)
    posts = _ensure_root(state)["posts"]

    post_id = _as_str(payload.get("post_id")).strip()
    if not post_id or post_id not in posts:
        raise ContentApplyError("not_found", "post_not_found", {"post_id": post_id})

    post = posts[post_id]
    if post.get("author") != env.signer and not env.system:
        raise ContentApplyError("forbidden", "not_author_or_system", {"post_id": post_id})

    post["deleted"] = True
    post["deleted_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_POST_DELETE", "post_id": post_id}


# ---------------------------
# Comments
# ---------------------------


def _apply_comment_create(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_tier2_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    comments = content["comments"]

    comment_id = _as_str(payload.get("comment_id")).strip() or f"comment:{env.signer}:{env.nonce}"
    if comment_id in comments:
        return {"applied": "CONTENT_COMMENT_CREATE", "comment_id": comment_id, "deduped": True}

    parent_post = _as_str(payload.get("post_id")).strip()
    if not parent_post:
        raise ContentApplyError("invalid_payload", "missing_post_id", {})

    posts = content.get("posts")
    if (
        not isinstance(posts, dict)
        or parent_post not in posts
        or not isinstance(posts[parent_post], dict)
    ):
        raise ContentApplyError("not_found", "post_not_found", {"post_id": parent_post})

    p = posts[parent_post]
    if bool(p.get("deleted")):
        raise ContentApplyError("forbidden", "post_deleted", {"post_id": parent_post})

    # Thread lock enforcement: locked posts reject new comments except SYSTEM.
    if bool(p.get("locked")) and not env.system:
        raise ContentApplyError("forbidden", "thread_locked", {"post_id": parent_post})

    if not env.system:
        _require_group_comment_authority(state, signer=env.signer, post=p)

    comments[comment_id] = {
        "comment_id": comment_id,
        "post_id": parent_post,
        "author": env.signer,
        "body": payload.get("body"),
        "created_nonce": int(env.nonce),
        "visibility": "public",
        "labels": [],
        "deleted": False,
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_COMMENT_CREATE", "comment_id": comment_id}


def _apply_comment_delete(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_tier2_action")

    payload = _as_dict(env.payload)
    comments = _ensure_root(state)["comments"]

    comment_id = _as_str(payload.get("comment_id")).strip()
    if not comment_id or comment_id not in comments:
        raise ContentApplyError("not_found", "comment_not_found", {"comment_id": comment_id})

    comment = comments[comment_id]
    if comment.get("author") != env.signer and not env.system:
        raise ContentApplyError("forbidden", "not_author_or_system", {"comment_id": comment_id})

    comment["deleted"] = True
    comment["deleted_nonce"] = int(env.nonce)
    return {"applied": "CONTENT_COMMENT_DELETE", "comment_id": comment_id}


# ---------------------------
# Reactions / flags
# ---------------------------


def _apply_reaction_set(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_tier2_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    reactions = content["reactions"]

    target_id = _as_str(payload.get("target_id")).strip()
    reaction = _as_str(payload.get("reaction")).strip()
    if not target_id or not reaction:
        raise ContentApplyError("invalid_payload", "missing_target_or_reaction", {})

    key = f"{env.signer}:{target_id}"
    reactions[key] = {
        "by": env.signer,
        "target_id": target_id,
        "reaction": reaction,
        "nonce": int(env.nonce),
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_REACTION_SET", "target_id": target_id, "reaction": reaction}


def _apply_content_flag(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_tier2_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    flags = content["flags"]

    target_id = _as_str(payload.get("target_id")).strip()
    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {})

    flag_id = _as_str(payload.get("flag_id")).strip() or f"flag:{env.signer}:{env.nonce}"
    reason = _as_str(payload.get("reason"))
    flags[flag_id] = {
        "flag_id": flag_id,
        "target_id": target_id,
        "by": env.signer,
        "reason": reason,
        "nonce": int(env.nonce),
    }

    _ensure_account_nonce(state, env.signer, env.nonce)

    # Demo-safe deterministic posture: a content flag is not just a dead moderation marker.
    # When the target has not already been escalated, enqueue the canonical escalation tx for
    # the next block so the disputes surface becomes authoritative without client-side synthesis.
    try:
        targets = _mod_targets(state)
        existing = targets.get(target_id)
        existing_dispute_id = _as_str(existing.get("dispute_id") if isinstance(existing, dict) else "").strip()
        if not existing_dispute_id:
            height = _as_int(state.get("height") or 0)
            enqueue_system_tx(
                state,
                tx_type="CONTENT_ESCALATE_TO_DISPUTE",
                payload={
                    "target_type": "content",
                    "target_id": target_id,
                    "reason": reason,
                    "flag_id": flag_id,
                    "flagged_by": env.signer,
                },
                due_height=height + 1,
                signer="SYSTEM",
                once=True,
                parent=f"CONTENT_FLAG:{flag_id}",
                phase="post",
            )
    except Exception:
        # The flag itself remains authoritative even if audit receipt scheduling fails.
        pass

    return {"applied": "CONTENT_FLAG", "flag_id": flag_id}


# ---------------------------
# Media (canon-claimed)
# ---------------------------


def _apply_content_media_declare(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_media_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    media = content["media"]

    media_id = (
        _as_str(payload.get("media_id") or payload.get("id")).strip()
        or f"media:{env.signer}:{env.nonce}"
    )
    # Back-compat with older/web clients that used `upload_ref`.
    # In the current design `upload_ref` is simply the CID returned by /v1/media/upload.
    cid = _as_str(
        payload.get("cid")
        or payload.get("ipfs_cid")
        or payload.get("content_cid")
        or payload.get("upload_ref")
        or payload.get("ref")
    ).strip()
    if not cid:
        raise ContentApplyError("invalid_payload", "missing_cid", {"tx_type": env.tx_type})

    if media_id in media:
        return {"applied": "CONTENT_MEDIA_DECLARE", "media_id": media_id, "deduped": True}

    created_height = _as_int(state.get("height"), 0)
    maturity_blocks = content_reputation_maturity_blocks(state)
    media[media_id] = {
        "media_id": media_id,
        "cid": cid,
        "kind": _as_str(payload.get("kind")).strip(),
        "declared_by": env.signer,
        "declared_at_nonce": int(env.nonce),
        "payload": payload,
        "reputation_accrual": pending_content_accrual(
            kind="media",
            source_id=media_id,
            account_id=env.signer,
            created_height=created_height,
            delta_milli=media_reputation_delta_milli(state),
            maturity_blocks=maturity_blocks,
        ),
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_DECLARE", "media_id": media_id, "deduped": False}


def _apply_content_media_bind(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_media_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    media = content["media"]
    bindings = content["media_bindings"]

    media_id = _as_str(payload.get("media_id")).strip()
    target_id = _as_str(payload.get("target_id")).strip()
    if not media_id or not target_id:
        raise ContentApplyError(
            "invalid_payload", "missing_media_or_target", {"tx_type": env.tx_type}
        )

    if media_id not in media:
        raise ContentApplyError("not_found", "media_not_found", {"media_id": media_id})

    bind_id = _as_str(payload.get("binding_id")).strip() or f"bind:{media_id}:{target_id}"
    bindings[bind_id] = {
        "binding_id": bind_id,
        "media_id": media_id,
        "target_id": target_id,
        "bound_by": env.signer,
        "bound_at_nonce": int(env.nonce),
    }

    # Mirror onto post/comment for convenience (optional)
    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        cur = post.get("media")
        if not isinstance(cur, list):
            cur = []
        if media_id not in cur:
            cur.append(media_id)
        post["media"] = cur

    comments = content.get("comments")
    if (
        isinstance(comments, dict)
        and target_id in comments
        and isinstance(comments[target_id], dict)
    ):
        c = comments[target_id]
        cur = c.get("media")
        if not isinstance(cur, list):
            cur = []
        if media_id not in cur:
            cur.append(media_id)
        c["media"] = cur

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_BIND", "binding_id": bind_id}


def _apply_content_media_unbind(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_media_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    bindings = content["media_bindings"]

    binding_id = _as_str(payload.get("binding_id")).strip()
    if not binding_id:
        # allow specifying media_id + target_id
        media_id = _as_str(payload.get("media_id")).strip()
        target_id = _as_str(payload.get("target_id")).strip()
        if media_id and target_id:
            binding_id = f"bind:{media_id}:{target_id}"

    if not binding_id or binding_id not in bindings:
        raise ContentApplyError("not_found", "binding_not_found", {"binding_id": binding_id})

    rec = bindings[binding_id]
    media_id = _as_str(rec.get("media_id")).strip()
    target_id = _as_str(rec.get("target_id")).strip()

    del bindings[binding_id]

    # Mirror removal
    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        cur = post.get("media")
        if isinstance(cur, list) and media_id:
            post["media"] = [x for x in cur if x != media_id]

    comments = content.get("comments")
    if (
        isinstance(comments, dict)
        and target_id in comments
        and isinstance(comments[target_id], dict)
    ):
        c = comments[target_id]
        cur = c.get("media")
        if isinstance(cur, list) and media_id:
            c["media"] = [x for x in cur if x != media_id]

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_UNBIND", "binding_id": binding_id}


def _apply_content_media_replace(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_media_action")

    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    media = content["media"]

    media_id = _as_str(payload.get("media_id")).strip()
    new_cid = _as_str(payload.get("new_cid") or payload.get("cid")).strip()
    if not media_id or not new_cid:
        raise ContentApplyError("invalid_payload", "missing_media_id_or_new_cid", {})

    if media_id not in media:
        raise ContentApplyError("not_found", "media_not_found", {"media_id": media_id})

    rec = media[media_id]
    rec["cid"] = new_cid
    rec["replaced_at_nonce"] = int(env.nonce)
    rec["replaced_by"] = env.signer
    rec["replace_payload"] = payload

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_REPLACE", "media_id": media_id, "cid": new_cid}


# ---------------------------
# Moderation / visibility / labels / locking
# ---------------------------


def _apply_content_label_set(state: Json, env: TxEnvelope) -> Json:
    # Typically SYSTEM/governance, but allow user in MVP for testing.
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("target_id") or payload.get("id")).strip()
    labels = payload.get("labels") or []
    if not target_id or not isinstance(labels, list):
        raise ContentApplyError(
            "invalid_payload", "missing_target_or_labels", {"tx_type": env.tx_type}
        )

    # Record the receipt for auditability.
    _touch_receipt(state, env)
    _apply_mod_to_target(
        state,
        target_id=target_id,
        changes={"labels": labels, "labels_set_at_nonce": int(env.nonce)},
    )
    return {"applied": "CONTENT_LABEL_SET", "target_id": target_id, "labels": labels}


def _apply_content_visibility_set(state: Json, env: TxEnvelope) -> Json:
    if not env.system:
        _require_min_poh_tier(state, signer=env.signer, min_tier=2, action="content_tier2_action")

    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("target_id") or payload.get("id")).strip()
    visibility = _as_str(payload.get("visibility") or "").strip().lower()
    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})
    if visibility not in {"public", "hidden", "unlisted", "deleted"}:
        # Keep it strict; UIs can map their own states into these.
        raise ContentApplyError("invalid_payload", "bad_visibility", {"visibility": visibility})

    _touch_receipt(state, env)
    changes: Json = {"visibility": visibility, "visibility_set_at_nonce": int(env.nonce)}
    if visibility == "deleted":
        changes["deleted"] = True
    _apply_mod_to_target(state, target_id=target_id, changes=changes)
    return {"applied": "CONTENT_VISIBILITY_SET", "target_id": target_id, "visibility": visibility}


def _apply_content_thread_lock_set(state: Json, env: TxEnvelope) -> Json:
    """Lock/unlock a post thread.

    Security / product policy:
      - SYSTEM may always lock/unlock (receipt-only governance/moderation).
      - Non-system users must be PoH Tier 2 / Live Verified Human and must be the post author.
      - Locked threads reject new comments (enforced in _apply_comment_create).

    Payload:
      - target_id | post_id | id: str
      - locked: bool
    """
    payload = _as_dict(env.payload)
    target_id = _as_str(
        payload.get("target_id") or payload.get("post_id") or payload.get("id")
    ).strip()
    locked = bool(payload.get("locked"))

    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})

    # Enforce author-only + Tier2 / Live Verified Human for user-initiated locks.
    if not env.system:
        _require_min_poh_tier(
            state, signer=env.signer, min_tier=2, action="content_thread_lock_set"
        )

        content = _ensure_root(state)
        posts = content.get("posts")
        post = posts.get(target_id) if isinstance(posts, dict) else None
        if not isinstance(post, dict):
            raise ContentApplyError("not_found", "post_not_found", {"post_id": target_id})

        if bool(post.get("deleted")):
            raise ContentApplyError("forbidden", "post_deleted", {"post_id": target_id})

        if _as_str(post.get("author")).strip() != env.signer:
            raise ContentApplyError(
                "forbidden", "not_author", {"post_id": target_id, "account": env.signer}
            )

    _touch_receipt(state, env)
    _apply_mod_to_target(
        state,
        target_id=target_id,
        changes={"locked": locked, "lock_set_at_nonce": int(env.nonce), "lock_set_by": env.signer},
    )
    return {"applied": "CONTENT_THREAD_LOCK_SET", "target_id": target_id, "locked": locked}


def _apply_content_escalate_to_dispute(state: Json, env: TxEnvelope) -> Json:
    """Escalate a content target to the dispute system.

    Payload:
      - target_type: str (e.g. "post"|"comment"|"account"|"group")
      - target_id: str
      - reason: str (optional)
      - dispute_id: str (optional)

    Behavior:
      1) Opens a dispute in disputes_by_id
      2) Annotates the moderation target with dispute_id
      3) Enqueues a FLAG_ESCALATION_RECEIPT (receipt-only) for auditability

    Notes:
      - If canon treats this as receipt-only in a given phase, this still behaves deterministically.
      - This is safe to call multiple times; it will dedupe on existing dispute_id mapping.
    """
    payload = _as_dict(env.payload)
    target_type = (
        _as_str(payload.get("target_type") or payload.get("kind") or "content").strip().lower()
        or "content"
    )
    target_id = _as_str(payload.get("target_id") or payload.get("id")).strip()
    reason = _as_str(payload.get("reason") or "").strip()
    dispute_id = _as_str(payload.get("dispute_id") or "").strip()

    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})

    # Dedup: if target already has a dispute_id, do not open another.
    targets = _mod_targets(state)
    existing = targets.get(target_id)
    if isinstance(existing, dict) and _as_str(existing.get("dispute_id") or "").strip():
        did = _as_str(existing.get("dispute_id") or "").strip()
        _touch_receipt(state, env)
        return {
            "applied": "CONTENT_ESCALATE_TO_DISPUTE",
            "target_id": target_id,
            "dispute_id": did,
            "deduped": True,
        }

    # Open dispute (uses same TxEnvelope shape)
    d_env = TxEnvelope(
        tx_type="DISPUTE_OPEN",
        signer=env.signer,
        nonce=int(env.nonce),
        payload={
            "dispute_id": (dispute_id or None),
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "flagged_by": payload.get("flagged_by") or payload.get("reported_by"),
            "reported_by": payload.get("flagged_by") or payload.get("reported_by"),
        },
        system=bool(env.system),
        parent=(str(getattr(env, "parent", "") or "") or None),
    )

    meta = dispute_open(state, d_env)
    did = _as_str(meta.get("dispute_id") or "").strip()

    _touch_receipt(state, env)
    _apply_mod_to_target(
        state,
        target_id=target_id,
        changes={"dispute_id": did, "escalated_at_nonce": int(env.nonce)},
    )

    disputes_root = _as_dict(state.get("disputes_by_id"))
    dispute_obj = _as_dict(disputes_root.get(did))
    target_author = _content_target_author(state, target_id)

    def clean_jurors(values: list[str]) -> list[str]:
        return _filter_target_owner_from_jurors(state, target_author=target_author, jurors=values)

    # Content report review is an explicit trusted responsibility. Tier2 status
    # makes an account eligible to opt in, but content escalation must not
    # silently assign validators, bootstrap operators, generic jurors without
    # exact lane consent, or the reporter as a reviewer. This keeps review duty
    # auditable and prevents accidental reputation liability for users who never
    # accepted the specific content-review responsibility.
    assigned_jurors = clean_jurors(eligible_reviewer_ids(state, CONTENT_REVIEW_LANE))
    if target_author:
        dispute_obj["target_owner"] = target_author
    dispute_obj["reviewer_responsibility_policy"] = "explicit_active_juror_opt_in_required"
    if not assigned_jurors:
        dispute_obj["stage"] = "unassigned"
        dispute_obj["assignment_blocked_reason"] = "no_unconflicted_content_reviewer"
        dispute_obj["jurors"] = _as_dict(dispute_obj.get("jurors"))
        dispute_obj["eligible_juror_ids"] = []
        dispute_obj["assigned_jurors"] = []
        dispute_obj["eligible_validator_count"] = 0
        dispute_obj["required_votes"] = 0

    if not assigned_jurors:
        disputes_root[did] = dispute_obj
        state["disputes_by_id"] = disputes_root

    current_height = _as_int(payload.get("_due_height"), _as_int(state.get("height") or 0))
    followup_height = int(current_height) + 1

    if assigned_jurors:
        jurors = _as_dict(dispute_obj.get("jurors"))
        for juror in assigned_jurors:
            existing = _as_dict(jurors.get(juror))
            jurors[juror] = {
                "status": _as_str(existing.get("status") or "assigned") or "assigned",
                "assigned_at_nonce": _as_int(existing.get("assigned_at_nonce"), int(env.nonce)),
            }
            if isinstance(existing.get("attendance"), dict):
                jurors[juror]["attendance"] = dict(_as_dict(existing.get("attendance")))
        dispute_obj["jurors"] = jurors
        dispute_obj["stage"] = "juror_review"
        dispute_obj["stage_set_at_nonce"] = int(env.nonce)
        dispute_obj["eligible_validator_count"] = len(assigned_jurors)
        dispute_obj["required_votes"] = quorum_threshold(len(assigned_jurors)) if assigned_jurors else 0
        dispute_obj["eligible_juror_ids"] = list(assigned_jurors)
        dispute_obj["assigned_jurors"] = list(assigned_jurors)
        disputes_root[did] = dispute_obj
        state["disputes_by_id"] = disputes_root

        # Preserve the older queued-system-tx surface while also keeping the
        # immediate assignment state used by the demo/read-model. The queued
        # DISPUTE_JUROR_ASSIGN is idempotent for already-assigned jurors and
        # gives block-level observers a canonical assignment tx to inspect.
        #
        # The CONTENT_ESCALATE_TO_DISPUTE envelope may be applied in tests
        # without mutating state["height"]. Use the emitter's _due_height when
        # present so follow-up txs land in the next block after escalation, not
        # the stale local state height.
        try:
            for juror in assigned_jurors:
                enqueue_system_tx(
                    state,
                    tx_type="DISPUTE_JUROR_ASSIGN",
                    payload={"dispute_id": did, "juror": juror},
                    due_height=followup_height,
                    signer="SYSTEM",
                    once=True,
                    parent="CONTENT_ESCALATE_TO_DISPUTE",
                    phase="post",
                )
        except Exception:
            pass

    # Enqueue a receipt-only audit record (system-emitted) for downstream tooling.
    try:
        enqueue_system_tx(
            state,
            tx_type="FLAG_ESCALATION_RECEIPT",
            payload={"target_id": target_id, "dispute_id": did, "reason": reason, "by": env.signer},
            due_height=followup_height,
            signer="SYSTEM",
            once=True,
            parent="CONTENT_ESCALATE_TO_DISPUTE",
            phase="post",
        )
    except Exception:
        # fail-soft here; the escalation itself is the authoritative state transition.
        pass

    return {
        "applied": "CONTENT_ESCALATE_TO_DISPUTE",
        "target_id": target_id,
        "dispute_id": did,
        "deduped": False,
    }


def _apply_flag_escalation_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system(env)
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("target_id") or "").strip()
    dispute_id = _as_str(payload.get("dispute_id") or "").strip()

    _touch_receipt(state, env)
    if target_id and dispute_id:
        _apply_mod_to_target(
            state,
            target_id=target_id,
            changes={"dispute_id": dispute_id, "flag_escalation_receipt_at_nonce": int(env.nonce)},
        )

    return {
        "applied": "FLAG_ESCALATION_RECEIPT",
        "receipt": True,
        "target_id": target_id,
        "dispute_id": dispute_id,
    }


def _apply_mod_action_receipt(state: Json, env: TxEnvelope) -> Json:
    """Apply a moderation action receipt.

    Expected payload fields (flexible):
      - target_id: str
      - action: str (hide|unhide|delete|lock|unlock|label)
      - visibility: optional explicit visibility
      - locked: optional explicit lock
      - labels: optional list

    We keep this permissive but deterministic.
    """
    _require_system(env)
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("target_id") or payload.get("id") or "").strip()
    action = _as_str(payload.get("action") or "").strip().lower()

    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})

    changes: Json = {"last_action": action, "last_action_at_nonce": int(env.nonce)}

    # Explicit fields win.
    if "visibility" in payload:
        vis = _as_str(payload.get("visibility") or "").strip().lower()
        if vis:
            changes["visibility"] = vis
    if "locked" in payload:
        changes["locked"] = bool(payload.get("locked"))
    if "labels" in payload and isinstance(payload.get("labels"), list):
        changes["labels"] = [str(x) for x in payload.get("labels") if str(x).strip()]

    # Action shortcuts.
    if action == "hide":
        changes["visibility"] = "hidden"
    elif action == "unhide":
        changes["visibility"] = "public"
    elif action == "delete":
        changes["visibility"] = "deleted"
        changes["deleted"] = True
    elif action == "lock":
        changes["locked"] = True
    elif action == "unlock":
        changes["locked"] = False

    _touch_receipt(state, env)
    _apply_mod_to_target(state, target_id=target_id, changes=changes)

    return {
        "applied": "MOD_ACTION_RECEIPT",
        "receipt": True,
        "target_id": target_id,
        "action": action,
    }


# ---------------------------
# Dispatcher
# ---------------------------


CONTENT_TX_TYPES: set[str] = {
    # Canon names
    "CONTENT_POST_CREATE",
    "CONTENT_POST_EDIT",
    "CONTENT_POST_DELETE",
    "CONTENT_COMMENT_CREATE",
    "CONTENT_COMMENT_DELETE",
    "CONTENT_REACTION_SET",
    "CONTENT_FLAG",
    "CONTENT_MEDIA_DECLARE",
    "CONTENT_MEDIA_BIND",
    "CONTENT_MEDIA_UNBIND",
    "CONTENT_MEDIA_REPLACE",
    "CONTENT_LABEL_SET",
    "CONTENT_VISIBILITY_SET",
    "CONTENT_THREAD_LOCK_SET",
    "CONTENT_ESCALATE_TO_DISPUTE",
    # Moderation receipts (canon Moderation domain)
    "FLAG_ESCALATION_RECEIPT",
    "MOD_ACTION_RECEIPT",
}


def apply_content(state: Json, env: TxEnvelope) -> Json | None:
    """Apply content txs. Returns meta if handled, else None."""
    t = str(env.tx_type or "").strip()
    if t not in CONTENT_TX_TYPES:
        return None

    if t == "CONTENT_POST_CREATE":
        return _apply_post_create(state, env)
    if t == "CONTENT_POST_EDIT":
        return _apply_post_edit(state, env)
    if t == "CONTENT_POST_DELETE":
        return _apply_post_delete(state, env)

    if t == "CONTENT_COMMENT_CREATE":
        return _apply_comment_create(state, env)
    if t == "CONTENT_COMMENT_DELETE":
        return _apply_comment_delete(state, env)

    if t == "CONTENT_REACTION_SET":
        return _apply_reaction_set(state, env)
    if t == "CONTENT_FLAG":
        return _apply_content_flag(state, env)

    if t == "CONTENT_MEDIA_DECLARE":
        return _apply_content_media_declare(state, env)
    if t == "CONTENT_MEDIA_BIND":
        return _apply_content_media_bind(state, env)
    if t == "CONTENT_MEDIA_UNBIND":
        return _apply_content_media_unbind(state, env)
    if t == "CONTENT_MEDIA_REPLACE":
        return _apply_content_media_replace(state, env)

    if t == "CONTENT_LABEL_SET":
        return _apply_content_label_set(state, env)
    if t == "CONTENT_VISIBILITY_SET":
        return _apply_content_visibility_set(state, env)
    if t == "CONTENT_THREAD_LOCK_SET":
        return _apply_content_thread_lock_set(state, env)
    if t == "CONTENT_ESCALATE_TO_DISPUTE":
        return _apply_content_escalate_to_dispute(state, env)

    if t == "FLAG_ESCALATION_RECEIPT":
        return _apply_flag_escalation_receipt(state, env)
    if t == "MOD_ACTION_RECEIPT":
        return _apply_mod_action_receipt(state, env)

    # Should be unreachable.
    _touch_receipt(state, env)
    return {"applied": t, "noop": True}
