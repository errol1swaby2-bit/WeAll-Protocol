# src/weall/runtime/apply/content.py
from __future__ import annotations

"""
Content domain apply semantics.

This module handles deterministic state transitions for:
- posts
- comments
- reactions
- flags
- media declarations / bindings
- visibility / moderation (receipt-only placeholders)
- escalation to dispute (receipt-only placeholder)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class ContentApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


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
            "reputation": 0.0,
            "keys": [],
        },
    )
    acct["nonce"] = int(nonce)


# ---------------------------
# Posts
# ---------------------------


def _apply_post_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    posts = content["posts"]

    post_id = _as_str(payload.get("post_id")).strip() or f"post:{env.signer}:{env.nonce}"
    if post_id in posts:
        return {"applied": "CONTENT_POST_CREATE", "post_id": post_id, "deduped": True}

    posts[post_id] = {
        "post_id": post_id,
        "author": env.signer,
        "body": payload.get("body"),
        # media may contain media_ids or app-specific attachment refs
        "media": _as_list(payload.get("media")),
        "created_nonce": int(env.nonce),
        "visibility": payload.get("visibility", "public"),
        # Feed indexing helpers
        "tags": payload.get("tags", []),
        "group_id": payload.get("group_id"),
        "labels": [],
        "flags": [],
        "deleted": False,
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_POST_CREATE", "post_id": post_id}


def _apply_post_edit(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    posts = content["posts"]

    post_id = _as_str(payload.get("post_id")).strip()
    if not post_id or post_id not in posts:
        raise ContentApplyError("not_found", "post_not_found", {"post_id": post_id})

    post = posts[post_id]
    if post.get("author") != env.signer:
        raise ContentApplyError("forbidden", "not_author", {"post_id": post_id})

    post["body"] = payload.get("body", post.get("body"))
    post["media"] = _as_list(payload.get("media", post.get("media")))

    # Only mutate if explicitly provided
    if "tags" in payload:
        post["tags"] = payload.get("tags")
    if "group_id" in payload:
        post["group_id"] = payload.get("group_id")

    post["edited_nonce"] = int(env.nonce)

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_POST_EDIT", "post_id": post_id}


def _apply_post_delete(state: Json, env: TxEnvelope) -> Json:
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
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    comments = content["comments"]

    comment_id = _as_str(payload.get("comment_id")).strip() or f"comment:{env.signer}:{env.nonce}"
    if comment_id in comments:
        return {"applied": "CONTENT_COMMENT_CREATE", "comment_id": comment_id, "deduped": True}

    parent_post = _as_str(payload.get("post_id")).strip()
    if not parent_post:
        raise ContentApplyError("invalid_payload", "missing_post_id", {})

    comments[comment_id] = {
        "comment_id": comment_id,
        "post_id": parent_post,
        "author": env.signer,
        "body": payload.get("body"),
        "created_nonce": int(env.nonce),
        "deleted": False,
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_COMMENT_CREATE", "comment_id": comment_id}


def _apply_comment_delete(state: Json, env: TxEnvelope) -> Json:
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
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    flags = content["flags"]

    target_id = _as_str(payload.get("target_id")).strip()
    if not target_id:
        raise ContentApplyError("invalid_payload", "missing_target_id", {})

    flag_id = _as_str(payload.get("flag_id")).strip() or f"flag:{env.signer}:{env.nonce}"
    flags[flag_id] = {
        "flag_id": flag_id,
        "target_id": target_id,
        "by": env.signer,
        "reason": _as_str(payload.get("reason")),
        "nonce": int(env.nonce),
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_FLAG", "flag_id": flag_id}


# ---------------------------
# Media (canon-claimed)
# ---------------------------


def _apply_content_media_declare(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    media = content["media"]

    media_id = _as_str(payload.get("media_id") or payload.get("id")).strip() or f"media:{env.signer}:{env.nonce}"
    cid = _as_str(payload.get("cid") or payload.get("ipfs_cid") or payload.get("content_cid")).strip()
    if not cid:
        raise ContentApplyError("invalid_payload", "missing_cid", {"tx_type": env.tx_type})

    if media_id in media:
        return {"applied": "CONTENT_MEDIA_DECLARE", "media_id": media_id, "deduped": True}

    media[media_id] = {
        "media_id": media_id,
        "cid": cid,
        "kind": _as_str(payload.get("kind")).strip(),
        "declared_by": env.signer,
        "declared_at_nonce": int(env.nonce),
        "payload": payload,
    }

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_DECLARE", "media_id": media_id, "deduped": False}


def _apply_content_media_bind(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    media = content["media"]
    bindings = content["media_bindings"]

    media_id = _as_str(payload.get("media_id")).strip()
    target_id = _as_str(payload.get("target_id")).strip()
    if not media_id or not target_id:
        raise ContentApplyError("invalid_payload", "missing_media_or_target", {"tx_type": env.tx_type})

    if media_id not in media:
        raise ContentApplyError("not_found", "media_not_declared", {"media_id": media_id})

    bind_id = _as_str(payload.get("bind_id") or payload.get("id")).strip() or f"bind:{env.signer}:{env.nonce}"
    if bind_id in bindings:
        return {"applied": "CONTENT_MEDIA_BIND", "bind_id": bind_id, "deduped": True}

    bindings[bind_id] = {
        "bind_id": bind_id,
        "media_id": media_id,
        "target_id": target_id,
        "by": env.signer,
        "at_nonce": int(env.nonce),
        "payload": payload,
        "status": "bound",
    }

    # If binding a post, also mirror into post.media list
    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        m = post.get("media")
        if not isinstance(m, list):
            m = []
        if media_id not in m:
            m.append(media_id)
        post["media"] = m

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_BIND", "bind_id": bind_id, "deduped": False}


def _apply_content_media_unbind(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)
    bindings = content["media_bindings"]

    bind_id = _as_str(payload.get("bind_id") or payload.get("id")).strip()
    if not bind_id:
        raise ContentApplyError("invalid_payload", "missing_bind_id", {"tx_type": env.tx_type})

    rec = bindings.get(bind_id)
    if not isinstance(rec, dict):
        raise ContentApplyError("not_found", "binding_not_found", {"bind_id": bind_id})

    rec["unbound_at_nonce"] = int(env.nonce)
    rec["unbound_by"] = env.signer
    rec["status"] = "unbound"
    bindings[bind_id] = rec

    # Mirror removal from post.media if applicable
    target_id = _as_str(rec.get("target_id")).strip()
    media_id = _as_str(rec.get("media_id")).strip()
    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        m = post.get("media")
        if isinstance(m, list) and media_id in m:
            post["media"] = [x for x in m if x != media_id]

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {"applied": "CONTENT_MEDIA_UNBIND", "bind_id": bind_id}


def _apply_content_media_replace(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    content = _ensure_root(state)

    target_id = _as_str(payload.get("target_id")).strip()
    old_media_id = _as_str(payload.get("old_media_id")).strip()
    new_media_id = _as_str(payload.get("new_media_id")).strip()
    if not target_id or not old_media_id or not new_media_id:
        raise ContentApplyError("invalid_payload", "missing_target_or_media_ids", {"tx_type": env.tx_type})

    media = content["media"]
    if new_media_id not in media:
        raise ContentApplyError("not_found", "new_media_not_declared", {"media_id": new_media_id})

    posts = content.get("posts")
    if isinstance(posts, dict) and target_id in posts and isinstance(posts[target_id], dict):
        post = posts[target_id]
        m = post.get("media")
        if not isinstance(m, list):
            m = []
        m = [x for x in m if x != old_media_id]
        if new_media_id not in m:
            m.append(new_media_id)
        post["media"] = m

    _ensure_account_nonce(state, env.signer, env.nonce)
    return {
        "applied": "CONTENT_MEDIA_REPLACE",
        "target_id": target_id,
        "old_media_id": old_media_id,
        "new_media_id": new_media_id,
    }


# ---------------------------
# Receipt-only placeholders
# ---------------------------


def _apply_content_receipt_only(state: Json, env: TxEnvelope) -> Json:
    """Record receipt-only content/moderation actions for auditability."""
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
    return {"applied": str(env.tx_type or ""), "receipt": True}


# ---------------------------
# Dispatcher
# ---------------------------


CONTENT_TX_TYPES: Set[str] = {
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


def apply_content(state: Json, env: TxEnvelope) -> Optional[Json]:
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

    # Receipt-only / block-only canon placeholders
    if t in {
        "CONTENT_LABEL_SET",
        "CONTENT_VISIBILITY_SET",
        "CONTENT_THREAD_LOCK_SET",
        "CONTENT_ESCALATE_TO_DISPUTE",
        "FLAG_ESCALATION_RECEIPT",
        "MOD_ACTION_RECEIPT",
    }:
        return _apply_content_receipt_only(state, env)

    # Should be unreachable because t is in CONTENT_TX_TYPES.
    return {"applied": t, "noop": True}
