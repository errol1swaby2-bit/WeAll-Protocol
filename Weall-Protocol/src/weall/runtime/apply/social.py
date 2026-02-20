# src/weall/runtime/apply/social.py
from __future__ import annotations

"""
Social domain apply semantics (staged-only).

Covers common Tier-2 social/account surface:
- PROFILE_UPDATE
- FOLLOW_SET / UNFOLLOW (via FOLLOW_SET active=False)
- BLOCK_SET
- MUTE_SET
- CONTENT_SHARE_CREATE (share/repost primitive)

IMPORTANT:
- This file is staged only.
- domain_apply_all.py is NOT modified yet.
- Final router hookup happens after all apply/* modules exist.

Design notes:
- This module intentionally uses simple, deterministic state shapes.
- If your monolith currently stores these in different locations, we’ll reconcile
  during final router cutover by preserving the monolith’s canonical storage keys.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class SocialApplyError(RuntimeError):
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


def _as_bool(x: Any, default: bool = False) -> bool:
    if x is None:
        return default
    return bool(x)


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_profiles(state: Json) -> Json:
    social = _ensure_root_dict(state, "social")
    profiles = social.get("profiles_by_id")
    if not isinstance(profiles, dict):
        profiles = {}
        social["profiles_by_id"] = profiles
    return profiles


def _ensure_edges(state: Json, key: str) -> Json:
    social = _ensure_root_dict(state, "social")
    edges = social.get(key)
    if not isinstance(edges, dict):
        edges = {}
        social[key] = edges
    return edges


def _mk_edge_key(a: str, b: str) -> str:
    return f"{a}:{b}"


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

def _apply_profile_update(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    profiles = _ensure_profiles(state)

    p = profiles.get(env.signer)
    if not isinstance(p, dict):
        p = {"account_id": env.signer, "created_at_nonce": int(env.nonce)}

    # allowlist common fields (safe, deterministic)
    for k in ("display_name", "bio", "avatar_cid", "banner_cid", "website", "location", "tags"):
        if k in payload:
            p[k] = payload.get(k)

    p["updated_at_nonce"] = int(env.nonce)
    profiles[env.signer] = p
    return {"applied": "PROFILE_UPDATE", "account_id": env.signer}


# ---------------------------------------------------------------------------
# Follow / Block / Mute
# ---------------------------------------------------------------------------

def _apply_follow_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target") or payload.get("account_id")).strip()
    active = _as_bool(payload.get("active"), True)
    if not target:
        raise SocialApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})
    if target == env.signer:
        raise SocialApplyError("invalid_payload", "cannot_follow_self", {"tx_type": env.tx_type})

    follows = _ensure_edges(state, "follows_by_edge")
    k = _mk_edge_key(env.signer, target)
    follows[k] = {"from": env.signer, "to": target, "active": active, "at_nonce": int(env.nonce)}
    return {"applied": "FOLLOW_SET", "from": env.signer, "to": target, "active": active}


def _apply_block_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target") or payload.get("account_id")).strip()
    active = _as_bool(payload.get("active"), True)
    if not target:
        raise SocialApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})
    if target == env.signer:
        raise SocialApplyError("invalid_payload", "cannot_block_self", {"tx_type": env.tx_type})

    blocks = _ensure_edges(state, "blocks_by_edge")
    k = _mk_edge_key(env.signer, target)
    blocks[k] = {"from": env.signer, "to": target, "active": active, "at_nonce": int(env.nonce)}
    return {"applied": "BLOCK_SET", "from": env.signer, "to": target, "active": active}


def _apply_mute_set(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target") or payload.get("account_id")).strip()
    active = _as_bool(payload.get("active"), True)
    if not target:
        raise SocialApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})
    if target == env.signer:
        raise SocialApplyError("invalid_payload", "cannot_mute_self", {"tx_type": env.tx_type})

    mutes = _ensure_edges(state, "mutes_by_edge")
    k = _mk_edge_key(env.signer, target)
    mutes[k] = {"from": env.signer, "to": target, "active": active, "at_nonce": int(env.nonce)}
    return {"applied": "MUTE_SET", "from": env.signer, "to": target, "active": active}


# ---------------------------------------------------------------------------
# Share / Repost primitive
# ---------------------------------------------------------------------------

def _apply_content_share_create(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target_id = _as_str(payload.get("target_id")).strip()
    if not target_id:
        raise SocialApplyError("invalid_payload", "missing_target_id", {"tx_type": env.tx_type})

    social = _ensure_root_dict(state, "social")
    shares = social.get("shares_by_id")
    if not isinstance(shares, dict):
        shares = {}
        social["shares_by_id"] = shares

    share_id = _as_str(payload.get("share_id")).strip() or f"share:{env.signer}:{env.nonce}"
    if share_id in shares:
        return {"applied": "CONTENT_SHARE_CREATE", "share_id": share_id, "deduped": True}

    shares[share_id] = {
        "share_id": share_id,
        "by": env.signer,
        "target_id": target_id,
        "comment": payload.get("comment"),
        "created_at_nonce": int(env.nonce),
    }
    return {"applied": "CONTENT_SHARE_CREATE", "share_id": share_id, "target_id": target_id}


SOCIAL_TX_TYPES: Set[str] = {
    "PROFILE_UPDATE",
    "FOLLOW_SET",
    "BLOCK_SET",
    "MUTE_SET",
    "CONTENT_SHARE_CREATE",
}


def apply_social(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = str(env.tx_type or "").strip()
    if t not in SOCIAL_TX_TYPES:
        return None

    if t == "PROFILE_UPDATE":
        return _apply_profile_update(state, env)
    if t == "FOLLOW_SET":
        return _apply_follow_set(state, env)
    if t == "BLOCK_SET":
        return _apply_block_set(state, env)
    if t == "MUTE_SET":
        return _apply_mute_set(state, env)
    if t == "CONTENT_SHARE_CREATE":
        return _apply_content_share_create(state, env)

    return None
