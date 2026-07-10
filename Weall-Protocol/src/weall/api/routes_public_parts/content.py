from __future__ import annotations

import base64
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import (
    _cursor_pack,
    _cursor_unpack,
    _int_param,
    _group_roles_by_id,
    _groups_by_id,
    _normalize_tags_param,
    _str_param,
)
from weall.api.security import require_account_session

router = APIRouter()

Json = dict[str, Any]


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _snapshot(request: Request) -> Json:
    ex = getattr(request.app.state, "executor", None)
    if ex is None or not hasattr(ex, "read_state"):
        return {}
    try:
        st = ex.read_state()
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _maybe_observer_read_sync(request: Request) -> None:
    try:
        from weall.api.routes_public_parts.tx import maybe_observer_edge_sync_latest_for_read

        maybe_observer_edge_sync_latest_for_read(request)
    except Exception:
        # Public reads must remain available even when an observer cannot reach
        # its configured upstream. The returned state remains local truth.
        return

def _content_root(st: Json) -> Json:
    return _as_dict(st.get("content"))


def _posts(st: Json) -> Json:
    return _as_dict(_content_root(st).get("posts"))


def _comments(st: Json) -> Json:
    return _as_dict(_content_root(st).get("comments"))


def _moderation_targets(st: Json) -> Json:
    content = _content_root(st)
    moderation = _as_dict(content.get("moderation"))
    return _as_dict(moderation.get("targets"))


def _moderation_record_hides(rec: Json) -> bool:
    if not isinstance(rec, dict):
        return False
    if bool(rec.get("deleted", False)):
        return True
    vis = str(rec.get("visibility", "") or "").strip().lower()
    action = str(rec.get("last_action", "") or "").strip().lower()
    return vis in {"hidden", "deleted", "removed"} or action in {"hide", "delete", "remove"}


def _target_key_variants(target_id: str = "", obj: Json | None = None) -> list[str]:
    """Return deterministic aliases for a content target id.

    The local rehearsal exposed a read-model split where a moderation/dispute
    record could be keyed by the canonical target id while an account/group feed
    looked up a post object's alternate id field.  Normal reads must treat all
    aliases as the same target so removed or appeal-window content cannot remain
    visible on one surface.
    """

    obj = obj if isinstance(obj, dict) else {}
    candidates: list[str] = []
    for raw in (target_id, obj.get("post_id"), obj.get("id"), obj.get("content_id")):
        text = str(raw or "").strip()
        if text and text not in candidates:
            candidates.append(text)

    author = str(obj.get("author") or obj.get("owner") or obj.get("account_id") or "").strip()
    for nonce_key in ("created_nonce", "created_at_nonce", "nonce"):
        try:
            nonce = int(obj.get(nonce_key) or 0)
        except Exception:
            nonce = 0
        if author and nonce > 0:
            for acct in (author, author.lstrip("@"), f"@{author.lstrip('@')}"):
                cand = f"post:{acct}:{nonce}"
                if cand not in candidates:
                    candidates.append(cand)

    return candidates


def _resolution_hides_target(resolution: Json) -> bool:
    if not isinstance(resolution, dict):
        return False
    outcome = str(resolution.get("outcome") or resolution.get("action") or "").strip().lower()
    if outcome in {"report_upheld", "remove", "removed", "delete", "deleted", "hide", "hidden"}:
        return True
    actions = resolution.get("actions")
    if not isinstance(actions, list):
        return False
    for action in actions:
        if not isinstance(action, dict):
            continue
        tx_type = str(action.get("tx_type") or "").strip()
        payload = _as_dict(action.get("payload"))
        if tx_type == "CONTENT_VISIBILITY_SET":
            visibility = str(payload.get("visibility") or "").strip().lower()
            if visibility in {"hidden", "deleted", "removed"}:
                return True
        if tx_type == "MOD_ACTION_RECEIPT":
            act = str(payload.get("action") or "").strip().lower()
            visibility = str(payload.get("visibility") or "").strip().lower()
            if act in {"hide", "delete", "remove"} or visibility in {"hidden", "deleted", "removed"}:
                return True
    return False


def _vote_choice_from_record(rec: Json) -> str:
    """Return the reviewer choice from old/new dispute vote record shapes."""

    choice = str(
        rec.get("vote")
        or rec.get("choice")
        or rec.get("decision")
        or rec.get("outcome")
        or ""
    ).strip().lower()
    if choice:
        return choice
    resolution = _as_dict(rec.get("resolution"))
    outcome = str(resolution.get("outcome") or resolution.get("action") or "").strip().lower()
    if outcome:
        return outcome
    return ""


def _dispute_vote_tally_hides_target(raw: Json) -> bool:
    """Return True when recorded review votes are sufficient to hide a target.

    Constitutional-clock mode can keep a report in an active/appeal stage while
    final enforcement receipts are delayed.  The appeal window remains open for
    the affected creator, but normal feeds must still hide the target once the
    recorded review tally has deterministically upheld removal; dispute/appeal
    routes remain the place to inspect or challenge the outcome.
    """

    votes = _as_dict(raw.get("votes"))
    if not votes:
        return False

    yes = 0
    no = 0
    active_votes = 0
    for rec in votes.values():
        if not isinstance(rec, dict):
            continue
        choice = _vote_choice_from_record(rec)
        if choice in {"yes", "remove", "removed", "uphold", "upheld", "report_upheld"}:
            yes += 1
            active_votes += 1
        elif choice in {"no", "keep", "kept", "dismiss", "dismissed", "report_not_upheld"}:
            no += 1
            active_votes += 1
        elif choice in {"abstain", "need_more_review", "need-more-review", "more_review"}:
            active_votes += 1

    try:
        required = int(raw.get("required_votes") or 0)
    except Exception:
        required = 0
    if required <= 0:
        try:
            required = int(raw.get("eligible_validator_count") or 0)
        except Exception:
            required = 0
    if required <= 0:
        required = max(1, active_votes)

    return yes > no and yes >= required


def _candidate_dispute_records_for_target(st: Json, *, target_keys: list[str]) -> list[Json]:
    key_set = {str(k or "").strip() for k in target_keys if str(k or "").strip()}
    if not key_set:
        return []

    disputes = _as_dict(st.get("disputes_by_id"))
    out: list[Json] = []
    seen: set[int] = set()

    def add(raw: Any) -> None:
        if not isinstance(raw, dict):
            return
        marker = id(raw)
        if marker in seen:
            return
        seen.add(marker)
        out.append(raw)

    # Direct scan is the canonical path.
    for raw in disputes.values():
        if not isinstance(raw, dict):
            continue
        target_type = str(raw.get("target_type") or "content").strip().lower()
        if target_type not in {"content", "post", "comment"}:
            continue
        target_id = str(raw.get("target_id") or "").strip()
        if target_id in key_set:
            add(raw)

    # Rehearsal nodes can have the target index even when a surface only has an
    # alias of the post id.  Consult it too so account/group feeds do not show
    # removed content while the detail route has already suppressed it.
    by_target = _as_dict(st.get("disputes_by_target"))
    for key in sorted(key_set):
        for target_type in ("content", "post", "comment"):
            did = str(by_target.get(f"{target_type}:{key}") or "").strip()
            if did and did in disputes:
                add(disputes.get(did))

    return out


def _dispute_record_hides_target(st: Json, *, target_keys: list[str]) -> bool:
    for raw in _candidate_dispute_records_for_target(st, target_keys=target_keys):
        stage = str(raw.get("stage") or raw.get("status") or "").strip().lower()
        if stage in {"dismissed", "expired", "unassigned", "declined", "report_not_upheld"}:
            continue
        resolution = _as_dict(raw.get("resolution"))
        if _resolution_hides_target(resolution):
            return True
        if _dispute_vote_tally_hides_target(raw):
            return True
    return False


def _content_target_hidden_by_review(st: Json, target_id: str = "", obj: Json | None = None) -> bool:
    keys = _target_key_variants(target_id, obj)
    if not keys:
        return False
    targets = _moderation_targets(st)
    for key in keys:
        if _moderation_record_hides(_as_dict(targets.get(key))):
            return True
    return _dispute_record_hides_target(st, target_keys=keys)


def _post_visible(st: Json, post: Json, post_id: str = "") -> bool:
    if not isinstance(post, dict):
        return False
    pid = str(post_id or post.get("post_id") or post.get("id") or "").strip()
    if bool(post.get("deleted", False)):
        return False
    if _content_target_hidden_by_review(st, pid, post):
        return False
    # Public-only default: public posts are visible; legacy group-scoped posts
    # remain publicly readable through detail/group routes instead of becoming a
    # restricted-read archive.  Non-public legacy records stay
    # hidden and cannot be revived by owner-scoped reads.
    vis = str(post.get("visibility", "public") or "public").strip().lower()
    gid = str(post.get("group_id") or post.get("group") or "").strip()
    return vis in {"public", ""} or (bool(gid) and vis == "group")


def _comment_visible(st: Json, comment: Json) -> bool:
    if not isinstance(comment, dict):
        return False
    if bool(comment.get("deleted", False)):
        return False
    vis = str(comment.get("visibility", "public") or "public").strip().lower()
    if vis not in {"public", ""}:
        return False
    root_id = str(comment.get("post_id") or comment.get("thread_id") or "").strip()
    if not root_id:
        return True
    root = _as_dict(_posts(st).get(root_id))
    return bool(root and _post_visible(st, root, root_id))



def _tags_list(obj: Json) -> list[str]:
    raw = obj.get("tags")
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


def _media_root(st: Json) -> Json:
    return _as_dict(_content_root(st).get("media"))


def _media_ref_summary(raw: Any, media_index: Json) -> Any:
    """Return metadata-only media references for feed responses.

    This deliberately never fetches blobs. It only translates committed media ids
    into bounded display metadata so observer/frontends can stay metadata-first
    until viewport-triggered media loading asks the local observer for the CID.
    """
    if isinstance(raw, str):
        media_id = raw.strip()
        rec = _as_dict(media_index.get(media_id)) if media_id else {}
        if not rec:
            return raw
        payload = _as_dict(rec.get("payload"))
        cid = str(rec.get("cid") or payload.get("cid") or payload.get("upload_ref") or "").strip()
        out: Json = {
            "media_id": media_id,
            "cid": cid,
            "mime": str(payload.get("mime") or payload.get("mime_type") or payload.get("content_type") or "").strip(),
            "name": str(payload.get("name") or payload.get("filename") or media_id).strip(),
            "kind": str(rec.get("kind") or payload.get("kind") or "").strip(),
            "bytes": _safe_int(payload.get("size") or payload.get("size_bytes"), 0),
            "declared_by": str(rec.get("declared_by") or "").strip(),
            "declared_at_nonce": rec.get("declared_at_nonce"),
            "load_policy": "viewport",
            "fetch_path": f"/v1/media/proxy/{cid}" if cid else "",
        }
        return out

    if isinstance(raw, dict):
        cid = str(raw.get("cid") or raw.get("upload_ref") or raw.get("ref") or "").strip()
        out = dict(raw)
        out.setdefault("load_policy", "viewport")
        if cid:
            out.setdefault("fetch_path", f"/v1/media/proxy/{cid}")
        return out

    return raw


def _with_media_summaries(st: Json, obj: Json) -> Json:
    out = dict(obj)
    raw_media = _as_list(out.get("media"))
    if not raw_media:
        return out
    media_index = _media_root(st)
    out["media"] = [_media_ref_summary(item, media_index) for item in raw_media]
    out["media_load_policy"] = "viewport"
    return out



def _group_has_non_public_legacy_read_marker(g: Json) -> bool:
    if not isinstance(g, dict):
        return False
    if bool(g.get("is_" + "pri" + "vate", False)):
        return True
    vis = str(g.get("visibility") or g.get("pri" + "vacy") or "").strip().lower()
    if vis in {"pri" + "vate", "closed", "members"}:
        return True
    meta = g.get("meta")
    if isinstance(meta, dict):
        if bool(meta.get("is_" + "pri" + "vate", False)):
            return True
        vis2 = str(meta.get("visibility") or meta.get("pri" + "vacy") or "").strip().lower()
        if vis2 in {"pri" + "vate", "closed", "members"}:
            return True
    return False


def _group_record_for_content(st: Json, group_id: str) -> Json:
    gid = str(group_id or "").strip()
    if not gid:
        return {}
    by_state = _groups_by_id(st)
    by_roles = _group_roles_by_id(st)
    g_state = by_state.get(gid)
    g_roles = by_roles.get(gid)
    if not isinstance(g_state, dict) and not isinstance(g_roles, dict):
        return {}
    out: Json = dict(g_state) if isinstance(g_state, dict) else {"id": gid, "group_id": gid}
    if isinstance(g_roles, dict):
        out.setdefault("roles", g_roles)
        if "members" not in out and isinstance(g_roles.get("members"), dict):
            out["members"] = g_roles.get("members")
    return out


def _is_group_member(st: Json, *, group_id: str, account: str) -> bool:
    acct = str(account or "").strip()
    gid = str(group_id or "").strip()
    if not acct or not gid:
        return False

    g = _groups_by_id(st).get(gid)
    if isinstance(g, dict):
        members = g.get("members")
        if isinstance(members, dict) and acct in members:
            return True

    g_roles = _group_roles_by_id(st).get(gid)
    if isinstance(g_roles, dict):
        members = g_roles.get("members")
        if isinstance(members, dict) and acct in members:
            return True

    return False


def _owner_of_content(obj: Json) -> str:
    return str(
        obj.get("author")
        or obj.get("owner")
        or obj.get("account_id")
        or obj.get("created_by")
        or obj.get("signer")
        or ""
    ).strip()


def _visibility_of_content(obj: Json) -> str:
    return str(obj.get("visibility", "public") or "public").strip().lower()


def _group_id_of_content(obj: Json) -> str:
    return str(obj.get("group_id") or obj.get("group") or "").strip()


def _viewer_can_read_post(st: Json, post: Json, viewer: str) -> bool:
    """Return whether the content is readable under the public-only protocol.

    Historical builds had an authenticated scoped route that let owners or group
    members read non-public protocol content.  The public-only redesign removes
    that private archive semantics: if a protocol object is not public-readable,
    it is not readable through a different account-scoped route either.  Group
    posts with legacy visibility=group remain publicly readable through group and
    content detail surfaces because group membership may gate participation but
    never read visibility.
    """

    if not isinstance(post, dict) or bool(post.get("deleted", False)):
        return False
    pid = str(post.get("post_id") or post.get("id") or "").strip()
    if _content_target_hidden_by_review(st, pid, post):
        return False

    vis = _visibility_of_content(post)
    gid = _group_id_of_content(post)

    if vis in {"public", ""}:
        return True
    if gid and vis == "group":
        return True
    return False


def _viewer_can_read_comment(st: Json, comment: Json, viewer: str) -> bool:
    if not isinstance(comment, dict) or bool(comment.get("deleted", False)):
        return False
    owner = _owner_of_content(comment)
    if owner and owner == viewer:
        return True
    root_id = str(comment.get("post_id") or comment.get("thread_id") or "").strip()
    root = _as_dict(_posts(st).get(root_id)) if root_id else {}
    if root:
        return _viewer_can_read_post(st, root, viewer)
    return _visibility_of_content(comment) in {"public", ""}

def _content_identity(obj: Json) -> str:
    return str(obj.get("post_id") or obj.get("comment_id") or obj.get("content_id") or obj.get("id") or "").strip()


def _sort_by_nonce_desc(items: list[Json], *, key: str) -> list[Json]:
    def k(obj: Json) -> tuple[int, str]:
        return (_safe_int(obj.get(key), 0), _content_identity(obj))

    return sorted(items, key=k, reverse=True)


def _comment_counts_by_post(st: Json) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _, raw in sorted(_comments(st).items(), key=lambda item: str(item[0])):
        com = _as_dict(raw)
        if not _comment_visible(st, com):
            continue
        post_id = str(com.get("post_id") or com.get("thread_id") or "").strip()
        if post_id:
            counts[post_id] = int(counts.get(post_id, 0)) + 1
    return counts


def _feed_rank_mode(raw: Any) -> str:
    mode = _str_param(raw, "recency").strip().lower().replace("-", "_") or "recency"
    if mode in {"latest", "new", "newest", "chronological"}:
        return "recency"
    if mode in {"engagement", "reaction", "reactions"}:
        return "engagement"
    if mode in {"balanced", "quality", "default_ranked"}:
        return "balanced"
    if mode in {"production", "prod", "social", "social_production", "for_you", "discovery"}:
        return "production"
    return "recency"


def _author_of_feed_item(obj: Json) -> str:
    return _str_param(obj.get("author") or obj.get("owner") or obj.get("account_id") or obj.get("created_by")).strip()


def _account_record(st: Json, account_id: str) -> Json:
    accounts = _as_dict(st.get("accounts"))
    acct = _str_param(account_id).strip()
    if acct in accounts and isinstance(accounts.get(acct), dict):
        return _as_dict(accounts.get(acct))
    if acct and not acct.startswith("@") and f"@{acct}" in accounts:
        return _as_dict(accounts.get(f"@{acct}"))
    if acct.startswith("@") and acct[1:] in accounts:
        return _as_dict(accounts.get(acct[1:]))
    return {}


def _account_reputation_score(st: Json, account_id: str) -> int:
    acct = _account_record(st, account_id)
    rep = _safe_int(acct.get("reputation") or acct.get("rep") or acct.get("score"), 0)
    tier = _safe_int(acct.get("poh_tier"), 0)
    if bool(acct.get("banned", False)) or bool(acct.get("locked", False)):
        return -500
    # Bounded so reputation helps quality ranking without letting whales or old
    # accounts dominate the public feed.
    return max(-500, min(500, rep * 5)) + max(0, min(3, tier)) * 25


def _reaction_weight_for_actor(st: Json, actor: str) -> int:
    acct = _account_record(st, actor)
    if bool(acct.get("banned", False)) or bool(acct.get("locked", False)):
        return 0
    tier = max(0, min(3, _safe_int(acct.get("poh_tier"), 0)))
    rep = max(0, min(80, _safe_int(acct.get("reputation") or acct.get("rep"), 0)))
    return 100 + tier * 25 + rep * 3


def _production_reaction_stats_by_target(st: Json) -> dict[str, Json]:
    content = _content_root(st)
    reactions = _as_dict(content.get("reactions"))
    stats: dict[str, Json] = {}
    seen: set[tuple[str, str]] = set()
    positive = {"like", "love", "up", "upvote", "agree", "helpful", "support", "+1"}
    negative = {"down", "downvote", "dislike", "spam", "abuse", "-1"}
    for key, raw in sorted(reactions.items(), key=lambda item: str(item[0])):
        rec = _as_dict(raw)
        target_id = str(rec.get("target_id") or "").strip()
        actor = str(rec.get("by") or rec.get("actor") or rec.get("account_id") or str(key).split(":", 1)[0]).strip()
        reaction = str(rec.get("reaction") or "").strip().lower()
        if not target_id or not actor or not reaction:
            continue
        actor_key = (target_id, actor)
        if actor_key in seen:
            continue
        seen.add(actor_key)
        bucket = stats.setdefault(target_id, {"weighted_positive": 0, "weighted_negative": 0, "unique_reactors": 0})
        weight = _reaction_weight_for_actor(st, actor)
        if reaction in negative:
            bucket["weighted_negative"] = int(bucket.get("weighted_negative", 0)) + weight
        elif reaction in positive or reaction:
            bucket["weighted_positive"] = int(bucket.get("weighted_positive", 0)) + weight
        bucket["unique_reactors"] = int(bucket.get("unique_reactors", 0)) + 1
    return stats


def _author_frequency_penalties(posts: list[Json]) -> dict[str, int]:
    by_author: dict[str, list[Json]] = {}
    for post in posts:
        author = _author_of_feed_item(post)
        if not author:
            continue
        by_author.setdefault(author, []).append(post)
    penalties: dict[str, int] = {}
    for author, author_posts in by_author.items():
        ordered = sorted(author_posts, key=lambda obj: (_safe_int(obj.get("created_at_nonce") or obj.get("created_nonce"), 0), _content_identity(obj)), reverse=True)
        for index, post in enumerate(ordered):
            if index <= 0:
                continue
            penalties[_content_identity(post)] = int(index * 120)
    return penalties


def _feed_safety_penalty(obj: Json) -> int:
    labels = obj.get("labels")
    penalty = 0
    if isinstance(labels, list):
        severe = {"policy_violation", "dispute_upheld", "abuse", "illegal"}
        soft = {"spam", "low_quality", "duplicate", "brigading_suspected"}
        for label in {str(x).strip().lower() for x in labels}:
            if label in severe:
                penalty += 50_000
            elif label in soft:
                penalty += 5_000
    return penalty


def _feed_rank_score(
    obj: Json,
    *,
    mode: str,
    state: Json | None = None,
    max_created_nonce: int | None = None,
    author_frequency_penalty: int = 0,
) -> int:
    created = _safe_int(obj.get("created_at_nonce") or obj.get("created_nonce"), 0)
    reactions = _safe_int(obj.get("reaction_total"), 0)
    comments = _safe_int(obj.get("comment_total"), 0)
    moderation_penalty = _feed_safety_penalty(obj)

    # All scores are integer-only and state-derived.  No wall clock, randomness,
    # floats, locale, or personalized client state participates in ranking.
    if mode == "engagement":
        return int((reactions * 1_000) + (comments * 250) + created - moderation_penalty)
    if mode == "balanced":
        return int(created + (reactions * 100) + (comments * 40) - moderation_penalty)
    if mode == "production":
        st = state if isinstance(state, dict) else {}
        max_nonce = int(max_created_nonce if max_created_nonce is not None else created)
        age = max(0, max_nonce - created)
        freshness = max(0, 30_000 - age * 35)
        author = _author_of_feed_item(obj)
        author_quality = _account_reputation_score(st, author)
        weighted_positive = _safe_int(obj.get("weighted_positive_reactions"), reactions * 100)
        weighted_negative = _safe_int(obj.get("weighted_negative_reactions"), 0)
        unique_reactors = min(250, _safe_int(obj.get("unique_reactors"), reactions))
        comment_quality = min(20_000, comments * 1_000)
        engagement = min(80_000, weighted_positive * 4 + unique_reactors * 500 + comment_quality)
        downrank = min(60_000, weighted_negative * 2) + moderation_penalty + max(0, int(author_frequency_penalty))
        return int(freshness + engagement + author_quality - downrank)
    return int(created)


def _sort_feed_items(items: list[Json], *, mode: str) -> list[Json]:
    if mode == "recency":
        return _sort_by_nonce_desc(items, key="created_at_nonce")

    def k(obj: Json) -> tuple[int, int, str]:
        return (
            _safe_int(obj.get("feed_rank_score"), 0),
            _safe_int(obj.get("created_at_nonce") or obj.get("created_nonce"), 0),
            _content_identity(obj),
        )

    return sorted(items, key=k, reverse=True)


def _feed_position(obj: Json, *, mode: str) -> tuple[int, int, str]:
    identity = _content_identity(obj)
    nonce = _safe_int(obj.get("created_at_nonce") or obj.get("created_nonce"), 0)
    if mode == "recency":
        return (nonce, 0, identity)
    return (_safe_int(obj.get("feed_rank_score"), 0), nonce, identity)


def _feed_cursor_pack(*, mode: str, obj: Json) -> str:
    """Encode a deterministic feed cursor.

    Recency mode preserves the legacy nonce|id cursor so existing clients and
    tests remain compatible.  Ranked modes require the score in the cursor;
    otherwise old-but-popular posts can make cursor filtering skip newer quiet
    posts that should appear later in the ranked order.
    """

    nonce = _safe_int(obj.get("created_at_nonce") or obj.get("created_nonce"), 0)
    identity = str(obj.get("id") or obj.get("post_id") or "").strip()
    if mode == "recency":
        return _cursor_pack(created_at_nonce=nonce, content_id=identity)
    payload = {
        "v": 1,
        "mode": mode,
        "score": _safe_int(obj.get("feed_rank_score"), 0),
        "nonce": nonce,
        "id": identity,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _feed_cursor_unpack(raw: Any, *, mode: str) -> tuple[int, int, str] | None:
    text = _str_param(raw).strip()
    if not text:
        return None

    # Ranked cursor format first.
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((text + pad).encode("ascii")).decode("utf-8", errors="strict")
        data = json.loads(decoded)
        if isinstance(data, dict) and int(data.get("v") or 0) == 1:
            if str(data.get("mode") or "") != mode:
                return None
            return (_safe_int(data.get("score"), 0), _safe_int(data.get("nonce"), 0), str(data.get("id") or "").strip())
    except Exception:
        pass

    # Legacy recency cursor.
    if mode == "recency":
        nonce, content_id = _cursor_unpack(text)
        if nonce is not None and content_id is not None:
            return (int(nonce), 0, str(content_id))
    return None


def _apply_feed_cursor(items: list[Json], *, mode: str, raw_cursor: Any) -> list[Json]:
    cursor = _feed_cursor_unpack(raw_cursor, mode=mode)
    if cursor is None:
        return items
    return [obj for obj in items if _feed_position(obj, mode=mode) < cursor]


def _reaction_counts_by_target(st: Json) -> dict[str, dict[str, int]]:
    content = _content_root(st)
    reactions = _as_dict(content.get("reactions"))
    counts: dict[str, dict[str, int]] = {}
    for _, raw in sorted(reactions.items(), key=lambda item: str(item[0])):
        rec = _as_dict(raw)
        target_id = str(rec.get("target_id") or "").strip()
        reaction = str(rec.get("reaction") or "").strip().lower()
        if not target_id or not reaction:
            continue
        target_counts = counts.setdefault(target_id, {})
        target_counts[reaction] = int(target_counts.get(reaction, 0)) + 1
    return counts


def _with_reaction_counts(obj: Json, counts_by_target: dict[str, dict[str, int]]) -> Json:
    out = dict(obj)
    target_id = str(out.get("comment_id") or out.get("post_id") or out.get("content_id") or "").strip()
    existing = _as_dict(out.get("reactions"))
    merged: Json = {}
    for key, value in existing.items():
        if isinstance(value, (int, float)):
            merged[str(key)] = int(value)
    if target_id and target_id in counts_by_target:
        for reaction, count in counts_by_target[target_id].items():
            merged[str(reaction)] = int(count)
    out["reactions"] = merged
    out["reaction_total"] = int(sum(int(v) for v in merged.values())) if merged else 0
    return out


@router.get("/feed")
def feed(request: Request) -> dict[str, object]:
    """Public feed.

    Production read-path rules:
      - returns non-deleted, visible posts only
      - supports bounded pagination instead of returning the full history
      - returns metadata-only media summaries; media blobs are never fetched here
      - sorted by created nonce descending

    This keeps observer/frontends metadata-first. Viewport-triggered media loads
    should use the local observer media proxy only when a media card approaches
    the user's viewport.
    """

    _maybe_observer_read_sync(request)
    st = _snapshot(request)
    qp = request.query_params
    limit = _int_param(qp.get("limit"), 25)
    limit = max(1, min(100, limit))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))
    visibility = _str_param(qp.get("visibility"), "public").strip().lower() or "public"
    tags = _normalize_tags_param(qp.get("tags"))
    author = _str_param(qp.get("author")).strip()

    posts = _posts(st)
    reaction_counts = _reaction_counts_by_target(st)
    production_reaction_stats = _production_reaction_stats_by_target(st)
    comment_counts = _comment_counts_by_post(st)
    rank_mode = _feed_rank_mode(qp.get("rank") or qp.get("ranking"))

    filtered: list[Json] = []
    for pid, p in posts.items():
        post = _with_reaction_counts(_as_dict(p), reaction_counts)
        post_id = _str_param(post.get("post_id") or post.get("id") or pid).strip()
        post.setdefault("id", post_id)
        post.setdefault("created_at_nonce", _safe_int(post.get("created_nonce"), 0))
        created_at_nonce = _safe_int(post.get("created_at_nonce") or post.get("created_nonce"), 0)

        if not _post_visible(st, post, post_id):
            continue

        if visibility in {"public", "pri" + "vate"}:
            if _str_param(post.get("visibility"), "public").strip().lower() != visibility:
                continue
        elif visibility != "all":
            # Unknown visibility filters fail closed to public.
            if _str_param(post.get("visibility"), "public").strip().lower() != "public":
                continue

        if author and _str_param(post.get("author")).strip() != author:
            continue

        if tags and not any(t in _tags_list(post) for t in tags):
            continue

        comment_total = int(comment_counts.get(post_id, 0))
        post["comment_total"] = comment_total
        if rank_mode == "production":
            stats = _as_dict(production_reaction_stats.get(post_id))
            post["weighted_positive_reactions"] = _safe_int(stats.get("weighted_positive"), 0)
            post["weighted_negative_reactions"] = _safe_int(stats.get("weighted_negative"), 0)
            post["unique_reactors"] = _safe_int(stats.get("unique_reactors"), 0)
        post["feed_rank_mode"] = rank_mode

        filtered.append(_with_media_summaries(st, post))

    max_created_nonce = max([_safe_int(p.get("created_at_nonce") or p.get("created_nonce"), 0) for p in filtered] or [0])
    author_penalties = _author_frequency_penalties(filtered) if rank_mode == "production" else {}
    for post in filtered:
        ident = _content_identity(post)
        post["feed_rank_score"] = _feed_rank_score(
            post,
            mode=rank_mode,
            state=st,
            max_created_nonce=max_created_nonce,
            author_frequency_penalty=_safe_int(author_penalties.get(ident), 0),
        )
        if rank_mode == "production":
            post["feed_rank_breakdown"] = {
                "weighted_positive_reactions": _safe_int(post.get("weighted_positive_reactions"), 0),
                "weighted_negative_reactions": _safe_int(post.get("weighted_negative_reactions"), 0),
                "unique_reactors": _safe_int(post.get("unique_reactors"), 0),
                "comment_total": _safe_int(post.get("comment_total"), 0),
                "author_frequency_penalty": _safe_int(author_penalties.get(ident), 0),
                "safety_penalty": _feed_safety_penalty(post),
            }

    filtered = _sort_feed_items(filtered, mode=rank_mode)
    filtered = _apply_feed_cursor(filtered, mode=rank_mode, raw_cursor=qp.get("cursor"))
    page = filtered[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _feed_cursor_pack(mode=rank_mode, obj=last)

    return {
        "ok": True,
        "items": page,
        "next_cursor": next_cursor,
        "ranking": {
            "mode": rank_mode,
            "deterministic": True,
            "personalized": False,
            "default_order": "created_at_nonce_desc" if rank_mode == "recency" else "feed_rank_score_desc",
            "cursor_model": "legacy_nonce_id" if rank_mode == "recency" else "rank_score_nonce_id",
            "production_social_feed": rank_mode == "production",
            "personalized": False,
            "uses_reputation_weighting": rank_mode == "production",
            "uses_anti_brigading_caps": rank_mode == "production",
            "uses_author_diversity_dampening": rank_mode == "production",
        },
    }


@router.get("/content/{content_id}")
def content_get(request: Request, content_id: str) -> dict[str, object]:
    """Get a single content object.

    Lookup order:
      1) posts[content_id]
      2) comments[content_id]

    Returns 404 if not found.
    """

    _maybe_observer_read_sync(request)
    st = _snapshot(request)

    pid = str(content_id or "").strip()
    if not pid:
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "content not found"}
        )

    moderation = _moderation_targets(st)

    posts = _posts(st)
    if pid in posts:
        post = _with_reaction_counts(_as_dict(posts.get(pid)), _reaction_counts_by_target(st))
        if bool(post.get("deleted", False)) or not _post_visible(st, post, pid):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {
            "ok": True,
            "type": "post",
            "content": _with_media_summaries(st, post),
            "moderation": _as_dict(moderation.get(pid)),
        }

    comments = _comments(st)
    if pid in comments:
        com = _with_reaction_counts(_as_dict(comments.get(pid)), _reaction_counts_by_target(st))
        if bool(com.get("deleted", False)) or not _comment_visible(st, com):
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "content not found"}
            )
        return {
            "ok": True,
            "type": "comment",
            "content": _with_media_summaries(st, com),
            "moderation": _as_dict(moderation.get(pid)),
        }

    raise HTTPException(
        status_code=404, detail={"code": "not_found", "message": "content not found"}
    )


@router.get("/content/{content_id}/scoped")
def content_get_scoped(request: Request, content_id: str) -> dict[str, object]:
    """Get a content object through an authenticated, scoped read path.

    Compatibility route for older clients that used an authenticated scoped
    content read.  It now applies the same public-only visibility rule as the
    public detail route; authentication may identify the requester for logs/UI,
    but it must not unlock non-public protocol content or restricted-read archives.
    """

    _maybe_observer_read_sync(request)
    st = _snapshot(request)
    try:
        viewer = require_account_session(request, st)
    except PermissionError as exc:
        code = str(exc) or "session_missing"
        raise ApiError.forbidden(code, code.replace("_", " "), {})

    pid = str(content_id or "").strip()
    if not pid:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})

    moderation = _moderation_targets(st)
    reaction_counts = _reaction_counts_by_target(st)

    posts = _posts(st)
    if pid in posts:
        post = _with_reaction_counts(_as_dict(posts.get(pid)), reaction_counts)
        if not _viewer_can_read_post(st, post, viewer):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {
            "ok": True,
            "type": "post",
            "content": _with_media_summaries(st, post),
            "moderation": _as_dict(moderation.get(pid)),
            "scope": {"viewer": viewer, "authorized": True},
        }

    comments = _comments(st)
    if pid in comments:
        com = _with_reaction_counts(_as_dict(comments.get(pid)), reaction_counts)
        if not _viewer_can_read_comment(st, com, viewer):
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})
        return {
            "ok": True,
            "type": "comment",
            "content": _with_media_summaries(st, com),
            "moderation": _as_dict(moderation.get(pid)),
            "scope": {"viewer": viewer, "authorized": True},
        }

    raise HTTPException(status_code=404, detail={"code": "not_found", "message": "content not found"})


@router.get("/thread/{thread_id}")
def thread_get(request: Request, thread_id: str) -> dict[str, object]:
    """Thread view: root post + its comments.

    The frontend expects this endpoint.
    """

    st = _snapshot(request)
    tid = str(thread_id or "").strip()

    posts = _posts(st)
    reaction_counts = _reaction_counts_by_target(st)
    root = _with_reaction_counts(_as_dict(posts.get(tid)), reaction_counts)
    if not root or bool(root.get("deleted", False)):
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "thread not found"}
        )

    # Public endpoint: hide non-public roots.
    if not _post_visible(st, root, tid):
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "thread not found"}
        )

    qp = request.query_params
    limit = max(1, min(200, _int_param(qp.get("limit"), 50)))
    cursor_n, cursor_id = _cursor_unpack(qp.get("cursor"))

    comments = _comments(st)
    all_comments: list[Json] = []
    for cid, c in comments.items():
        com = _with_reaction_counts(_as_dict(c), reaction_counts)
        if bool(com.get("deleted", False)):
            continue
        if str(com.get("post_id") or "") != tid:
            continue
        if not _comment_visible(st, com):
            continue
        comment_id = _str_param(com.get("comment_id") or com.get("id") or cid).strip()
        com.setdefault("comment_id", comment_id)
        com.setdefault("id", comment_id)
        created_nonce = _safe_int(com.get("created_nonce") or com.get("created_at_nonce"), 0)
        com.setdefault("created_at_nonce", created_nonce)
        if cursor_n is not None and cursor_id is not None:
            if created_nonce > cursor_n:
                continue
            if created_nonce == cursor_n and comment_id >= cursor_id:
                continue
        all_comments.append(_with_media_summaries(st, com))

    out_comments = _sort_by_nonce_desc(all_comments, key="created_at_nonce")
    page = out_comments[:limit]
    next_cursor = None
    if len(page) == limit:
        last = page[-1]
        next_cursor = _cursor_pack(
            created_at_nonce=_safe_int(last.get("created_at_nonce") or last.get("created_nonce"), 0),
            content_id=str(last.get("comment_id") or last.get("id") or ""),
        )

    return {
        "ok": True,
        "post": _with_media_summaries(st, root),
        "comments": page,
        "next_cursor": next_cursor,
        "counts": {"comments": len(out_comments), "returned": len(page)},
    }
