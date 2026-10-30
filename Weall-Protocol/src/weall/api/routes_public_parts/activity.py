from __future__ import annotations

"""Read-only notices derived from explicit public protocol event identity.

The public event ledger is authoritative. This projection is not a transaction,
a private messaging channel, or a source of role/reputation authority.
"""

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request

from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session

router = APIRouter()

Json = dict[str, Any]

NOTICE_TYPES: tuple[str, ...] = (
    "mention",
    "reply",
    "group_invitation",
    "moderation_notice",
    "dispute_assignment",
    "governance_notice",
    "validator_operator_alert",
    "reputation_update",
    "notification_receipt",
)

# A receipt topic is public, but its text is not trusted to become arbitrary
# UI content or a navigation URL. Only known topics get a fixed presentation.
RECEIPT_TOPIC_PRESENTATION: dict[str, tuple[str, str, str]] = {
    "review_assignment": ("dispute_assignment", "Review assignment", "/reviews"),
    "dispute_update": ("moderation_notice", "Public dispute update", "/reviews"),
    "governance": ("governance_notice", "Governance activity", "/decisions"),
    "security": ("validator_operator_alert", "Security notice", "/session"),
}


def _mapping(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return fallback


def collect_public_activity_notices(state: Json, account_id: str) -> list[Json]:
    """Project only explicitly addressed public records, without mutating state.

    IDs and ordering are stable across repeated reads of the same canonical
    snapshot. No arbitrary JSON-substring account matching is permitted.
    """
    account = _text(account_id)
    if not account:
        return []

    notices: dict[str, Json] = {}

    def add(
        notice_id: str,
        *,
        kind: str,
        title: str,
        body: str,
        href: str,
        priority: str = "normal",
        height: int = 0,
        source: str,
    ) -> None:
        if not notice_id or kind not in NOTICE_TYPES:
            return
        if notice_id in notices:
            return
        notices[notice_id] = {
            "id": notice_id,
            "type": kind,
            "title": title,
            "body": body,
            "href": href,
            "priority": priority,
            "height": max(0, int(height)),
            "source": source,
        }

    # Receipt-only SYSTEM events have an explicit recipient. Subscription
    # topics are NOT themselves user notifications.
    receipts = _records(_mapping(state.get("notify")).get("emit_receipts"))
    for index, raw in enumerate(receipts):
        record = _mapping(raw)
        payload = _mapping(record.get("payload"))
        if _text(payload.get("account_id")) != account:
            continue
        topic = _text(payload.get("topic"))
        if not topic:
            continue
        receipt_id = _text(payload.get("receipt_id")) or f"index:{index}"
        kind, title, href = RECEIPT_TOPIC_PRESENTATION.get(
            topic, ("notification_receipt", "Public protocol notice", "/activity")
        )
        add(
            f"notify:{receipt_id}:{account}",
            kind=kind,
            title=title,
            body="A finalized public protocol notification receipt is available.",
            href=href,
            priority="high" if topic in {"review_assignment", "security"} else "normal",
            source="notify.emit_receipts",
        )

    # Append-only Reputation Matrix events identify their actor explicitly;
    # only event code / source identity is surfaced, never raw evidence details.
    events = _records(_mapping(state.get("reputation")).get("events"))
    for raw in events:
        event = _mapping(raw)
        if _text(event.get("actor_id")) != account:
            continue
        event_id = _text(event.get("event_id"))
        if not event_id:
            continue
        event_code = _text(event.get("event_code") or event.get("reason_code"))
        if not event_code:
            continue
        severity = _int(event.get("severity"))
        add(
            f"reputation:{event_id}:{account}",
            kind="reputation_update",
            title="Reputation record updated",
            body=f"Public reputation event: {event_code[:80]}",
            href=f"/reputation/{quote(account, safe='')}",
            priority="high" if severity >= 3 else "normal",
            height=_int(event.get("occurred_at_block")),
            source="reputation.events",
        )

    # Public comments have an unambiguous parent post and author. A comment
    # by another account on the viewer's own visible post is an actual reply;
    # mention-like substrings in arbitrary bodies do not confer relevance.
    content = _mapping(state.get("content"))
    posts = _mapping(content.get("posts"))
    comments = _mapping(content.get("comments"))
    for comment_id, raw in comments.items():
        comment = _mapping(raw)
        if bool(comment.get("deleted")) or _text(comment.get("visibility")) != "public":
            continue
        author = _text(comment.get("author"))
        if not author or author == account:
            continue
        post_id = _text(comment.get("post_id"))
        post = _mapping(posts.get(post_id))
        if _text(post.get("author")) != account or bool(post.get("deleted")):
            continue
        if _text(post.get("visibility")) != "public":
            continue
        cid = _text(comment.get("comment_id")) or _text(comment_id)
        if not cid:
            continue
        add(
            f"reply:{cid}:{account}",
            kind="reply",
            title="New public reply",
            body="Another account commented on your public post.",
            href=f"/thread/{quote(post_id, safe='')}",
            source="content.comments",
        )

    # A juror entry is an explicit public assignment, not a text reference.
    disputes = _mapping(state.get("disputes_by_id"))
    for dispute_id, raw in disputes.items():
        dispute = _mapping(raw)
        if account not in _mapping(dispute.get("jurors")):
            continue
        did = _text(dispute.get("dispute_id")) or _text(dispute_id)
        if not did:
            continue
        add(
            f"dispute-assignment:{did}:{account}",
            kind="dispute_assignment",
            title="Public review assignment",
            body="A public dispute lists your account as a juror.",
            href=f"/reports/{quote(did, safe='')}",
            priority="high",
            source="disputes_by_id.jurors",
        )

    return sorted(notices.values(), key=lambda item: (-int(item["height"]), item["id"]))


@router.get("/activity/notices")
def activity_notices(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = None,
) -> Json:
    """Authenticated personalized projection of publicly inspectable facts.

    Unauthenticated clients retain a discoverable public route/type contract,
    but do not receive notices personalized to a claimed account.
    """
    base: Json = {
        "ok": True,
        "public_only": True,
        "source": "public_protocol_events",
        "notice_types": list(NOTICE_TYPES),
        "items": [],
        "next_cursor": None,
        "authenticated": False,
    }
    if not (
        _text(request.headers.get("x-weall-account"))
        or _text(request.headers.get("x-weall-session-key"))
    ):
        return base

    state = _snapshot(request)
    try:
        account = require_account_session(request, state)
    except PermissionError as error:
        raise HTTPException(
            status_code=401, detail={"code": "invalid_session", "reason": str(error)}
        ) from error

    all_notices = collect_public_activity_notices(state, account)
    if cursor:
        cursor_index = next((i for i, item in enumerate(all_notices) if item["id"] == cursor), None)
        if cursor_index is None:
            raise HTTPException(status_code=400, detail={"code": "invalid_notice_cursor"})
        all_notices = all_notices[cursor_index + 1 :]

    page = all_notices[:limit]
    base.update(
        {
            "authenticated": True,
            "account_id": account,
            "chain_id": _text(state.get("chain_id")),
            "genesis_id": _text(state.get("genesis_hash") or state.get("genesis_id")),
            "items": page,
            "next_cursor": page[-1]["id"] if len(all_notices) > limit else None,
        }
    )
    return base
