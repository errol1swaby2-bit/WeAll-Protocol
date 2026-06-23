from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter()

Json = dict[str, Any]

_PRIVATE_MESSAGING_ERROR: Json = {
    "code": "PRIVATE_MESSAGING_UNSUPPORTED",
    "message": (
        "Protocol-native private/direct messaging is unsupported. "
        "Use the public activity/notification model derived from public protocol events."
    ),
    "public_only": True,
}


def _unsupported() -> None:
    raise HTTPException(status_code=410, detail=dict(_PRIVATE_MESSAGING_ERROR))


@router.get("/messages/threads")
def message_threads() -> Json:
    """Compatibility stub: private/direct thread reads are hard-disabled."""

    _unsupported()


@router.get("/messages/threads/{thread_id:path}")
def message_thread(thread_id: str) -> Json:
    """Compatibility stub: private/direct thread detail reads are hard-disabled."""

    _unsupported()


@router.get("/activity/inbox")
def activity_inbox() -> Json:
    """Return the public-only notification inbox contract.

    The frontend currently derives notices from public state snapshots and public
    event surfaces (mentions, replies, group invitations, moderation notices,
    dispute assignments, governance notices, and validator/operator alerts).  A
    node may later materialize this index, but it must never contain private
    user-to-user messages or encrypted protocol-native payloads.
    """

    return {
        "ok": True,
        "public_only": True,
        "source": "public_protocol_events",
        "items": [],
        "notice_types": [
            "mention",
            "reply",
            "group_invitation",
            "moderation_notice",
            "dispute_assignment",
            "governance_notice",
            "validator_operator_alert",
        ],
    }
