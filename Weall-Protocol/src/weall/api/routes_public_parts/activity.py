from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()

Json = dict[str, Any]


@router.get("/activity/inbox")
def activity_inbox() -> Json:
    """Return public-event-derived activity notices.

    This route is a public read model for visible protocol activity such as
    mentions, replies, group invitations, moderation notices, dispute
    assignments, governance notices, and validator/operator alerts.
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
