from __future__ import annotations

from pathlib import Path

from weall.api.routes_public_parts.accounts import _iter_posts_by_author
from weall.api.routes_public_parts.content import _content_target_hidden_by_review, _post_visible
from weall.api.routes_public_parts.groups import _iter_group_posts

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def _state_with_removed_group_post() -> dict:
    post = {
        "id": "post:@errol:12",
        "post_id": "post:@errol:12",
        "author": "@errol",
        "body": "removed group post",
        "visibility": "group",
        "group_id": "g:test",
        "created_nonce": 12,
        "created_at_nonce": 12,
        "deleted": False,
    }
    return {
        "content": {"posts": {"post:@errol:12": post}, "comments": {}, "moderation": {"targets": {}}},
        "disputes_by_id": {
            "d1": {
                "dispute_id": "d1",
                "stage": "appeal_window",
                "target_type": "content",
                "target_id": "post:@errol:12",
                "resolution": {
                    "outcome": "report_upheld",
                    "actions": [
                        {
                            "tx_type": "CONTENT_VISIBILITY_SET",
                            "payload": {"target_id": "post:@errol:12", "visibility": "deleted"},
                        }
                    ],
                },
            }
        },
    }


def test_batch449_removed_content_is_hidden_from_author_and_group_feeds_before_final_receipt() -> None:
    st = _state_with_removed_group_post()
    post = st["content"]["posts"]["post:@errol:12"]

    assert _content_target_hidden_by_review(st, "post:@errol:12", post)
    assert not _post_visible(st, post, "post:@errol:12")
    assert _iter_posts_by_author(st, author="@errol") == []
    assert _iter_group_posts(st, group_id="g:test") == []


def test_batch449_group_post_detail_uses_scoped_content_read_when_signed_in() -> None:
    text = (WEB / "src/pages/Content.tsx").read_text(encoding="utf-8")
    assert "getAuthHeaders" in text
    assert "weall.contentScoped(routeContentId, base, headers)" in text
    assert "weall.content(routeContentId, base)" in text



def test_batch449_removed_communication_key_autopublish_surface_stays_removed() -> None:
    assert not (WEB / "src" / "pages" / ("Mess" + "aging.tsx")).exists()
    assert not (WEB / "src" / "components" / ("Mess" + "agingKeyBootstrapper.tsx")).exists()


def test_batch449_center_flow_cannot_overflow_into_protocol_side_panel() -> None:
    css = (WEB / "src/styles.css").read_text(encoding="utf-8")
    assert "Batch 449: keep dense action/detail content inside the center column" in css
    assert ".appShellContent {\n  overflow-x: clip;" in css
    assert ".p2pVideoGrid" in css and "repeat(auto-fit, minmax(220px, 1fr))" in css
    assert "@media (max-width: 1320px)" in css
