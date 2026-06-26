from __future__ import annotations

from weall.api.routes_public_parts.accounts import _iter_posts_by_author
from weall.api.routes_public_parts.content import _content_target_hidden_by_review, _post_visible
from weall.api.routes_public_parts.groups import _iter_group_posts


def _state_with_group_post_and_upheld_vote() -> dict:
    post = {
        "id": "post:@errol:16",
        "post_id": "post:@errol:16",
        "author": "@errol",
        "body": "reported group post",
        "visibility": "group",
        "group_id": "g:test",
        "created_nonce": 16,
        "created_at_nonce": 16,
    }
    return {
        "height": 42,
        "content": {"posts": {"post:@errol:16": post}, "moderation": {"targets": {}}},
        "groups": {"by_id": {"g:test": {"id": "g:test", "visibility": "public"}}},
        "group_roles": {"by_id": {"g:test": {"members": {"@errol": {}, "@devnet-genesis": {}}}}},
        "disputes_by_target": {"content:post:@errol:16": "dispute:SYSTEM:0"},
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "stage": "appeal_window",
                "target_type": "content",
                "target_id": "post:@errol:16",
                "required_votes": 1,
                "votes": {"@devnet-genesis": {"vote": "yes", "at_nonce": 20}},
                "resolution": None,
            }
        },
    }


def test_upheld_review_hides_content_before_final_receipt() -> None:
    st = _state_with_group_post_and_upheld_vote()
    post = st["content"]["posts"]["post:@errol:16"]

    assert _content_target_hidden_by_review(st, "post:@errol:16", post) is True
    assert _post_visible(st, post, "post:@errol:16") is False
    assert _iter_posts_by_author(st, author="@errol") == []
    assert _iter_group_posts(st, group_id="g:test") == []


def test_non_upheld_review_keeps_content_visible() -> None:
    st = _state_with_group_post_and_upheld_vote()
    dispute = st["disputes_by_id"]["dispute:SYSTEM:0"]
    dispute["votes"] = {"@devnet-genesis": {"vote": "no", "at_nonce": 20}}
    dispute["resolution"] = {"outcome": "report_not_upheld", "actions": []}

    post = st["content"]["posts"]["post:@errol:16"]
    assert _content_target_hidden_by_review(st, "post:@errol:16", post) is False
    assert _iter_posts_by_author(st, author="@errol")
    assert _iter_group_posts(st, group_id="g:test")
