from weall.api.routes_public_parts.accounts import _iter_posts_by_author
from weall.api.routes_public_parts.content import _content_target_hidden_by_review
from weall.api.routes_public_parts.disputes import _redact_dispute_detail_for_viewer
from weall.api.routes_public_parts.groups import _iter_group_posts


def _state_with_upheld_review(stage="juror_review"):
    target_id = "post:@errol:13"
    return {
        "content": {
            "posts": {
                target_id: {
                    "id": target_id,
                    "post_id": target_id,
                    "author": "@errol",
                    "body": "post 1",
                    "visibility": "public",
                    "group_id": "",
                    "created_nonce": 13,
                },
                "post:@errol:14": {
                    "id": "post:@errol:14",
                    "post_id": "post:@errol:14",
                    "author": "@errol",
                    "body": "post 2",
                    "visibility": "public",
                    "created_nonce": 14,
                },
                "post:@errol:15": {
                    "id": "post:@errol:15",
                    "post_id": "post:@errol:15",
                    "author": "@errol",
                    "body": "group post",
                    "visibility": "group",
                    "group_id": "test",
                    "tags": ["group:test"],
                    "created_nonce": 15,
                },
            },
            "moderation": {"targets": {}},
        },
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "target_type": "content",
                "target_id": target_id,
                "stage": stage,
                "required_votes": 1,
                "eligible_validator_count": 1,
                "opened_by": "SYSTEM",
                "jurors": {"@devnet-genesis": {"status": "accepted", "attendance": {"present": True}}},
                "votes": {"@devnet-genesis": {"vote": "yes", "at_nonce": 37}},
            }
        },
        "disputes_by_target": {f"content:{target_id}": "dispute:SYSTEM:0"},
    }


def test_upheld_review_hides_from_account_feed_even_before_resolution_stage():
    st = _state_with_upheld_review(stage="juror_review")

    assert _content_target_hidden_by_review(st, "post:@errol:13", st["content"]["posts"]["post:@errol:13"])
    rows = _iter_posts_by_author(st, author="@errol")
    ids = {row.get("id") or row.get("post_id") for row in rows}
    assert "post:@errol:13" not in ids
    assert "post:@errol:14" in ids


def test_upheld_review_hides_group_target_before_final_receipt():
    st = _state_with_upheld_review(stage="review")
    group_post = st["content"]["posts"]["post:@errol:15"]
    st["disputes_by_id"]["dispute:SYSTEM:0"]["target_id"] = "post:@errol:15"
    st["disputes_by_target"] = {"content:post:@errol:15": "dispute:SYSTEM:0"}

    assert _content_target_hidden_by_review(st, "post:@errol:15", group_post)
    rows = _iter_group_posts(st, group_id="test")
    ids = {row.get("id") or row.get("post_id") for row in rows}
    assert "post:@errol:15" not in ids


def test_redacted_dispute_detail_exposes_only_viewer_vote_for_current_user():
    st = _state_with_upheld_review(stage="juror_review")
    dispute = st["disputes_by_id"]["dispute:SYSTEM:0"]

    redacted = _redact_dispute_detail_for_viewer(dispute, viewer="@devnet-genesis", st=st)

    assert redacted["votes_redacted"] is True
    assert "votes" not in redacted
    assert redacted["viewer_vote"]["vote"] == "yes"
    assert redacted["current_vote"]["vote"] == "yes"
    assert redacted["vote_counts"]["yes"] == 1
