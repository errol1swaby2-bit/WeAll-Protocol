from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, payload: dict, signer: str, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig")


def _state() -> dict:
    return {
        "chain_id": "test",
        "height": 1,
        "tip": "d" * 64,
        "accounts": {
            "owner": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10000, "banned": False, "locked": False},
            "member": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10000, "banned": False, "locked": False},
            "outsider": {"nonce": 0, "poh_tier": 2, "reputation_milli": 10000, "banned": False, "locked": False},
        },
        "roles": {
            "groups_by_id": {
                "g1": {
                    "group_id": "g1",
                    "created_by": "owner",
                    "members": {
                        "owner": {"role": "creator"},
                        "member": {"role": "member"},
                    },
                    "signers": ["owner"],
                    "roles": {"posters": ["member"]},
                }
            }
        },
        "content": {"posts": {}, "comments": {}, "reactions": {}, "flags": {}, "media": {}, "receipts": {}},
    }


def test_group_post_requires_membership_or_posting_role() -> None:
    st = _state()

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "CONTENT_POST_CREATE",
                {
                    "post_id": "p1",
                    "body": "unauthorized group post",
                    "visibility": "group",
                    "group_id": "g1",
                },
                signer="outsider",
            ),
        )

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "group_post_authority_required"
    assert "p1" not in st["content"]["posts"]


def test_group_member_can_create_group_scoped_post() -> None:
    st = _state()

    meta = apply_tx(
        st,
        _env(
            "CONTENT_POST_CREATE",
            {
                "post_id": "p2",
                "body": "authorized group post",
                "visibility": "group",
                "group_id": "g1",
                "tags": ["group:g1", "welcome"],
            },
            signer="member",
        ),
    )

    assert meta["applied"] == "CONTENT_POST_CREATE"
    assert st["content"]["posts"]["p2"]["group_id"] == "g1"
    assert st["content"]["posts"]["p2"]["visibility"] == "group"
    assert st["content"]["posts"]["p2"]["tags"] == ["group:g1", "welcome"]


def test_group_tag_spoofing_is_rejected_without_group_authority() -> None:
    st = _state()

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "CONTENT_POST_CREATE",
                {
                    "post_id": "p3",
                    "body": "spoofed tag",
                    "visibility": "public",
                    "tags": ["group:g1"],
                },
                signer="outsider",
            ),
        )

    assert ei.value.reason == "group_post_authority_required"
    assert "p3" not in st["content"]["posts"]


def test_group_id_requires_group_visibility() -> None:
    st = _state()

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "CONTENT_POST_CREATE",
                {
                    "post_id": "p4",
                    "body": "bad payload",
                    "visibility": "public",
                    "group_id": "g1",
                },
                signer="member",
            ),
        )

    assert ei.value.reason == "group_id_requires_group_visibility"


def test_post_edit_cannot_move_post_into_group_without_authority() -> None:
    st = _state()

    apply_tx(
        st,
        _env(
            "CONTENT_POST_CREATE",
            {"post_id": "p5", "body": "public post", "visibility": "public"},
            signer="outsider",
            nonce=1,
        ),
    )

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "CONTENT_POST_EDIT",
                {
                    "post_id": "p5",
                    "visibility": "group",
                    "group_id": "g1",
                    "tags": ["group:g1"],
                },
                signer="outsider",
                nonce=2,
            ),
        )

    assert ei.value.reason == "group_post_authority_required"
    assert st["content"]["posts"]["p5"].get("group_id") in (None, "")
