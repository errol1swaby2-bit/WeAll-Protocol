from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


class _FakeExecutor:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def _auth(account: str) -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": f"sk:{account}"}


def _env(tx_type: str, payload: dict[str, Any], signer: str = "@author", nonce: int = 1, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig", system=system, parent="parent" if system else None)


def _state() -> dict[str, Any]:
    return {
        "chain_id": "batch447",
        "height": 10,
        "finalized_height": 10,
        "meta": {"constitutional_clock": {"enabled": True}},
        "accounts": {
            "@author": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@author": {"active": True}}},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@reviewer": {"active": True}}},
            "@member": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@member": {"active": True}}},
        },
        "groups_by_id": {"g1": {"id": "g1", "visibility": "public", "members": {"@member": {"role": "member"}, "@author": {"role": "member"}}}},
        "roles": {"groups_by_id": {"g1": {"id": "g1", "members": {"@member": {"role": "member"}, "@author": {"role": "member"}}}}},
        "content": {
            "posts": {
                "post:1": {"post_id": "post:1", "author": "@author", "body": "group post", "visibility": "group", "group_id": "g1", "created_nonce": 1, "deleted": False},
                "post:2": {"post_id": "post:2", "author": "@author", "body": "removed post", "visibility": "public", "created_nonce": 2, "deleted": False},
            },
            "comments": {},
            "reactions": {},
            "media": {},
            "moderation": {"targets": {"post:2": {"target_id": "post:2", "visibility": "deleted", "deleted": True, "last_action": "delete"}}},
        },
    }


def test_group_feed_surfaces_group_scoped_posts_and_hides_removed_content() -> None:
    with _client(_state()) as client:
        res = client.get("/v1/groups/g1/feed", headers=_auth("@member"))
        assert res.status_code == 200, res.text
        ids = [item.get("post_id") for item in res.json()["items"]]
        assert "post:1" in ids
        assert "post:2" not in ids

        public = client.get("/v1/feed")
        assert public.status_code == 200, public.text
        public_ids = [item.get("post_id") for item in public.json()["items"]]
        assert "post:1" not in public_ids
        assert "post:2" not in public_ids


def test_content_read_paths_hide_moderation_deleted_posts_even_if_post_flag_not_synced() -> None:
    with _client(_state()) as client:
        assert client.get("/v1/content/post:2").status_code == 404
        assert client.get("/v1/content/post:2/scoped", headers=_auth("@author")).status_code == 404


def test_content_creator_can_appeal_but_reviewer_cannot() -> None:
    st = _state()
    dispute = apply_dispute(st, _env("DISPUTE_OPEN", {"dispute_id": "d1", "target_type": "content", "target_id": "post:2", "reason": "flagged"}, signer="@reviewer", nonce=1))
    assert dispute and dispute["dispute_id"] == "d1"
    assert st["disputes_by_id"]["d1"]["target_owner"] == "@author"

    apply_dispute(st, _env("DISPUTE_RESOLVE", {"dispute_id": "d1", "resolution": {"actions": [{"tx_type": "CONTENT_VISIBILITY_SET", "payload": {"target_id": "post:2", "visibility": "deleted"}}]}, "_due_height": 11}, signer="SYSTEM", nonce=2, system=True))
    assert st["disputes_by_id"]["d1"]["stage"] == "appeal_window"
    assert st["content"]["posts"]["post:2"].get("deleted") is False
    assert st["disputes_by_id"]["d1"]["resolution"]["actions"][0]["payload"]["visibility"] == "hidden"
    assert st["disputes_by_id"]["d1"]["resolution"]["appeal_quarantine"]["content_record_retained"] is True

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("DISPUTE_APPEAL", {"dispute_id": "d1", "reason": "I reviewed this"}, signer="@reviewer", nonce=3))
    assert exc.value.reason == "appeal_not_target_owner"

    apply_tx(st, _env("DISPUTE_APPEAL", {"dispute_id": "d1", "reason": "I created this content"}, signer="@author", nonce=4))
    assert st["disputes_by_id"]["d1"]["stage"] == "appealed"
    assert st["disputes_by_id"]["d1"]["appeals"][-1]["by"] == "@author"


def test_dispute_detail_api_exposes_creator_only_appeal_eligibility() -> None:
    st = _state()
    st["disputes_by_id"] = {
        "d1": {
            "id": "d1",
            "stage": "appeal_window",
            "target_type": "content",
            "target_id": "post:2",
            "target_owner": "@author",
            "appeal_allowed_accounts": ["@author"],
            "appeals": [],
            "jurors": {},
            "votes": {},
            "evidence": [],
        }
    }
    with _client(st) as client:
        author = client.get("/v1/disputes/d1", headers=_auth("@author")).json()["dispute"]["appeal_eligibility"]
        reviewer = client.get("/v1/disputes/d1", headers=_auth("@reviewer")).json()["dispute"]["appeal_eligibility"]
        assert author["can_file"] is True
        assert reviewer["can_file"] is False
        assert reviewer["reason"] == "not_target_owner"
