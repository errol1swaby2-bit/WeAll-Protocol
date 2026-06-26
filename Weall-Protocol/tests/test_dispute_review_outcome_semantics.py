from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _base_state() -> dict:
    return {
        "height": 0,
        "time": 0,
        "params": {"system_signer": "SYSTEM", "economics_enabled": True, "economic_unlock_time": 0},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "juror": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["juror"]}},
        "system_queue": [],
        "content": {
            "posts": {"post:alice:1": {"id": "post:alice:1", "post_id": "post:alice:1", "author": "alice", "body": "flagged", "visibility": "public"}},
            "comments": {},
            "reactions": {},
            "flags": {},
            "media": {},
            "media_bindings": {},
            "moderation": {"receipts": [], "targets": {}},
        },
    }


def _open_accept_vote(st: dict, *, vote: str, resolution: dict | None = None) -> None:
    apply_tx(st, _env("DISPUTE_OPEN", "alice", 1, {"dispute_id": "d1", "target_type": "content", "target_id": "post:alice:1", "reason": "test"}))
    apply_tx(st, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d1", "juror": "juror"}, system=True, parent="tx:alice:1"))
    apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "juror", 2, {"dispute_id": "d1"}))
    payload = {"dispute_id": "d1", "vote": vote}
    if resolution is not None:
        payload["resolution"] = resolution
    apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "juror", 3, payload))


def test_remove_post_vote_upholds_report_and_deletes_content_batch278() -> None:
    st = _base_state()
    _open_accept_vote(st, vote="yes", resolution={"summary": "client remove choice without explicit actions", "actions": []})

    dispute = st["disputes_by_id"]["d1"]
    post = st["content"]["posts"]["post:alice:1"]

    assert dispute["resolved"] is True
    assert dispute["stage"] == "resolved"
    assert dispute["resolution"]["outcome"] == "report_upheld"
    assert dispute["resolution"]["tally"] == {"yes": 1, "no": 0, "abstain": 0}
    assert post["visibility"] == "deleted"
    assert post["deleted"] is True
    assert post["locked"] is True


def test_keep_post_vote_does_not_delete_content_batch278() -> None:
    st = _base_state()
    _open_accept_vote(st, vote="no", resolution={"summary": "client keep choice", "actions": [{"tx_type": "CONTENT_VISIBILITY_SET", "payload": {"target_id": "post:alice:1", "visibility": "deleted"}}]})

    dispute = st["disputes_by_id"]["d1"]
    post = st["content"]["posts"]["post:alice:1"]

    assert dispute["resolved"] is True
    assert dispute["stage"] == "resolved"
    assert dispute["resolution"]["outcome"] == "report_not_upheld"
    assert dispute["resolution"]["tally"] == {"yes": 0, "no": 1, "abstain": 0}
    assert dispute["resolution"].get("actions") == []
    assert post["visibility"] == "public"
    assert post.get("deleted") is not True


def test_frontend_review_labels_match_backend_vote_semantics_batch278() -> None:
    root = Path(__file__).resolve().parents[1]
    language = (root.parent / "web" / "src" / "lib" / "userLanguage.ts").read_text(encoding="utf-8")
    review = (root.parent / "web" / "src" / "pages" / "DisputeReview.tsx").read_text(encoding="utf-8")

    assert 'choice === "yes" || choice === "remove" || choice === "report_upheld") return "Remove Post"' in language
    assert 'choice === "no" || choice === "keep" || choice === "report_not_upheld") return "Keep Post"' in language
    assert "Remove ${Number(c.yes || 0)}" in language
    assert "Keep ${Number(c.no || 0)}" in language
    assert 'vote: "no", resolution: { outcome: "report_not_upheld"' in review
    assert 'vote: "yes", resolution: { outcome: "report_upheld"' in review
    assert 'CONTENT_VISIBILITY_SET' in review and 'visibility: "deleted"' in review
