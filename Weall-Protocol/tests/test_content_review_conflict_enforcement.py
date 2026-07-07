from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _base_state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "@genesis": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@errol": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@reviewer": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "validators": {"active_set": ["@genesis"]},
            "jurors": {"active_set": ["@reviewer"], "by_id": {"@reviewer": {"active": True, "enrolled": True}}},
        },
        "params": {
            "bootstrap_operator": "@genesis",
            "genesis_bootstrap_account": "@genesis",
        },
        "system_queue": [],
        "content": {
            "posts": {
                "post:@genesis:1": {
                    "post_id": "post:@genesis:1",
                    "id": "post:@genesis:1",
                    "author": "@genesis",
                    "body": "flag me",
                    "created_nonce": 1,
                    "visibility": "public",
                    "locked": False,
                    "labels": [],
                    "deleted": False,
                }
            },
            "comments": {},
            "reactions": {},
            "flags": {},
            "moderation": {"receipts": [], "targets": {}},
        },
    }


def test_content_flag_excludes_original_poster_from_assignment_and_uses_unconflicted_reviewer() -> None:
    idx = _load_index()
    st = _base_state()

    apply_tx(st, _env("CONTENT_FLAG", "@errol", 1, {"target_id": "post:@genesis:1", "reason": "policy"}))
    emitted = system_tx_emitter(st, canon=idx, next_height=1, phase="post")
    assert [env.tx_type for env in emitted] == ["CONTENT_ESCALATE_TO_DISPUTE"]
    for env in emitted:
        apply_tx(st, env)

    dispute = next(iter(st["disputes_by_id"].values()))
    assert dispute["target_owner"] == "@genesis"
    assert dispute["flagged_by"] == "@errol"
    assert "@genesis" not in dispute.get("assigned_jurors", [])
    assert dispute.get("conflict_policy") == "target_owner_excluded_from_content_review"
    assert dispute["assigned_jurors"] == ["@reviewer"]


def test_original_poster_cannot_be_assigned_or_vote_on_own_content_report() -> None:
    st = _base_state()
    apply_tx(st, _env("DISPUTE_OPEN", "@errol", 1, {"dispute_id": "d-own", "target_type": "content", "target_id": "post:@genesis:1", "reason": "policy"}))

    with pytest.raises(Exception) as assign_error:
        apply_tx(st, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 2, {"dispute_id": "d-own", "juror": "@genesis"}, system=True, parent="test"))
    assert "juror_conflict_target_owner" in str(assign_error.value)

    dispute = st["disputes_by_id"]["d-own"]
    dispute["jurors"]["@genesis"] = {"status": "accepted", "attendance": {"present": True}}
    dispute["assigned_jurors"] = ["@genesis"]
    dispute["eligible_juror_ids"] = ["@genesis"]
    dispute["required_votes"] = 1

    with pytest.raises(Exception) as vote_error:
        apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "@genesis", 3, {"dispute_id": "d-own", "vote": "yes"}))
    assert "juror_conflict_target_owner" in str(vote_error.value)


def test_unconflicted_remove_vote_applies_content_removal() -> None:
    st = _base_state()
    apply_tx(st, _env("DISPUTE_OPEN", "@errol", 1, {"dispute_id": "d-remove", "target_type": "content", "target_id": "post:@genesis:1", "reason": "policy"}))
    apply_tx(st, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 2, {"dispute_id": "d-remove", "juror": "@reviewer"}, system=True, parent="test"))
    apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "@reviewer", 3, {"dispute_id": "d-remove"}))
    apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "@reviewer", 4, {"dispute_id": "d-remove", "vote": "yes", "resolution": {"outcome": "report_upheld", "actions": []}}))

    dispute = st["disputes_by_id"]["d-remove"]
    post = st["content"]["posts"]["post:@genesis:1"]
    assert dispute["resolution"]["outcome"] == "report_upheld"
    assert post["visibility"] == "deleted"
    assert post["deleted"] is True
    assert post["locked"] is True
