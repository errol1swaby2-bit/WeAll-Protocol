from __future__ import annotations

from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json
from pathlib import Path


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _base_state() -> dict:
    return {
        "height": 0,
        "time": 0,
        "params": {"system_signer": "SYSTEM", "economics_enabled": True, "economic_unlock_time": 0},
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False},
            "bob": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["alice"]}},
        "system_queue": [],
    }


def test_governance_vote_auto_progresses_from_active_validator_threshold_batch205() -> None:
    st = _base_state()

    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p1", "title": "t", "rules": {"start_stage": "voting"}}))
    apply_tx(st, _env("GOV_VOTE_CAST", "alice", 2, {"proposal_id": "p1", "vote": "yes"}))

    pr = st["gov_proposals_by_id"]["p1"]
    assert pr["stage"] == "finalized"
    latest_tally = pr["tallies"][-1]["payload"]
    assert latest_tally["eligible_validator_count"] == 1
    assert latest_tally["required_votes"] == 1
    assert latest_tally["yes"] == 1
    assert latest_tally["passed"] is True


def test_dispute_vote_auto_resolves_from_active_validator_threshold_batch205() -> None:
    st = _base_state()

    apply_tx(st, _env("DISPUTE_OPEN", "alice", 1, {"dispute_id": "d1", "target_type": "content", "target_id": "c1", "reason": "test"}))
    apply_tx(st, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d1", "juror": "alice"}, system=True, parent="tx:alice:1"))
    apply_tx(st, _env("DISPUTE_JUROR_ACCEPT", "alice", 2, {"dispute_id": "d1"}))
    apply_tx(st, _env("DISPUTE_VOTE_SUBMIT", "alice", 3, {"dispute_id": "d1", "vote": "yes", "resolution": {"summary": "remove content"}}))

    dispute = st["disputes_by_id"]["d1"]
    assert dispute["stage"] == "resolved"
    assert dispute["resolved"] is True
    assert dispute["resolution"]["eligible_validator_count"] == 1
    assert dispute["resolution"]["required_votes"] == 1
    assert dispute["resolution"]["total_votes"] == 1
    assert dispute["resolution"]["tally"]["yes"] == 1


def test_governance_poll_vote_auto_progresses_immediately_batch205() -> None:
    st = _base_state()

    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p2", "title": "t", "rules": {"start_stage": "poll"}}))
    apply_tx(st, _env("GOV_VOTE_CAST", "alice", 2, {"proposal_id": "p2", "vote": "yes"}))

    pr = st["gov_proposals_by_id"]["p2"]
    assert pr["stage"] == "finalized"
    latest_tally = pr["tallies"][-1]["payload"]
    assert latest_tally["vote_window"] == "poll"
    assert latest_tally["required_votes"] == 1


def test_content_flag_escalation_assigns_active_validators_immediately_batch205() -> None:
    st = _base_state()
    st["content"] = {
        "posts": {"post:alice:1": {"id": "post:alice:1", "author": "alice", "body": "x"}},
        "comments": {},
        "reactions": {},
        "flags": {},
        "media": {},
        "media_bindings": {},
        "moderation": {"receipts": [], "targets": {}},
    }

    apply_tx(st, _env("CONTENT_ESCALATE_TO_DISPUTE", "SYSTEM", 5, {"target_type": "content", "target_id": "post:alice:1", "reason": "test"}, system=True, parent="tx:alice:5"))

    disputes = st["disputes_by_id"]
    dispute = disputes[sorted(disputes.keys())[0]]
    assert dispute["stage"] == "juror_review"
    assert "alice" in dispute["jurors"]
    assert dispute["jurors"]["alice"]["status"] == "assigned"


def test_governance_vote_progresses_when_validator_id_uses_account_alias_batch205() -> None:
    st = _base_state()
    st["accounts"] = {"@alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False}}
    st["roles"] = {"validators": {"active_set": ["alice"]}}

    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "@alice", 1, {"proposal_id": "p3", "title": "t", "rules": {"start_stage": "poll"}}))
    apply_tx(st, _env("GOV_VOTE_CAST", "@alice", 2, {"proposal_id": "p3", "vote": "yes"}))

    pr = st["gov_proposals_by_id"]["p3"]
    assert pr["stage"] == "finalized"
    assert "@alice" in pr["poll_votes"]


def test_content_escalation_assigns_canonical_account_identity_batch205() -> None:
    st = _base_state()
    st["accounts"] = {"@alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False}}
    st["roles"] = {"validators": {"active_set": ["alice"]}}
    st["content"] = {
        "posts": {"post:@alice:1": {"id": "post:@alice:1", "author": "@alice", "body": "x"}},
        "comments": {},
        "reactions": {},
        "flags": {},
        "media": {},
        "media_bindings": {},
        "moderation": {"receipts": [], "targets": {}},
    }

    apply_tx(st, _env("CONTENT_ESCALATE_TO_DISPUTE", "SYSTEM", 5, {"target_type": "content", "target_id": "post:@alice:1", "reason": "test"}, system=True, parent="tx:@alice:5"))

    disputes = st["disputes_by_id"]
    dispute = disputes[sorted(disputes.keys())[0]]
    assert dispute["stage"] == "juror_review"
    assert "@alice" in dispute["jurors"]
    assert dispute["jurors"]["@alice"]["status"] == "assigned"


def test_governance_live_created_proposal_falls_back_to_creator_threshold_batch205() -> None:
    st = _base_state()
    st["roles"] = {"validators": {"active_set": []}}

    apply_tx(st, _env("GOV_PROPOSAL_CREATE", "alice", 1, {"proposal_id": "p4", "title": "t", "rules": {"start_stage": "poll"}}))
    apply_tx(st, _env("GOV_VOTE_CAST", "alice", 2, {"proposal_id": "p4", "vote": "yes"}))

    pr = st["gov_proposals_by_id"]["p4"]
    assert pr["eligible_validator_ids"] == ["alice"]
    assert pr["required_votes"] == 1
    assert pr["stage"] == "finalized"


def test_content_escalation_falls_back_to_opening_account_for_review_batch205() -> None:
    st = _base_state()
    st["roles"] = {"validators": {"active_set": []}}
    st["content"] = {
        "posts": {"post:alice:1": {"id": "post:alice:1", "author": "alice", "body": "x"}},
        "comments": {},
        "reactions": {},
        "flags": {},
        "media": {},
        "media_bindings": {},
        "moderation": {"receipts": [], "targets": {}},
    }

    apply_tx(st, _env("CONTENT_ESCALATE_TO_DISPUTE", "SYSTEM", 5, {"target_type": "content", "target_id": "post:alice:1", "reason": "test"}, system=True, parent="tx:alice:5"))

    disputes = st["disputes_by_id"]
    dispute = disputes[sorted(disputes.keys())[0]]
    assert dispute["stage"] == "juror_review"
    assert dispute["eligible_juror_ids"] == ["alice"]
    assert dispute["jurors"]["alice"]["status"] == "assigned"
