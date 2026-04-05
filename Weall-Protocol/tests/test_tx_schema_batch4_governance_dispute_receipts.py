from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.tx_schema import model_for_tx_type, validate_tx_envelope


BASE_ENV = {
    "signer": "alice",
    "nonce": 1,
    "sig": "deadbeef",
    "payload": {},
}


def _env(tx_type: str, payload: dict) -> dict:
    env = dict(BASE_ENV)
    env["tx_type"] = tx_type
    env["payload"] = payload
    return env


def test_batch4_schema_models_registered() -> None:
    expected = {
        "GOV_PROPOSAL_EDIT",
        "GOV_PROPOSAL_WITHDRAW",
        "GOV_STAGE_SET",
        "GOV_QUORUM_SET",
        "GOV_RULES_SET",
        "GOV_EXECUTE",
        "GOV_EXECUTION_RECEIPT",
        "PROTOCOL_UPGRADE_DECLARE",
        "PROTOCOL_UPGRADE_ACTIVATE",
        "GOV_VOTE_REVOKE",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_PROPOSAL_FINALIZE",
        "GOV_PROPOSAL_RECEIPT",
        "DISPUTE_STAGE_SET",
        "DISPUTE_JUROR_ATTENDANCE",
        "DISPUTE_RESOLVE",
        "DISPUTE_APPEAL",
        "DISPUTE_FINAL_RECEIPT",
        "CASE_TYPE_REGISTER",
        "CASE_BIND_TO_DISPUTE",
        "CASE_OUTCOME_RECEIPT",
        "MOD_ACTION_RECEIPT",
        "FLAG_ESCALATION_RECEIPT",
    }
    missing = {name for name in expected if model_for_tx_type(name) is None}
    assert not missing


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("GOV_PROPOSAL_EDIT", {"proposal_id": "p1", "title": "Updated", "actions": [{"tx_type": "GOV_RULES_SET", "payload": {"params": {}}}], "_due_height": 10}),
        ("GOV_PROPOSAL_WITHDRAW", {"proposal_id": "p1"}),
        ("GOV_STAGE_SET", {"proposal_id": "p1", "stage": "poll", "poll_total_votes": 4}),
        ("GOV_QUORUM_SET", {"quorum_percent": 60}),
        ("GOV_QUORUM_SET", {"quorum_bps": 6000}),
        ("GOV_RULES_SET", {"params": {"gov": {"open": True}}, "treasury": {"timelock_blocks": 5}}),
        ("GOV_EXECUTE", {"proposal_id": "p1", "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_percent": 51}}], "_parent_ref": "parent-1"}),
        ("GOV_EXECUTION_RECEIPT", {"proposal_id": "p1", "ok": True}),
        ("PROTOCOL_UPGRADE_DECLARE", {"upgrade_id": "u1", "version": "2026.04-prod.1", "hash": "abc123"}),
        ("PROTOCOL_UPGRADE_DECLARE", {"id": "u1", "target_version": "2026.04-prod.1", "commit": "deadbeef"}),
        ("PROTOCOL_UPGRADE_ACTIVATE", {"proposal_id": "u1", "version": "2026.04-prod.1"}),
        ("GOV_VOTE_REVOKE", {"proposal_id": "p1"}),
        ("GOV_VOTING_CLOSE", {"proposal_id": "p1"}),
        ("GOV_TALLY_PUBLISH", {"proposal_id": "p1", "tally": {"yes": 4}, "total_votes": 4}),
        ("GOV_PROPOSAL_FINALIZE", {"proposal_id": "p1", "_parent_ref": "parent-1"}),
        ("GOV_PROPOSAL_RECEIPT", {"proposal_id": "p1", "finalized": True}),
        ("DISPUTE_STAGE_SET", {"dispute_id": "d1", "stage": "juror_review"}),
        ("DISPUTE_JUROR_ATTENDANCE", {"dispute_id": "d1", "present": True}),
        ("DISPUTE_RESOLVE", {"dispute_id": "d1", "resolution": {"outcome": "remove"}, "_due_height": 12}),
        ("DISPUTE_APPEAL", {"dispute_id": "d1", "reason": "new evidence", "basis": {"cid": "bafk-test"}}),
        ("DISPUTE_FINAL_RECEIPT", {"receipt_id": "r1", "dispute_id": "d1", "resolution": {"outcome": "remove"}}),
        ("DISPUTE_FINAL_RECEIPT", {"id": "r1"}),
        ("CASE_TYPE_REGISTER", {"case_type": "poh_review"}),
        ("CASE_TYPE_REGISTER", {"type": "poh_review"}),
        ("CASE_BIND_TO_DISPUTE", {"case_id": "c1", "dispute_id": "d1"}),
        ("CASE_BIND_TO_DISPUTE", {"id": "c1", "dispute_id": "d1"}),
        ("CASE_OUTCOME_RECEIPT", {"case_id": "c1", "outcome": {"approved": True}}),
        ("MOD_ACTION_RECEIPT", {"target_id": "post-1", "action": "hide", "labels": ["spam"]}),
        ("MOD_ACTION_RECEIPT", {"id": "post-1", "visibility": "hidden", "locked": True}),
        ("FLAG_ESCALATION_RECEIPT", {"target_id": "post-1", "dispute_id": "d1"}),
        ("DISPUTE_OPEN", {"dispute_id": "d1", "target_type": "content", "target_id": "post-1", "reason": "spam"}),
        ("DISPUTE_JUROR_ASSIGN", {"dispute_id": "d1", "juror": "bob"}),
        ("DISPUTE_EVIDENCE_DECLARE", {"dispute_id": "d1", "evidence_id": "e1", "kind": "video", "cid": "bafk-test"}),
        ("DISPUTE_EVIDENCE_BIND", {"dispute_id": "d1", "evidence_id": "e1"}),
        ("DISPUTE_VOTE_SUBMIT", {"dispute_id": "d1", "vote": "approve"}),
        ("DISPUTE_VOTE_SUBMIT", {"dispute_id": "d1", "verdict": "approve", "resolution": {"action": "remove"}}),
    ],
)
def test_batch4_valid_payloads_are_accepted(tx_type: str, payload: dict) -> None:
    env, parsed = validate_tx_envelope(_env(tx_type, payload))
    assert env.tx_type == tx_type
    assert parsed is not None


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_fragment"),
    [
        ("GOV_PROPOSAL_EDIT", {}, "proposal_id"),
        ("GOV_PROPOSAL_WITHDRAW", {}, "proposal_id"),
        ("GOV_STAGE_SET", {"proposal_id": "p1"}, "stage"),
        ("GOV_EXECUTE", {}, "proposal_id"),
        ("GOV_EXECUTION_RECEIPT", {}, "proposal_id"),
        ("GOV_VOTE_REVOKE", {}, "proposal_id"),
        ("GOV_VOTING_CLOSE", {}, "proposal_id"),
        ("GOV_TALLY_PUBLISH", {}, "proposal_id"),
        ("GOV_PROPOSAL_FINALIZE", {}, "proposal_id"),
        ("GOV_PROPOSAL_RECEIPT", {}, "proposal_id"),
        ("DISPUTE_STAGE_SET", {"dispute_id": "d1"}, "stage"),
        ("DISPUTE_JUROR_ATTENDANCE", {}, "dispute_id"),
        ("DISPUTE_RESOLVE", {}, "dispute_id"),
        ("DISPUTE_APPEAL", {}, "dispute_id"),
        ("CASE_TYPE_REGISTER", {}, "case_type"),
        ("CASE_BIND_TO_DISPUTE", {}, "dispute_id"),
        ("MOD_ACTION_RECEIPT", {}, "target_id"),
        ("FLAG_ESCALATION_RECEIPT", {"target_id": "post-1"}, "dispute_id"),
        ("DISPUTE_OPEN", {"dispute_id": "d1", "target_id": "post-1"}, "target_type"),
        ("DISPUTE_JUROR_ASSIGN", {"dispute_id": "d1"}, "juror_id"),
        ("DISPUTE_EVIDENCE_DECLARE", {"dispute_id": "d1"}, "evidence_id"),
        ("DISPUTE_VOTE_SUBMIT", {"dispute_id": "d1"}, "either vote or verdict is required"),
    ],
)
def test_batch4_missing_required_fields_are_rejected(tx_type: str, payload: dict, expected_fragment: str) -> None:
    with pytest.raises((ValidationError, ValueError)) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert expected_fragment in str(excinfo.value)


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("GOV_PROPOSAL_EDIT", {"proposal_id": "p1", "extra": True}),
        ("GOV_STAGE_SET", {"proposal_id": "p1", "stage": "poll", "extra": True}),
        ("GOV_QUORUM_SET", {"quorum_percent": 60, "extra": True}),
        ("GOV_RULES_SET", {"params": {}, "extra": True}),
        ("GOV_EXECUTE", {"proposal_id": "p1", "extra": True}),
        ("PROTOCOL_UPGRADE_DECLARE", {"upgrade_id": "u1", "extra": True}),
        ("DISPUTE_STAGE_SET", {"dispute_id": "d1", "stage": "open", "extra": True}),
        ("DISPUTE_RESOLVE", {"dispute_id": "d1", "resolution": {}, "extra": True}),
        ("CASE_TYPE_REGISTER", {"case_type": "poh_review", "extra": True}),
        ("MOD_ACTION_RECEIPT", {"target_id": "post-1", "extra": True}),
        ("FLAG_ESCALATION_RECEIPT", {"target_id": "post-1", "dispute_id": "d1", "extra": True}),
    ],
)
def test_batch4_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
