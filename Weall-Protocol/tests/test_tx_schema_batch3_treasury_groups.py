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


def test_batch3_schema_models_registered() -> None:
    expected = {
        "TREASURY_CREATE",
        "TREASURY_SIGNERS_SET",
        "TREASURY_WALLET_CREATE",
        "TREASURY_SIGNER_ADD",
        "TREASURY_SIGNER_REMOVE",
        "TREASURY_POLICY_SET",
        "TREASURY_SPEND_PROPOSE",
        "TREASURY_SPEND_SIGN",
        "TREASURY_SPEND_CANCEL",
        "TREASURY_SPEND_EXPIRE",
        "TREASURY_SPEND_EXECUTE",
        "TREASURY_PROGRAM_CREATE",
        "TREASURY_PROGRAM_UPDATE",
        "TREASURY_PROGRAM_CLOSE",
        "TREASURY_AUDIT_ANCHOR_SET",
        "GROUP_CREATE",
        "GROUP_UPDATE",
        "GROUP_ROLE_GRANT",
        "GROUP_ROLE_REVOKE",
        "GROUP_MEMBERSHIP_REQUEST",
        "GROUP_MEMBERSHIP_DECIDE",
        "GROUP_MEMBERSHIP_REMOVE",
        "GROUP_SIGNERS_SET",
        "GROUP_MODERATORS_SET",
        "GROUP_TREASURY_CREATE",
        "GROUP_TREASURY_POLICY_SET",
        "GROUP_TREASURY_SPEND_PROPOSE",
        "GROUP_TREASURY_SPEND_SIGN",
        "GROUP_TREASURY_SPEND_CANCEL",
        "GROUP_TREASURY_SPEND_EXPIRE",
        "GROUP_TREASURY_SPEND_EXECUTE",
        "GROUP_TREASURY_AUDIT_ANCHOR_SET",
        "GROUP_EMISSARY_ELECTION_CREATE",
        "GROUP_EMISSARY_BALLOT_CAST",
        "GROUP_EMISSARY_ELECTION_FINALIZE",
    }
    missing = {name for name in expected if model_for_tx_type(name) is None}
    assert not missing


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("TREASURY_CREATE", {"treasury_id": "treasury-1"}),
        ("TREASURY_CREATE", {"id": "treasury-1"}),
        ("TREASURY_SIGNERS_SET", {"treasury_id": "treasury-1", "signers": ["alice"], "threshold": 1}),
        ("TREASURY_SIGNERS_SET", {"id": "treasury-1", "signers": ["alice", "bob"]}),
        ("TREASURY_WALLET_CREATE", {"wallet_id": "wallet-1"}),
        ("TREASURY_WALLET_CREATE", {"id": "wallet-1", "meta": {"label": "ops"}}),
        ("TREASURY_SIGNER_ADD", {"wallet_id": "wallet-1", "signer": "alice"}),
        ("TREASURY_SIGNER_ADD", {"id": "wallet-1", "account": "alice"}),
        ("TREASURY_SIGNER_REMOVE", {"wallet_id": "wallet-1", "signer": "alice"}),
        ("TREASURY_SIGNER_REMOVE", {"treasury_id": "wallet-1", "account_id": "alice"}),
        ("TREASURY_POLICY_SET", {"policy": {"timelock_blocks": 10}}),
        ("TREASURY_SPEND_PROPOSE", {"treasury_id": "treasury-1", "spend_id": "spend-1", "to": "bob", "amount": 25}),
        ("TREASURY_SPEND_PROPOSE", {"wallet_id": "treasury-1", "spend_id": "spend-1", "to": "bob", "amount": 0, "memo": "test"}),
        ("TREASURY_SPEND_SIGN", {"treasury_id": "treasury-1", "spend_id": "spend-1"}),
        ("TREASURY_SPEND_CANCEL", {"id": "treasury-1", "spend_id": "spend-1"}),
        ("TREASURY_SPEND_EXPIRE", {"spend_id": "spend-1"}),
        ("TREASURY_SPEND_EXECUTE", {"spend_id": "spend-1"}),
        ("TREASURY_PROGRAM_CREATE", {"program_id": "program-1"}),
        ("TREASURY_PROGRAM_CREATE", {"id": "program-1", "config": {"label": "grants"}}),
        ("TREASURY_PROGRAM_UPDATE", {"program_id": "program-1", "patch": {"active": True}}),
        ("TREASURY_PROGRAM_CLOSE", {"id": "program-1"}),
        ("TREASURY_AUDIT_ANCHOR_SET", {"anchor": {"cid": "bafk-test"}}),
        ("GROUP_CREATE", {"group_id": "group-1", "charter": "charter"}),
        ("GROUP_UPDATE", {"group_id": "group-1", "charter": "new charter"}),
        ("GROUP_ROLE_GRANT", {"group_id": "group-1", "account": "bob", "role": "moderator"}),
        ("GROUP_ROLE_REVOKE", {"group_id": "group-1", "account": "bob", "role": "moderator"}),
        ("GROUP_MEMBERSHIP_REQUEST", {"group_id": "group-1", "note": "please"}),
        ("GROUP_MEMBERSHIP_DECIDE", {"group_id": "group-1", "account": "bob", "decision": "accept"}),
        ("GROUP_MEMBERSHIP_REMOVE", {"group_id": "group-1", "account": "bob"}),
        ("GROUP_SIGNERS_SET", {"group_id": "group-1", "signers": ["alice", "bob"], "threshold": 2}),
        ("GROUP_MODERATORS_SET", {"group_id": "group-1", "moderators": ["alice", "bob"]}),
        ("GROUP_TREASURY_CREATE", {"treasury_id": "group-treasury-1"}),
        ("GROUP_TREASURY_POLICY_SET", {"group_id": "group-1", "policy": {"timelock_blocks": 5}}),
        ("GROUP_TREASURY_SPEND_PROPOSE", {"group_id": "group-1", "spend_id": "gspend-1", "to": "bob", "amount": 50}),
        ("GROUP_TREASURY_SPEND_SIGN", {"spend_id": "gspend-1"}),
        ("GROUP_TREASURY_SPEND_CANCEL", {"spend_id": "gspend-1"}),
        ("GROUP_TREASURY_SPEND_EXPIRE", {"group_id": "group-1", "spend_id": "gspend-1"}),
        ("GROUP_TREASURY_SPEND_EXECUTE", {"spend_id": "gspend-1"}),
        ("GROUP_TREASURY_AUDIT_ANCHOR_SET", {"group_id": "group-1", "anchor": {"cid": "bafk-test"}}),
        ("GROUP_EMISSARY_ELECTION_CREATE", {"group_id": "group-1", "election_id": "e1", "seats": 5, "candidates": ["alice", "bob"], "start_height": 10, "end_height": 20}),
        ("GROUP_EMISSARY_BALLOT_CAST", {"election_id": "e1", "ranking": ["alice", "bob"]}),
        ("GROUP_EMISSARY_ELECTION_FINALIZE", {"election_id": "e1"}),
    ],
)
def test_batch3_valid_payloads_are_accepted(tx_type: str, payload: dict) -> None:
    env, parsed = validate_tx_envelope(_env(tx_type, payload))
    assert env.tx_type == tx_type
    assert parsed is not None


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_fragment"),
    [
        ("TREASURY_CREATE", {}, "treasury_id"),
        ("TREASURY_SIGNERS_SET", {"treasury_id": "t1"}, "signers"),
        ("TREASURY_WALLET_CREATE", {}, "wallet_id"),
        ("TREASURY_SIGNER_ADD", {"wallet_id": "w1"}, "signer"),
        ("TREASURY_SIGNER_REMOVE", {"wallet_id": "w1"}, "signer"),
        ("TREASURY_POLICY_SET", {}, "policy"),
        ("TREASURY_SPEND_PROPOSE", {"treasury_id": "t1", "spend_id": "s1"}, "to"),
        ("TREASURY_SPEND_SIGN", {"treasury_id": "t1"}, "spend_id"),
        ("TREASURY_SPEND_CANCEL", {"treasury_id": "t1"}, "spend_id"),
        ("TREASURY_SPEND_EXPIRE", {}, "spend_id"),
        ("TREASURY_SPEND_EXECUTE", {}, "spend_id"),
        ("TREASURY_PROGRAM_CREATE", {}, "program_id"),
        ("TREASURY_PROGRAM_UPDATE", {}, "program_id"),
        ("TREASURY_PROGRAM_CLOSE", {}, "program_id"),
        ("TREASURY_AUDIT_ANCHOR_SET", {}, "anchor"),
        ("GROUP_CREATE", {}, "group_id"),
        ("GROUP_UPDATE", {}, "group_id"),
        ("GROUP_ROLE_GRANT", {"group_id": "g1", "account": "bob"}, "role"),
        ("GROUP_ROLE_REVOKE", {"group_id": "g1", "account": "bob"}, "role"),
        ("GROUP_MEMBERSHIP_REQUEST", {}, "group_id"),
        ("GROUP_MEMBERSHIP_DECIDE", {"group_id": "g1", "account": "bob"}, "decision"),
        ("GROUP_MEMBERSHIP_REMOVE", {"group_id": "g1"}, "account"),
        ("GROUP_SIGNERS_SET", {"group_id": "g1"}, "signers"),
        ("GROUP_MODERATORS_SET", {"group_id": "g1"}, "moderators"),
        ("GROUP_TREASURY_CREATE", {}, "treasury_id"),
        ("GROUP_TREASURY_POLICY_SET", {"group_id": "g1"}, "policy"),
        ("GROUP_TREASURY_SPEND_PROPOSE", {"group_id": "g1", "spend_id": "s1"}, "to"),
        ("GROUP_TREASURY_SPEND_SIGN", {}, "spend_id"),
        ("GROUP_TREASURY_SPEND_CANCEL", {}, "spend_id"),
        ("GROUP_TREASURY_SPEND_EXPIRE", {"group_id": "g1"}, "spend_id"),
        ("GROUP_TREASURY_SPEND_EXECUTE", {}, "spend_id"),
        ("GROUP_TREASURY_AUDIT_ANCHOR_SET", {}, "group_id"),
        ("GROUP_EMISSARY_ELECTION_CREATE", {"group_id": "g1", "election_id": "e1", "seats": 5}, "candidates"),
        ("GROUP_EMISSARY_BALLOT_CAST", {"election_id": "e1"}, "ranking"),
        ("GROUP_EMISSARY_ELECTION_FINALIZE", {}, "election_id"),
    ],
)
def test_batch3_missing_required_fields_are_rejected(tx_type: str, payload: dict, expected_fragment: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert expected_fragment in str(excinfo.value)


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("TREASURY_CREATE", {"treasury_id": "t1", "extra": True}),
        ("TREASURY_SIGNERS_SET", {"treasury_id": "t1", "signers": ["alice"], "extra": True}),
        ("TREASURY_POLICY_SET", {"policy": {}, "extra": True}),
        ("TREASURY_SPEND_PROPOSE", {"treasury_id": "t1", "spend_id": "s1", "to": "bob", "amount": 1, "extra": True}),
        ("TREASURY_PROGRAM_CREATE", {"program_id": "p1", "extra": True}),
        ("GROUP_CREATE", {"group_id": "g1", "extra": True}),
        ("GROUP_ROLE_GRANT", {"group_id": "g1", "account": "bob", "role": "mod", "extra": True}),
        ("GROUP_SIGNERS_SET", {"group_id": "g1", "signers": ["alice"], "extra": True}),
        ("GROUP_TREASURY_SPEND_PROPOSE", {"group_id": "g1", "spend_id": "s1", "to": "bob", "amount": 1, "extra": True}),
        ("GROUP_EMISSARY_ELECTION_CREATE", {"group_id": "g1", "election_id": "e1", "seats": 5, "candidates": ["alice"], "extra": True}),
    ],
)
def test_batch3_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
