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


def test_batch5_models_registered() -> None:
    expected = {
        "ACCOUNT_BAN",
        "ACCOUNT_REINSTATE",
        "BALANCE_TRANSFER",
        "FEE_PAY",
        "ECONOMICS_ACTIVATION",
        "FEE_POLICY_SET",
        "RATE_LIMIT_POLICY_SET",
        "RATE_LIMIT_STRIKE_APPLY",
        "MEMPOOL_REJECT_RECEIPT",
        "REWARD_POOL_OPT_IN_SET",
        "BLOCK_REWARD_MINT",
        "BLOCK_REWARD_DISTRIBUTE",
        "CREATOR_REWARD_ALLOCATE",
        "TREASURY_REWARD_ALLOCATE",
        "FORFEITURE_APPLY",
        "CREATOR_PERFORMANCE_REPORT",
        "NODE_OPERATOR_PERFORMANCE_REPORT",
        "PERFORMANCE_EVALUATE",
        "PERFORMANCE_SCORE_APPLY",
        "CONTENT_LABEL_SET",
        "CONTENT_VISIBILITY_SET",
        "CONTENT_THREAD_LOCK_SET",
        "CONTENT_MEDIA_REPLACE",
        "CONTENT_MEDIA_UNBIND",
        "CONTENT_ESCALATE_TO_DISPUTE",
        "NOTIFICATION_EMIT_RECEIPT",
        "INDEX_ANCHOR_SET",
        "STATE_SNAPSHOT_DECLARE",
        "STATE_SNAPSHOT_ACCEPT",
        "COLD_SYNC_REQUEST",
        "COLD_SYNC_COMPLETE",
        "INDEX_TOPIC_REGISTER",
        "INDEX_TOPIC_ANCHOR_SET",
        "TX_RECEIPT_EMIT",
        "ROLE_ELIGIBILITY_SET",
        "ROLE_ELIGIBILITY_REVOKE",
        "ROLE_EMISSARY_NOMINATE",
        "ROLE_EMISSARY_VOTE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_EMISSARY_REMOVE",
        "ROLE_GOV_EXECUTOR_SET",
        "ROLE_JUROR_ENROLL",
        "ROLE_JUROR_ACTIVATE",
        "ROLE_JUROR_REINSTATE",
        "ROLE_JUROR_SUSPEND",
        "ROLE_NODE_OPERATOR_ENROLL",
        "ROLE_NODE_OPERATOR_ACTIVATE",
        "ROLE_NODE_OPERATOR_SUSPEND",
        "ROLE_VALIDATOR_ACTIVATE",
        "ROLE_VALIDATOR_SUSPEND",
        "REPUTATION_DELTA_APPLY",
        "REPUTATION_THRESHOLD_CROSS",
        "VALIDATOR_REGISTER",
        "VALIDATOR_CANDIDATE_REGISTER",
        "VALIDATOR_CANDIDATE_APPROVE",
        "VALIDATOR_SUSPEND",
        "VALIDATOR_REMOVE",
        "VALIDATOR_DEREGISTER",
        "VALIDATOR_SET_UPDATE",
        "VALIDATOR_HEARTBEAT",
        "VALIDATOR_PERFORMANCE_REPORT",
        "BLOCK_PROPOSE",
        "BLOCK_ATTEST",
        "BLOCK_FINALIZE",
        "EPOCH_OPEN",
        "EPOCH_CLOSE",
        "SLASH_PROPOSE",
        "SLASH_VOTE",
        "SLASH_EXECUTE",
    }
    missing = {name for name in expected if model_for_tx_type(name) is None}
    assert not missing


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("ACCOUNT_BAN", {"account": "@bob", "reason": "abuse"}),
        ("ACCOUNT_REINSTATE", {"account_id": "@bob"}),
        ("BALANCE_TRANSFER", {"to": "@bob", "amount": 5}),
        ("FEE_PAY", {"tx_id": "tx1", "tx_type": "BALANCE_TRANSFER", "amount": 1}),
        ("ECONOMICS_ACTIVATION", {"enabled": True}),
        ("FEE_POLICY_SET", {"transfer_fee_int": 1}),
        ("RATE_LIMIT_POLICY_SET", {"window_ms": 60000, "limit": 3}),
        ("RATE_LIMIT_STRIKE_APPLY", {"target": "@bob", "reason": "spam"}),
        ("MEMPOOL_REJECT_RECEIPT", {"tx_id": "tx1", "code": "stale_nonce"}),
        ("REWARD_POOL_OPT_IN_SET", {"enabled": True}),
        ("BLOCK_REWARD_MINT", {"block_id": "b1", "amount": 25}),
        ("BLOCK_REWARD_DISTRIBUTE", {"block_id": "b1", "transfers": [], "debits": []}),
        ("CREATOR_REWARD_ALLOCATE", {"block_id": "b1", "alloc_id": "a1", "transfers": [], "debits": []}),
        ("TREASURY_REWARD_ALLOCATE", {"block_id": "b1", "alloc_id": "a2", "transfers": [], "debits": []}),
        ("FORFEITURE_APPLY", {"account": "@bob", "amount": 3}),
        ("CREATOR_PERFORMANCE_REPORT", {"subject": "@alice", "metrics": {"posts": 5}}),
        ("NODE_OPERATOR_PERFORMANCE_REPORT", {"account": "@nodeop", "metrics": {"uptime": 99}}),
        ("PERFORMANCE_EVALUATE", {"subject": "@alice", "score": 88}),
        ("PERFORMANCE_SCORE_APPLY", {"subject": "@alice", "score": 91}),
        ("CONTENT_LABEL_SET", {"target_id": "post-1", "labels": ["spam"]}),
        ("CONTENT_VISIBILITY_SET", {"id": "post-1", "visibility": "hidden"}),
        ("CONTENT_THREAD_LOCK_SET", {"post_id": "post-1", "locked": True}),
        ("CONTENT_MEDIA_REPLACE", {"media_id": "m1", "new_cid": "bafkreigh2akiscaildc4examplecidstring1111111111111111111111111"}),
        ("CONTENT_MEDIA_UNBIND", {"binding_id": "bind-1"}),
        ("CONTENT_ESCALATE_TO_DISPUTE", {"target_type": "content", "target_id": "post-1", "reason": "spam"}),
        ("NOTIFICATION_EMIT_RECEIPT", {"topic": "mentions"}),
        ("INDEX_ANCHOR_SET", {"anchor_id": "anc-1"}),
        ("STATE_SNAPSHOT_DECLARE", {"snapshot_id": "snap-1"}),
        ("STATE_SNAPSHOT_ACCEPT", {"cid": "snap-1"}),
        ("COLD_SYNC_REQUEST", {"snapshot_id": "snap-1", "request_id": "req-1"}),
        ("COLD_SYNC_COMPLETE", {"id": "req-1"}),
        ("INDEX_TOPIC_REGISTER", {"name": "governance"}),
        ("INDEX_TOPIC_ANCHOR_SET", {"topic": "governance", "anchor_id": "anc-1"}),
        ("TX_RECEIPT_EMIT", {"receipt_id": "r1"}),
        ("TX_RECEIPT_EMIT", {"tx_id": "tx1", "tx_type": "BALANCE_TRANSFER"}),
        ("ROLE_ELIGIBILITY_SET", {"account": "@bob", "role": "juror"}),
        ("ROLE_ELIGIBILITY_REVOKE", {"account_id": "@bob", "role": "juror"}),
        ("ROLE_EMISSARY_NOMINATE", {"emissary": "@bob"}),
        ("ROLE_EMISSARY_VOTE", {"account": "@bob"}),
        ("ROLE_EMISSARY_SEAT", {"target": "@bob"}),
        ("ROLE_EMISSARY_REMOVE", {"account_id": "@bob", "reason": "term end"}),
        ("ROLE_GOV_EXECUTOR_SET", {"executor": "@govbot", "note": "rotate"}),
        ("ROLE_JUROR_ENROLL", {"juror": "@bob"}),
        ("ROLE_JUROR_ACTIVATE", {"account": "@bob"}),
        ("ROLE_JUROR_REINSTATE", {"account_id": "@bob"}),
        ("ROLE_JUROR_SUSPEND", {"target": "@bob"}),
        ("ROLE_NODE_OPERATOR_ENROLL", {"operator": "@bob"}),
        ("ROLE_NODE_OPERATOR_ACTIVATE", {"node_operator": "@bob"}),
        ("ROLE_NODE_OPERATOR_SUSPEND", {"account": "@bob"}),
        ("ROLE_VALIDATOR_ACTIVATE", {"validator": "@bob"}),
        ("ROLE_VALIDATOR_SUSPEND", {"account_id": "@bob"}),
        ("REPUTATION_DELTA_APPLY", {"account": "@bob", "delta": -5}),
        ("REPUTATION_THRESHOLD_CROSS", {"account_id": "@bob", "threshold": "tier2", "direction": "down"}),
        ("VALIDATOR_REGISTER", {"endpoint": "https://node.example"}),
        ("VALIDATOR_CANDIDATE_REGISTER", {"node_id": "node-bob", "pubkey": "ed25519:bob", "endpoints": ["https://node.example"]}),
        ("VALIDATOR_CANDIDATE_REGISTER", {"node_id": "node-bob", "pubkey": "ed25519:bob", "endpoint": "https://node.example"}),
        ("VALIDATOR_CANDIDATE_APPROVE", {"account": "@bob", "activate_at_epoch": 2}),
        ("VALIDATOR_SUSPEND", {"account": "@bob", "effective_epoch": 2}),
        ("VALIDATOR_REMOVE", {"account": "@bob", "effective_epoch": 3}),
        ("VALIDATOR_DEREGISTER", {"account": "@bob"}),
        ("VALIDATOR_SET_UPDATE", {"active_set": ["@alice", "@bob"], "activate_at_epoch": 3}),
        ("VALIDATOR_HEARTBEAT", {"node_id": "node-bob", "account": "@bob", "ts_ms": 123}),
        ("VALIDATOR_PERFORMANCE_REPORT", {"validator": "@bob", "report": {"uptime": 99}}),
        ("BLOCK_PROPOSE", {"block_id": "b1", "height": 1}),
        ("BLOCK_ATTEST", {"id": "b1", "vote": "yes", "height": 1, "round": 1}),
        ("BLOCK_FINALIZE", {"block_id": "b1", "height": 1}),
        ("EPOCH_OPEN", {"epoch": 2}),
        ("EPOCH_CLOSE", {"epoch": 2}),
        ("SLASH_PROPOSE", {"slash_id": "s1", "subject": "@bob", "reason": "equivocation"}),
        ("SLASH_VOTE", {"slash_id": "s1", "vote": "yes"}),
        ("SLASH_EXECUTE", {"slash_id": "s1", "outcome": "burn", "amount": 10}),
    ],
)
def test_batch5_valid_payloads_are_accepted(tx_type: str, payload: dict) -> None:
    env, parsed = validate_tx_envelope(_env(tx_type, payload))
    assert env.tx_type == tx_type
    assert parsed is not None


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_fragment"),
    [
        ("ACCOUNT_BAN", {}, "account_id"),
        ("BALANCE_TRANSFER", {"to": "@bob"}, "amount"),
        ("BLOCK_REWARD_MINT", {}, "block_id"),
        ("CONTENT_LABEL_SET", {"target_id": "post-1"}, "labels"),
        ("CONTENT_VISIBILITY_SET", {"target_id": "post-1"}, "visibility"),
        ("COLD_SYNC_REQUEST", {}, "snapshot_id"),
        ("INDEX_TOPIC_REGISTER", {}, "topic"),
        ("TX_RECEIPT_EMIT", {}, "either receipt_id or tx_id+tx_type is required"),
        ("ROLE_ELIGIBILITY_SET", {"account": "@bob"}, "role"),
        ("REPUTATION_DELTA_APPLY", {"account": "@bob"}, "either delta or delta_milli is required"),
        ("VALIDATOR_REGISTER", {}, "endpoint"),
        ("VALIDATOR_CANDIDATE_REGISTER", {"node_id": "node-bob", "pubkey": "ed25519:bob"}, "either endpoint or endpoints is required"),
        ("VALIDATOR_CANDIDATE_APPROVE", {"account": "@bob"}, "activate_at_epoch"),
        ("VALIDATOR_HEARTBEAT", {"account": "@bob", "ts_ms": 1}, "node_id"),
        ("BLOCK_PROPOSE", {"height": 1}, "block_id"),
        ("SLASH_VOTE", {"slash_id": "s1"}, "vote"),
    ],
)
def test_batch5_missing_required_fields_are_rejected(tx_type: str, payload: dict, expected_fragment: str) -> None:
    with pytest.raises((ValidationError, ValueError)) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert expected_fragment in str(excinfo.value)


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("ACCOUNT_BAN", {"account": "@bob", "extra": True}),
        ("BALANCE_TRANSFER", {"to": "@bob", "amount": 5, "extra": True}),
        ("CONTENT_LABEL_SET", {"target_id": "post-1", "labels": ["spam"], "extra": True}),
        ("TX_RECEIPT_EMIT", {"receipt_id": "r1", "extra": True}),
        ("ROLE_ELIGIBILITY_SET", {"account": "@bob", "role": "juror", "extra": True}),
        ("VALIDATOR_REGISTER", {"endpoint": "https://node.example", "extra": True}),
        ("BLOCK_PROPOSE", {"block_id": "b1", "height": 1, "extra": True}),
        ("SLASH_EXECUTE", {"slash_id": "s1", "extra": True}),
    ],
)
def test_batch5_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
