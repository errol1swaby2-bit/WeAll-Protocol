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

VALID_CID = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7xqz7i"


def _env(tx_type: str, payload: dict) -> dict:
    env = dict(BASE_ENV)
    env["tx_type"] = tx_type
    env["payload"] = payload
    return env


def test_batch2_schema_models_registered() -> None:
    expected = {
        "PEER_ADVERTISE",
        "PEER_RENDEZVOUS_TICKET_CREATE",
        "PEER_RENDEZVOUS_TICKET_REVOKE",
        "PEER_REQUEST_CONNECT",
        "PEER_BAN_SET",
        "PEER_REPUTATION_SIGNAL",
        "STORAGE_OFFER_CREATE",
        "STORAGE_OFFER_WITHDRAW",
        "STORAGE_LEASE_CREATE",
        "STORAGE_LEASE_RENEW",
        "STORAGE_LEASE_REVOKE",
        "STORAGE_PROOF_SUBMIT",
        "STORAGE_CHALLENGE_ISSUE",
        "STORAGE_CHALLENGE_RESPOND",
        "STORAGE_PAYOUT_EXECUTE",
        "STORAGE_REPORT_ANCHOR",
        "IPFS_PIN_REQUEST",
        "IPFS_PIN_CONFIRM",
    }
    missing = {name for name in expected if model_for_tx_type(name) is None}
    assert not missing


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("PEER_ADVERTISE", {"endpoint": "https://node.example"}),
        ("PEER_ADVERTISE", {"url": "https://node.example", "peer": "peer-1"}),
        ("PEER_RENDEZVOUS_TICKET_CREATE", {"target_peer": "peer-2", "ticket_id": "ticket-1"}),
        ("PEER_RENDEZVOUS_TICKET_CREATE", {"target_peer": "peer-2", "id": "ticket-1"}),
        ("PEER_RENDEZVOUS_TICKET_REVOKE", {"ticket_id": "ticket-1"}),
        ("PEER_RENDEZVOUS_TICKET_REVOKE", {"id": "ticket-1"}),
        ("PEER_REQUEST_CONNECT", {"peer_id": "peer-2"}),
        ("PEER_REQUEST_CONNECT", {"ticket_id": "ticket-1"}),
        ("PEER_REQUEST_CONNECT", {"url": "https://node.example"}),
        ("PEER_BAN_SET", {"peer_id": "peer-2", "banned": True, "reason": "spam"}),
        ("PEER_REPUTATION_SIGNAL", {"peer": "peer-2", "score": 5, "reason": "helpful"}),
        ("STORAGE_OFFER_CREATE", {"offer_id": "offer-1", "capacity_bytes": 1024}),
        ("STORAGE_OFFER_CREATE", {"id": "offer-1", "capacity": 1024, "cid": VALID_CID}),
        ("STORAGE_OFFER_WITHDRAW", {"offer_id": "offer-1"}),
        ("STORAGE_OFFER_WITHDRAW", {"id": "offer-1"}),
        ("STORAGE_LEASE_CREATE", {"offer_id": "offer-1", "lease_id": "lease-1", "duration_blocks": 10}),
        ("STORAGE_LEASE_CREATE", {"offer_id": "offer-1", "id": "lease-1", "blocks": 10}),
        ("STORAGE_LEASE_RENEW", {"lease_id": "lease-1", "add_blocks": 5}),
        ("STORAGE_LEASE_RENEW", {"id": "lease-1", "duration_blocks": 5}),
        ("STORAGE_LEASE_REVOKE", {"lease_id": "lease-1"}),
        ("STORAGE_LEASE_REVOKE", {"id": "lease-1"}),
        ("STORAGE_PROOF_SUBMIT", {"lease_id": "lease-1", "proof_cid": VALID_CID}),
        ("STORAGE_PROOF_SUBMIT", {"lease_id": "lease-1", "cid": VALID_CID}),
        ("STORAGE_CHALLENGE_ISSUE", {"lease_id": "lease-1", "challenge_id": "challenge-1"}),
        ("STORAGE_CHALLENGE_ISSUE", {"lease_id": "lease-1", "id": "challenge-1", "operator": "alice", "lessee": "bob"}),
        ("STORAGE_CHALLENGE_RESPOND", {"challenge_id": "challenge-1"}),
        ("STORAGE_CHALLENGE_RESPOND", {"id": "challenge-1"}),
        ("STORAGE_PAYOUT_EXECUTE", {"payout_id": "payout-1", "operator_id": "alice", "amount": 25}),
        ("STORAGE_PAYOUT_EXECUTE", {"id": "payout-1", "operator": "alice", "amount": "25"}),
        ("STORAGE_REPORT_ANCHOR", {"report_id": "report-1", "report_cid": VALID_CID}),
        ("STORAGE_REPORT_ANCHOR", {"key": "report-1", "cid": VALID_CID}),
        ("IPFS_PIN_REQUEST", {"cid": VALID_CID, "pin_id": "pin-1", "size_bytes": 64}),
        ("IPFS_PIN_REQUEST", {"content_cid": VALID_CID, "id": "pin-1", "bytes": 64}),
        ("IPFS_PIN_CONFIRM", {"pin_id": "pin-1", "ok": True}),
        ("IPFS_PIN_CONFIRM", {"id": "pin-1", "cid": VALID_CID, "operator": "alice", "ok": 1}),
    ],
)
def test_batch2_valid_payloads_are_accepted(tx_type: str, payload: dict) -> None:
    env, parsed = validate_tx_envelope(_env(tx_type, payload))
    assert env.tx_type == tx_type
    assert parsed is not None


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_fragment"),
    [
        ("PEER_ADVERTISE", {}, "endpoint"),
        ("PEER_RENDEZVOUS_TICKET_CREATE", {}, "target_peer"),
        ("PEER_RENDEZVOUS_TICKET_REVOKE", {}, "ticket_id"),
        ("PEER_REQUEST_CONNECT", {}, "peer_id, ticket_id, or endpoint is required"),
        ("PEER_BAN_SET", {}, "peer_id"),
        ("PEER_REPUTATION_SIGNAL", {}, "peer_id"),
        ("STORAGE_OFFER_WITHDRAW", {}, "offer_id"),
        ("STORAGE_LEASE_CREATE", {}, "offer_id"),
        ("STORAGE_LEASE_RENEW", {}, "lease_id"),
        ("STORAGE_LEASE_REVOKE", {}, "lease_id"),
        ("STORAGE_PROOF_SUBMIT", {}, "lease_id"),
        ("STORAGE_CHALLENGE_ISSUE", {}, "lease_id"),
        ("STORAGE_CHALLENGE_RESPOND", {}, "challenge_id"),
        ("IPFS_PIN_REQUEST", {}, "cid"),
        ("IPFS_PIN_REQUEST", {"cid": "not-a-cid"}, "invalid_cid_format"),
        ("IPFS_PIN_CONFIRM", {"pin_id": "pin-1", "cid": "not-a-cid"}, "invalid_cid_format"),
        ("STORAGE_REPORT_ANCHOR", {"report_id": "report-1", "report_cid": "not-a-cid"}, "invalid_cid_format"),
        ("STORAGE_PROOF_SUBMIT", {"lease_id": "lease-1", "proof_cid": "not-a-cid"}, "invalid_cid_format"),
    ],
)
def test_batch2_missing_or_invalid_fields_are_rejected(
    tx_type: str,
    payload: dict,
    expected_fragment: str,
) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert expected_fragment in str(excinfo.value)


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("PEER_ADVERTISE", {"endpoint": "https://node.example", "unexpected": True}),
        ("PEER_REQUEST_CONNECT", {"peer_id": "peer-2", "extra": "x"}),
        ("STORAGE_OFFER_CREATE", {"offer_id": "offer-1", "extra": "x"}),
        ("STORAGE_LEASE_CREATE", {"offer_id": "offer-1", "extra": "x"}),
        ("STORAGE_PROOF_SUBMIT", {"lease_id": "lease-1", "proof_cid": VALID_CID, "extra": "x"}),
        ("STORAGE_REPORT_ANCHOR", {"report_id": "report-1", "report_cid": VALID_CID, "extra": "x"}),
        ("IPFS_PIN_REQUEST", {"cid": VALID_CID, "extra": "x"}),
        ("IPFS_PIN_CONFIRM", {"pin_id": "pin-1", "ok": True, "extra": "x"}),
    ],
)
def test_batch2_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
