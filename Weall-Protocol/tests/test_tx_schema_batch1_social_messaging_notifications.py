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


def test_batch1_schema_models_registered() -> None:
    expected = {
        "PROFILE_UPDATE",
        "FOLLOW_SET",
        "BLOCK_SET",
        "MUTE_SET",
        "CONTENT_SHARE_CREATE",
        "DIRECT_MESSAGE_SEND",
        "DIRECT_MESSAGE_REDACT",
        "NOTIFICATION_SUBSCRIBE",
        "NOTIFICATION_UNSUBSCRIBE",
    }
    missing = {name for name in expected if model_for_tx_type(name) is None}
    assert not missing


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("PROFILE_UPDATE", {"display_name": "Alice", "bio": "Hello", "tags": ["one"]}),
        ("FOLLOW_SET", {"target": "bob", "active": True}),
        ("FOLLOW_SET", {"account_id": "bob"}),
        ("BLOCK_SET", {"target": "bob"}),
        ("MUTE_SET", {"account_id": "bob", "active": False}),
        ("CONTENT_SHARE_CREATE", {"target_id": "post:1", "share_id": "share:1"}),
        ("DIRECT_MESSAGE_SEND", {"to": "bob", "body": "hi"}),
        ("DIRECT_MESSAGE_SEND", {"recipient": "bob", "cid": "bafy123"}),
        ("DIRECT_MESSAGE_SEND", {"to_account": "bob", "body": "hi", "message_id": "dm:1"}),
        ("DIRECT_MESSAGE_SEND", {"account_id": "bob", "body": "hi", "id": "dm:1"}),
        ("DIRECT_MESSAGE_REDACT", {"message_id": "dm:1", "reason": "oops"}),
        ("DIRECT_MESSAGE_REDACT", {"id": "dm:1"}),
        ("NOTIFICATION_SUBSCRIBE", {"topic": "mentions"}),
        ("NOTIFICATION_SUBSCRIBE", {"topics": ["mentions", "replies"]}),
        ("NOTIFICATION_UNSUBSCRIBE", {"topic": "mentions"}),
        ("NOTIFICATION_UNSUBSCRIBE", {"topics": ["mentions"]}),
    ],
)
def test_batch1_valid_payloads_are_accepted(tx_type: str, payload: dict) -> None:
    env, parsed = validate_tx_envelope(_env(tx_type, payload))
    assert env.tx_type == tx_type
    assert parsed is not None


@pytest.mark.parametrize(
    ("tx_type", "payload", "expected_fragment"),
    [
        ("FOLLOW_SET", {"active": True}, "target"),
        ("CONTENT_SHARE_CREATE", {}, "target_id"),
        ("DIRECT_MESSAGE_SEND", {"to": "bob"}, "body or cid"),
        ("DIRECT_MESSAGE_SEND", {"body": "hi"}, "to"),
        ("DIRECT_MESSAGE_REDACT", {}, "message_id"),
        ("NOTIFICATION_SUBSCRIBE", {"topic": ""}, "topic"),
        ("NOTIFICATION_UNSUBSCRIBE", {"topics": []}, "topics"),
    ],
)
def test_batch1_missing_required_fields_are_rejected(
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
        ("PROFILE_UPDATE", {"display_name": "Alice", "unexpected": True}),
        ("FOLLOW_SET", {"target": "bob", "unexpected": True}),
        ("CONTENT_SHARE_CREATE", {"target_id": "post:1", "extra": "x"}),
        ("DIRECT_MESSAGE_SEND", {"to": "bob", "body": "hi", "extra": "x"}),
        ("DIRECT_MESSAGE_REDACT", {"message_id": "dm:1", "extra": "x"}),
        ("NOTIFICATION_SUBSCRIBE", {"topic": "mentions", "extra": "x"}),
    ],
)
def test_batch1_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
