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
        ("BLOCK_SET", {"target": "bob"}),
        ("CONTENT_SHARE_CREATE", {"target_id": "post:1", "share_id": "share:1"}),
        ("NOTIFICATION_SUBSCRIBE", {"topic": "mentions"}),
        ("NOTIFICATION_UNSUBSCRIBE", {"topic": "mentions"}),
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
        ("NOTIFICATION_SUBSCRIBE", {"topic": "mentions", "extra": "x"}),
    ],
)
def test_batch1_extra_fields_are_forbidden(tx_type: str, payload: dict) -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope(_env(tx_type, payload))
    assert "Extra inputs are not permitted" in str(excinfo.value)
