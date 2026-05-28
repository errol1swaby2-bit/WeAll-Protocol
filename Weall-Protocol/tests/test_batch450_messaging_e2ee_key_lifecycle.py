from __future__ import annotations

import pytest

from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.messaging import MessagingApplyError, apply_messaging
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope


def _jwk(x: str, y: str) -> dict:
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y, "ext": True}


def _acct_env(account: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="ACCOUNT_REGISTER", signer=account, nonce=nonce, payload={"pubkey": f"pk:{account}", **payload}, sig="sig")


def _policy_env(account: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="ACCOUNT_SECURITY_POLICY_SET", signer=account, nonce=nonce, payload=payload, sig="sig")


def _dm_env(account: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="DIRECT_MESSAGE_SEND", signer=account, nonce=nonce, payload=payload, sig="sig")


def _dm_payload(**extra: object) -> dict:
    payload = {
        "to": "bob",
        "encryption": "WEALL_E2EE_V1",
        "ciphertext_b64": "Y2lwaGVydGV4dA==",
        "iv_b64": "MTIzNDU2Nzg5MDEy",
        "aad_b64": "YWFk",
        "sender_encryption_public_jwk": _jwk("alice-x", "alice-y"),
        "recipient_encryption_public_jwk": _jwk("bob-x", "bob-y"),
        "sender_encryption_key_id": "msgenc:alice-v1",
        "recipient_encryption_key_id": "msgenc:bob-v1",
    }
    payload.update(extra)
    return payload


def _state_with_messaging_keys() -> dict:
    st: dict = {"accounts": {}, "messaging": {}}
    apply_identity(st, _acct_env("alice", 1, {"messaging_encryption_public_jwk": _jwk("alice-x", "alice-y"), "messaging_encryption_key_id": "msgenc:alice-v1"}))
    apply_identity(st, _acct_env("bob", 1, {"messaging_encryption_public_jwk": _jwk("bob-x", "bob-y"), "messaging_encryption_key_id": "msgenc:bob-v1"}))
    return st


def test_direct_message_envelope_must_match_published_account_keys_batch450() -> None:
    st = _state_with_messaging_keys()
    out = apply_messaging(st, _dm_env("alice", 2, _dm_payload()))
    assert out and out["applied"] == "DIRECT_MESSAGE_SEND"

    bad_recipient_key = _dm_payload(recipient_encryption_public_jwk=_jwk("mallory-x", "mallory-y"))
    with pytest.raises(MessagingApplyError) as ei:
        apply_messaging(st, _dm_env("alice", 3, bad_recipient_key))
    assert ei.value.reason == "recipient_messaging_encryption_public_key_mismatch"

    bad_sender_key_id = _dm_payload(sender_encryption_key_id="msgenc:wrong")
    with pytest.raises(MessagingApplyError) as ei2:
        apply_messaging(st, _dm_env("alice", 4, bad_sender_key_id))
    assert ei2.value.reason == "sender_messaging_encryption_key_mismatch"


def test_messaging_key_rotation_requires_explicit_current_previous_key_batch450() -> None:
    st = _state_with_messaging_keys()

    with pytest.raises(ApplyError) as ei:
        apply_identity(st, _policy_env("alice", 2, {"messaging_encryption_public_jwk": _jwk("alice-x2", "alice-y2"), "messaging_encryption_key_id": "msgenc:alice-v2"}))
    assert ei.value.reason == "messaging_encryption_key_rotation_requires_current_previous_key"

    with pytest.raises(ApplyError) as ei2:
        apply_identity(st, _policy_env("alice", 2, {
            "messaging_encryption_public_jwk": _jwk("alice-x2", "alice-y2"),
            "messaging_encryption_key_id": "msgenc:alice-v2",
            "messaging_encryption_previous_key_id": "msgenc:alice-v1",
            "messaging_encryption_rotation_reason": "short",
        }))
    assert ei2.value.reason == "messaging_encryption_key_rotation_reason_required"

    apply_identity(st, _policy_env("alice", 2, {
        "messaging_encryption_public_jwk": _jwk("alice-x2", "alice-y2"),
        "messaging_encryption_key_id": "msgenc:alice-v2",
        "messaging_encryption_previous_key_id": "msgenc:alice-v1",
        "messaging_encryption_rotation_reason": "explicit user requested key rotation",
    }))
    policy = st["accounts"]["alice"]["security_policy"]
    assert policy["messaging_encryption_key_id"] == "msgenc:alice-v2"
    assert policy["messaging_encryption_previous_key_id"] == "msgenc:alice-v1"
    assert policy["messaging_encryption_key_change_count"] == 1
    assert len(policy["messaging_encryption_key_history"]) == 2
    assert policy["messaging_encryption_forward_secrecy"] is False
    assert policy["messaging_encryption_metadata_visible"] is True


def test_account_security_policy_schema_accepts_explicit_rotation_fields_batch450() -> None:
    env, parsed = validate_tx_envelope({
        "tx_type": "ACCOUNT_SECURITY_POLICY_SET",
        "signer": "alice",
        "nonce": 2,
        "sig": "sig",
        "payload": {
            "messaging_encryption_public_jwk": _jwk("alice-x2", "alice-y2"),
            "messaging_encryption_key_id": "msgenc:alice-v2",
            "messaging_encryption_previous_key_id": "msgenc:alice-v1",
            "messaging_encryption_rotation_reason": "explicit user requested key rotation",
        },
    })
    assert env.tx_type == "ACCOUNT_SECURITY_POLICY_SET"
    assert parsed is not None
