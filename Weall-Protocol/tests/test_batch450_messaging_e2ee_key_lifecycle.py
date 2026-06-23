from __future__ import annotations

import pytest

from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.messaging import MessagingApplyError, apply_messaging
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope
from pydantic import ValidationError

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


def test_direct_message_envelope_is_rejected_before_key_matching_batch450() -> None:
    st: dict = {"accounts": {"alice": {}, "bob": {}}, "messaging": {}}
    with pytest.raises(MessagingApplyError) as ei:
        apply_messaging(st, _dm_env("alice", 2, _dm_payload()))
    assert ei.value.code == "PRIVATE_MESSAGING_UNSUPPORTED"
    assert ei.value.reason == "protocol_native_direct_messages_are_unsupported"


def test_messaging_key_registration_and_rotation_are_unsupported_batch450() -> None:
    st: dict = {"accounts": {}}

    with pytest.raises(ApplyError) as ei:
        apply_identity(st, _acct_env("alice", 1, {"messaging_encryption_public_jwk": _jwk("alice-x", "alice-y"), "messaging_encryption_key_id": "msgenc:alice-v1"}))
    assert ei.value.code == "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED"

    st = {"accounts": {"alice": {"nonce": 1, "security_policy": {}}}}
    with pytest.raises(ApplyError) as ei2:
        apply_identity(st, _policy_env("alice", 2, {
            "messaging_encryption_public_jwk": _jwk("alice-x2", "alice-y2"),
            "messaging_encryption_key_id": "msgenc:alice-v2",
            "messaging_encryption_previous_key_id": "msgenc:alice-v1",
            "messaging_encryption_rotation_reason": "explicit user requested key rotation",
        }))
    assert ei2.value.code == "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED"


def test_account_security_policy_schema_rejects_messaging_encryption_fields_batch450() -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope({
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
    assert "messaging_encryption_public_jwk" in str(excinfo.value)
