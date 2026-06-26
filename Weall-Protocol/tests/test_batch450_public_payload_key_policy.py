from __future__ import annotations

import pytest
from pydantic import ValidationError

from weall.runtime.apply.identity import apply_identity
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope


def _acct_env(account: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="ACCOUNT_REGISTER", signer=account, nonce=nonce, payload={"pubkey": f"pk:{account}", **payload}, sig="sig")


def _policy_env(account: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="ACCOUNT_SECURITY_POLICY_SET", signer=account, nonce=nonce, payload=payload, sig="sig")


def test_account_register_rejects_non_inspectable_protocol_key_material_batch450() -> None:
    st: dict = {"accounts": {}}
    with pytest.raises(ApplyError) as ei:
        apply_identity(st, _acct_env("alice", 1, {"encrypted" + "_payload": {"k": "opaque"}}))
    assert ei.value.code == "OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED"


def test_account_security_policy_rejects_non_inspectable_protocol_key_material_batch450() -> None:
    st = {"accounts": {"alice": {"nonce": 1, "security_policy": {}}}}
    with pytest.raises(ApplyError) as ei:
        apply_identity(st, _policy_env("alice", 2, {"encrypted" + "_payload": {"k": "opaque"}}))
    assert ei.value.code == "OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED"


def test_account_security_policy_schema_rejects_non_inspectable_protocol_fields_batch450() -> None:
    with pytest.raises(ValidationError) as excinfo:
        validate_tx_envelope({
            "tx_type": "ACCOUNT_SECURITY_POLICY_SET",
            "signer": "alice",
            "nonce": 2,
            "sig": "sig",
            "payload": {"encrypted" + "_payload": {"k": "opaque"}},
        })
    assert "encrypted" + "_payload" in str(excinfo.value)
