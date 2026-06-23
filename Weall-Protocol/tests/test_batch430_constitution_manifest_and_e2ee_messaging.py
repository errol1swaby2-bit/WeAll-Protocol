from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from weall.runtime.apply.messaging import MessagingApplyError, apply_messaging
from weall.runtime.chain_manifest import chain_manifest_status, load_chain_manifest
from weall.runtime.constitution import active_constitution_commitment, constitution_document_hash
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]


def _jwk(x: str, y: str) -> dict:
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y, "ext": True}


def _encrypted_payload(**extra: object) -> dict:
    payload = {
        "to": "bob",
        "encryption": "WEALL_E2EE_V1",
        "ciphertext_b64": "Y2lwaGVydGV4dA==",
        "iv_b64": "MTIzNDU2Nzg5MDEy",
        "aad_b64": "YWFk",
        "sender_encryption_public_jwk": _jwk("a", "b"),
        "recipient_encryption_public_jwk": _jwk("c", "d"),
        "sender_encryption_key_id": "msgenc:sender",
        "recipient_encryption_key_id": "msgenc:recipient",
    }
    payload.update(extra)
    return payload


def _env(payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type="DIRECT_MESSAGE_SEND", signer="alice", nonce=1, payload=payload, sig="sig")


def test_constitution_hash_is_bound_into_canonical_chain_manifest_batch430() -> None:
    manifest = load_chain_manifest(str(ROOT / "configs" / "chains" / "weall-genesis.json"), required=True)
    assert manifest is not None
    expected_hash = hashlib.sha256((ROOT / "docs" / "constitution" / "WEALL_GENESIS_CONSTITUTION_DRAFT_2.md").read_bytes()).hexdigest()
    assert manifest.constitution_version == "draft-2"
    assert manifest.constitution_hash == expected_hash == constitution_document_hash()
    commitment = active_constitution_commitment(manifest.raw)
    assert commitment["active"] is True
    assert commitment["status"] == "genesis_bound"


def test_chain_manifest_status_reports_constitution_commitments_batch430() -> None:
    manifest = load_chain_manifest(str(ROOT / "configs" / "chains" / "weall-genesis.json"), required=True)
    report = chain_manifest_status(manifest=manifest, chain_id="weall-prod", mode="prod", strict=True)
    assert report["constitution_version"] == "draft-2"
    assert report["constitution_hash"]
    assert "chain_manifest_constitution_hash_unpinned" not in report["issues"]


def test_direct_messages_reject_plaintext_body_batch430() -> None:
    st = {"messaging": {}}
    with pytest.raises(MessagingApplyError) as ei:
        apply_messaging(st, _env({"to": "bob", "body": "hello"}))
    assert ei.value.code == "PRIVATE_MESSAGING_UNSUPPORTED"
    assert ei.value.reason == "protocol_native_direct_messages_are_unsupported"


def test_direct_messages_reject_e2ee_ciphertext_envelope_batch430() -> None:
    st: dict = {"messaging": {}}
    with pytest.raises(MessagingApplyError) as ei:
        apply_messaging(st, _env(_encrypted_payload()))
    assert ei.value.code == "PRIVATE_MESSAGING_UNSUPPORTED"
    assert "messages_by_id" not in st.get("messaging", {})
