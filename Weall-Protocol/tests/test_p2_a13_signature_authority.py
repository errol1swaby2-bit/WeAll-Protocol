from __future__ import annotations

from dataclasses import replace

import pytest

from weall.net.messages import MsgType, PeerHello, WireHeader
from weall.net.peer_identity import verify_peer_hello_identity
from weall.runtime.domain_apply import apply_tx
from weall.runtime.helper_certificates import (
    CERTIFICATE_DOMAIN,
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
    verify_helper_certificate_signature,
)
from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt
from weall.testing.sigtools import deterministic_mldsa_keypair


def _envelope(tx_type: str, payload: dict, *, signer: str, nonce: int) -> dict:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload,
        "sig": "",
        "system": False,
    }


def _peer_hello(*, sig_profile: str | None) -> PeerHello:
    identity = {"pubkey": "pk1", "sig": "sig1"}
    if sig_profile is not None:
        identity["sig_profile"] = sig_profile
    return PeerHello(
        header=WireHeader(
            type=MsgType.PEER_HELLO,
            chain_id="weall",
            schema_version="1",
            tx_index_hash="txindex",
            sent_ts_ms=123,
            corr_id=None,
        ),
        peer_id="acc1",
        agent="p2",
        nonce="nonce",
        caps=(),
        identity=identity,
    )


def _peer_ledger() -> dict:
    state: dict = {}
    apply_tx(state, _envelope("ACCOUNT_REGISTER", {"pubkey": "pk1"}, signer="acc1", nonce=1))
    apply_tx(
        state,
        _envelope(
            "ACCOUNT_DEVICE_REGISTER",
            {
                "device_id": "node:acc1",
                "device_type": "node",
                "label": "node",
                "pubkey": "pk1",
            },
            signer="acc1",
            nonce=2,
        ),
    )
    return state


def test_peer_identity_profile_stripping_fails_before_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import weall.net.peer_identity as peer_identity_mod

    monkeypatch.setattr(peer_identity_mod, "verify_mldsa_sig", lambda *_args, **_kwargs: True)
    state = _peer_ledger()

    ok, reason, _, _ = verify_peer_hello_identity(
        hello=_peer_hello(sig_profile=None),
        ledger=state,
    )
    assert ok is False
    assert reason == "missing_signature_profile"

    ok2, reason2, _, _ = verify_peer_hello_identity(
        hello=_peer_hello(sig_profile="unknown-profile"),
        ledger=state,
    )
    assert ok2 is False
    assert reason2 == "unsupported_signature_profile"

    ok3, reason3, _, _ = verify_peer_hello_identity(
        hello=_peer_hello(sig_profile="pq-mldsa-v1"),
        ledger=state,
    )
    assert ok3 is True
    assert reason3 == "ok"


def _receipt_verify(receipt, pubkey: str) -> bool:
    return verify_helper_receipt(
        receipt,
        helper_pubkey=pubkey,
        expected_chain_id="weall-testnet-v1",
        expected_height=7,
        expected_validator_epoch=1,
        expected_validator_set_hash="set-hash",
        expected_parent_block_id="parent",
        expected_lane_id="PARALLEL_CONTENT",
        expected_helper_id="helper-a",
        expected_plan_id="plan-p2",
        expected_ordered_tx_ids=("tx1", "tx2"),
    )


def test_helper_receipt_profile_stripping_and_unknown_profile_fail() -> None:
    pubkey, privkey = deterministic_mldsa_keypair(label="p2-a13-helper-receipt")
    receipt = sign_helper_receipt(
        chain_id="weall-testnet-v1",
        height=7,
        validator_epoch=1,
        validator_set_hash="set-hash",
        parent_block_id="parent",
        lane_id="PARALLEL_CONTENT",
        ordered_tx_ids=("tx1", "tx2"),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="helper-a",
        plan_id="plan-p2",
        privkey=privkey,
        sig_profile="pq-mldsa-v1",
    )

    assert _receipt_verify(receipt, pubkey) is True
    assert _receipt_verify(replace(receipt, sig_profile=""), pubkey) is False
    assert (
        _receipt_verify(replace(receipt, sig_profile="unknown-profile"), pubkey) is False
    )


def _unsigned_certificate() -> HelperExecutionCertificate:
    return HelperExecutionCertificate(
        domain=CERTIFICATE_DOMAIN,
        chain_id="weall-testnet-v1",
        block_height=9,
        view=5,
        leader_id="v1",
        helper_id="v2",
        validator_epoch=3,
        validator_set_hash="validator-hash",
        lane_id="PARALLEL_CONTENT",
        tx_ids=("t1", "t2"),
        tx_order_hash="order",
        receipts_root="receipts",
        write_set_hash="writes",
        read_set_hash="reads",
        lane_delta_hash="delta",
        namespace_hash=make_namespace_hash(["content:post:1"]),
        plan_id="plan-p2",
        sig_profile="pq-mldsa-v1",
    )


def test_helper_certificate_binds_domain_and_explicit_profile() -> None:
    pubkey, privkey = deterministic_mldsa_keypair(label="p2-a13-helper-certificate")
    signed = sign_helper_certificate(
        _unsigned_certificate(),
        privkey=privkey,
        sig_profile="pq-mldsa-v1",
    )
    assert isinstance(signed, HelperExecutionCertificate)
    assert signed.domain == CERTIFICATE_DOMAIN
    assert verify_helper_certificate_signature(signed, helper_pubkey=pubkey) is True

    domain_mutation = HelperExecutionCertificate(
        **{**signed.to_json(), "domain": "WEALL/HELPER_RECEIPT/V1"}
    )
    assert (
        verify_helper_certificate_signature(domain_mutation, helper_pubkey=pubkey)
        is False
    )

    stripped = signed.to_json()
    stripped.pop("domain")
    assert verify_helper_certificate_signature(stripped, helper_pubkey=pubkey) is False

    stripped_profile = signed.to_json()
    stripped_profile.pop("sig_profile")
    assert (
        verify_helper_certificate_signature(stripped_profile, helper_pubkey=pubkey)
        is False
    )

    unknown_profile = {**signed.to_json(), "sig_profile": "unknown-profile"}
    assert (
        verify_helper_certificate_signature(unknown_profile, helper_pubkey=pubkey)
        is False
    )


def test_helper_receipt_signature_cannot_authorize_certificate() -> None:
    pubkey, privkey = deterministic_mldsa_keypair(label="p2-a13-cross-object")
    receipt = sign_helper_receipt(
        chain_id="weall-testnet-v1",
        height=9,
        validator_epoch=3,
        validator_set_hash="validator-hash",
        parent_block_id="parent",
        lane_id="PARALLEL_CONTENT",
        ordered_tx_ids=("t1", "t2"),
        input_state_hash="in",
        output_state_hash="out",
        helper_id="v2",
        plan_id="plan-p2",
        privkey=privkey,
        sig_profile="pq-mldsa-v1",
    )
    forged = HelperExecutionCertificate(
        **{**_unsigned_certificate().to_json(), "helper_signature": receipt.signature}
    )
    assert verify_helper_certificate_signature(forged, helper_pubkey=pubkey) is False
