from __future__ import annotations

import hashlib
import time

import pytest

from weall.net.handshake import (
    HandshakeConfig,
    HandshakeRejected,
    HandshakeState,
    begin_outbound_handshake,
    process_inbound_ack,
    process_inbound_hello,
)
from weall.net.messages import PeerHelloAck
from weall.net.peer_identity import verify_peer_hello_ack_identity, verify_peer_hello_identity
from weall.testing.sigtools import deterministic_mldsa_keypair


def _seed_hex(label: str) -> str:
    return hashlib.sha256(("weall-test-pq-mldsa:" + label).encode("utf-8")).digest().hex()


def _cfg(label: str) -> HandshakeConfig:
    pubkey, _ = deterministic_mldsa_keypair(label=label)
    return HandshakeConfig(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id=label,
        identity_pubkey=pubkey,
        identity_privkey=_seed_hex(label),
        require_identity=True,
    )


def _ledger() -> dict:
    out = {"accounts": {}}
    for label in ("alice", "bob"):
        pubkey, _ = deterministic_mldsa_keypair(label=label)
        out["accounts"][label] = {
            "keys": {pubkey: {"active": True}},
            "devices": {"node:0": {"active": True, "device_type": "node"}},
        }
    return out


def test_strict_mutual_identity_requires_receiver_challenge_and_both_signed_acks() -> None:
    ledger = _ledger()
    alice = HandshakeState(config=_cfg("alice"))
    bob = HandshakeState(config=_cfg("bob"))
    hello = begin_outbound_handshake(alice)
    ok, reason, account, _ = verify_peer_hello_identity(
        hello=hello, ledger=ledger, strict=True, now_ms=int(time.time() * 1000)
    )
    assert (ok, reason, account) == (True, "ok", "alice")
    challenge_ack = process_inbound_hello(bob, hello)
    assert bob.is_established() is False
    assert challenge_ack.phase == "challenge" and challenge_ack.challenge
    ok2, reason2, account2, _ = verify_peer_hello_ack_identity(
        ack=challenge_ack,
        ledger=ledger,
        expected_recipient_peer_id="alice",
        expected_corr_id=str(hello.header.corr_id),
        now_ms=int(time.time() * 1000),
    )
    assert (ok2, reason2, account2) == (True, "ok", "bob")
    challenge_response = process_inbound_ack(alice, challenge_ack)
    assert challenge_response is not None and alice.is_established() is False
    assert challenge_response.nonce == challenge_ack.challenge
    ok3, reason3, account3, _ = verify_peer_hello_identity(
        hello=challenge_response, ledger=ledger, strict=True, now_ms=int(time.time() * 1000)
    )
    assert (ok3, reason3, account3) == (True, "ok", "alice")
    final_ack = process_inbound_hello(bob, challenge_response)
    assert bob.is_established() is True
    assert final_ack.phase == "final" and final_ack.challenge == challenge_ack.challenge
    ok4, reason4, account4, _ = verify_peer_hello_ack_identity(
        ack=final_ack,
        ledger=ledger,
        expected_recipient_peer_id="alice",
        expected_corr_id=str(hello.header.corr_id),
        now_ms=int(time.time() * 1000),
    )
    assert (ok4, reason4, account4) == (True, "ok", "bob")
    assert process_inbound_ack(alice, final_ack) is None
    assert alice.is_established() is True
    replay_ack = process_inbound_hello(bob, challenge_response)
    assert replay_ack.ok is False and replay_ack.reason == "unexpected_peer_hello"


def test_strict_ack_rejects_unsigned_wrong_recipient_and_wrong_correlation() -> None:
    ledger = _ledger()
    alice = HandshakeState(config=_cfg("alice"))
    bob = HandshakeState(config=_cfg("bob"))
    hello = begin_outbound_handshake(alice)
    ack = process_inbound_hello(bob, hello)
    unsigned = PeerHelloAck(
        header=ack.header,
        peer_id=ack.peer_id,
        ok=True,
        caps=ack.caps,
        server_ts_ms=ack.server_ts_ms,
        phase=ack.phase,
        challenge=ack.challenge,
        recipient_peer_id=ack.recipient_peer_id,
        identity=None,
    )
    ok, reason, *_ = verify_peer_hello_ack_identity(
        ack=unsigned,
        ledger=ledger,
        expected_recipient_peer_id="alice",
        expected_corr_id=str(hello.header.corr_id),
        now_ms=int(time.time() * 1000),
    )
    assert ok is False and reason == "missing_pubkey"
    ok2, reason2, *_ = verify_peer_hello_ack_identity(
        ack=ack,
        ledger=ledger,
        expected_recipient_peer_id="mallory",
        expected_corr_id=str(hello.header.corr_id),
        now_ms=int(time.time() * 1000),
    )
    assert ok2 is False and reason2 == "recipient_peer_id_mismatch"
    ok3, reason3, *_ = verify_peer_hello_ack_identity(
        ack=ack,
        ledger=ledger,
        expected_recipient_peer_id="alice",
        expected_corr_id="wrong-corr",
        now_ms=int(time.time() * 1000),
    )
    assert ok3 is False and reason3 == "corr_id_mismatch"


def test_strict_hello_rejects_stale_proof() -> None:
    ledger = _ledger()
    alice = HandshakeState(config=_cfg("alice"))
    hello = begin_outbound_handshake(alice)
    ok, reason, *_ = verify_peer_hello_identity(
        hello=hello,
        ledger=ledger,
        strict=True,
        now_ms=int(hello.header.sent_ts_ms or 0) + 30_001,
        max_clock_skew_ms=30_000,
    )
    assert ok is False and reason == "stale_identity_proof"


def test_process_ack_rejects_wrong_corr_even_when_shape_is_otherwise_valid() -> None:
    alice = HandshakeState(config=_cfg("alice"))
    bob = HandshakeState(config=_cfg("bob"))
    hello = begin_outbound_handshake(alice)
    ack = process_inbound_hello(bob, hello)
    bad = PeerHelloAck(
        header=type(ack.header)(
            type=ack.header.type,
            chain_id=ack.header.chain_id,
            schema_version=ack.header.schema_version,
            tx_index_hash=ack.header.tx_index_hash,
            sent_ts_ms=ack.header.sent_ts_ms,
            corr_id="wrong",
        ),
        peer_id=ack.peer_id,
        ok=ack.ok,
        reason=ack.reason,
        caps=ack.caps,
        server_ts_ms=ack.server_ts_ms,
        phase=ack.phase,
        challenge=ack.challenge,
        recipient_peer_id=ack.recipient_peer_id,
        identity=ack.identity,
    )
    with pytest.raises(HandshakeRejected, match="hello_ack_corr_id_mismatch"):
        process_inbound_ack(alice, bad)
