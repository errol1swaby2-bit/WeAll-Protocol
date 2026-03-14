from __future__ import annotations

import hashlib

from weall.net.codec import encode_message
from weall.net.messages import BftVoteMsg, MsgType, PeerHello, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.peer_identity import sign_peer_hello_identity
from weall.net.transport import WirePacket
from weall.testing.sigtools import deterministic_ed25519_keypair


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="local")


def _seed_hex(label: str) -> str:
    # Must match weall.testing.sigtools.deterministic_ed25519_keypair seed derivation.
    b = ("weall-test-ed25519:" + label).encode("utf-8")
    return hashlib.sha256(b).digest().hex()


def _pkt(peer_id: str, msg) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=encode_message(msg), received_at_ms=0, meta=None)


def _ledger_for_validator(account_id: str, pubkey_hex: str) -> dict:
    return {
        "roles": {"validators": {"active_set": [account_id]}},
        "accounts": {
            account_id: {
                "keys": {pubkey_hex: {"active": True}},
                "devices": {"node:0": {"active": True, "device_type": "node"}},
            }
        },
    }


def test_bft_vote_requires_identity_and_validator(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "1")

    pubkey, _sk = deterministic_ed25519_keypair(label="alice")
    ledger = _ledger_for_validator("alice", pubkey)

    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000),
        ledger_provider=lambda: ledger,
    )

    # Handshake hello (with identity)
    hdr = WireHeader(type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    ident = sign_peer_hello_identity(
        header=hdr,
        peer_id="alice",
        pubkey=pubkey,
        privkey=_seed_hex("alice"),
        agent="weall-node",
        nonce="",
    )
    hello = PeerHello(header=hdr, peer_id="alice", agent="weall-node", nonce="", caps=(), identity=ident)
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", hello))

    # Now a BFT vote should be accepted (gating passes).
    vh = WireHeader(type=MsgType.BFT_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    vote = {
        "t": "VOTE",
        "chain_id": "test",
        "view": 1,
        "block_id": "b1",
        "parent_id": "b0",
        "signer": "alice",
        "pubkey": pubkey,
        "sig": "00",
    }
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", BftVoteMsg(header=vh, view=1, vote=vote)))

    assert node.is_banned("tcp://9.9.9.9:7777") is False


def test_bft_vote_signer_mismatch_bans_fast(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "1")

    pubkey, _sk = deterministic_ed25519_keypair(label="alice")
    ledger = _ledger_for_validator("alice", pubkey)

    # max_strikes=1 so first violation bans
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=1, ban_cooldown_ms=10_000, strike_handshake_rejected=1),
        ledger_provider=lambda: ledger,
    )

    # Handshake hello (with identity)
    hdr = WireHeader(type=MsgType.PEER_HELLO, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    ident = sign_peer_hello_identity(
        header=hdr,
        peer_id="alice",
        pubkey=pubkey,
        privkey=_seed_hex("alice"),
        agent="weall-node",
        nonce="",
    )
    hello = PeerHello(header=hdr, peer_id="alice", agent="weall-node", nonce="", caps=(), identity=ident)
    node._handle_packet(_pkt("tcp://9.9.9.9:7777", hello))

    # Send a vote with wrong signer.
    vh = WireHeader(type=MsgType.BFT_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef")
    vote = {
        "t": "VOTE",
        "chain_id": "test",
        "view": 1,
        "block_id": "b1",
        "parent_id": "b0",
        "signer": "bob",
        "pubkey": pubkey,
        "sig": "00",
    }

    node._handle_packet(_pkt("tcp://9.9.9.9:7777", BftVoteMsg(header=vh, view=1, vote=vote)))
    assert node.is_banned("tcp://9.9.9.9:7777") is True
