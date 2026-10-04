from __future__ import annotations

import hashlib
import time

from weall.net.codec import encode_message
from weall.net.messages import BftVoteMsg, MsgType, PeerHello, WireHeader
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.peer_identity import sign_peer_hello_identity
from weall.net.transport import WirePacket
from weall.testing.sigtools import deterministic_mldsa_keypair


def _cfg() -> NetConfig:
    pubkey, _sk = deterministic_mldsa_keypair(label="local")
    return NetConfig(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id="local",
        identity_pubkey=pubkey,
        identity_privkey=_seed_hex("local"),
    )


def _seed_hex(label: str) -> str:
    # Must match weall.testing.sigtools.deterministic_mldsa_keypair seed derivation.
    b = ("weall-test-pq-mldsa:" + label).encode("utf-8")
    return hashlib.sha256(b).digest().hex()


def _pkt(peer_id: str, msg) -> WirePacket:
    return WirePacket(peer_id=peer_id, payload=encode_message(msg), received_at_ms=0, meta=None)


def _complete_inbound_identity_handshake(
    node: NetNode, *, transport_peer: str, account_id: str, pubkey: str, label: str
) -> None:
    corr_id = f"corr-{label}"
    rec = node._ensure_peer(transport_peer)
    hs_cfg = rec.router.handshake.config
    hdr = WireHeader(
        type=MsgType.PEER_HELLO,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        sent_ts_ms=int(time.time() * 1000),
        corr_id=corr_id,
    )
    ident = sign_peer_hello_identity(
        header=hdr,
        peer_id=account_id,
        pubkey=pubkey,
        privkey=_seed_hex(label),
        agent="weall-node",
        nonce=corr_id,
    )
    node._handle_packet(
        _pkt(
            transport_peer,
            PeerHello(
                header=hdr,
                peer_id=account_id,
                agent="weall-node",
                nonce=corr_id,
                caps=(),
                identity=ident,
                protocol_version=hs_cfg.protocol_version or None,
                protocol_profile_hash=hs_cfg.protocol_profile_hash or None,
                validator_epoch=hs_cfg.validator_epoch or None,
                validator_set_hash=hs_cfg.validator_set_hash or None,
                bft_enabled=hs_cfg.bft_enabled,
                genesis_bootstrap_profile_hash=hs_cfg.genesis_bootstrap_profile_hash or None,
                genesis_bootstrap_enabled=hs_cfg.genesis_bootstrap_enabled,
                genesis_bootstrap_mode=hs_cfg.genesis_bootstrap_mode or None,
            ),
        )
    )
    rec = node._peers[transport_peer]
    challenge = str(rec.router.handshake.inbound_challenge or "")
    assert challenge
    hdr2 = WireHeader(
        type=MsgType.PEER_HELLO,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        sent_ts_ms=int(time.time() * 1000),
        corr_id=corr_id,
    )
    ident2 = sign_peer_hello_identity(
        header=hdr2,
        peer_id=account_id,
        pubkey=pubkey,
        privkey=_seed_hex(label),
        agent="weall-node",
        nonce=challenge,
    )
    node._handle_packet(
        _pkt(
            transport_peer,
            PeerHello(
                header=hdr2,
                peer_id=account_id,
                agent="weall-node",
                nonce=challenge,
                caps=(),
                identity=ident2,
                protocol_version=hs_cfg.protocol_version or None,
                protocol_profile_hash=hs_cfg.protocol_profile_hash or None,
                validator_epoch=hs_cfg.validator_epoch or None,
                validator_set_hash=hs_cfg.validator_set_hash or None,
                bft_enabled=hs_cfg.bft_enabled,
                genesis_bootstrap_profile_hash=hs_cfg.genesis_bootstrap_profile_hash or None,
                genesis_bootstrap_enabled=hs_cfg.genesis_bootstrap_enabled,
                genesis_bootstrap_mode=hs_cfg.genesis_bootstrap_mode or None,
            ),
        )
    )
    assert rec.router.handshake.is_established()
    assert rec.identity_ok is True


def _ledger_for_validator(account_id: str, pubkey_hex: str) -> dict:
    return {
        "consensus": {"validator_set": {"epoch": 1, "active_set": [account_id]}},
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

    pubkey, _sk = deterministic_mldsa_keypair(label="alice")
    ledger = _ledger_for_validator("alice", pubkey)

    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=3, ban_cooldown_ms=10_000),
        ledger_provider=lambda: ledger,
    )

    _complete_inbound_identity_handshake(
        node, transport_peer="tcp://9.9.9.9:7777", account_id="alice", pubkey=pubkey, label="alice"
    )

    # Now a BFT vote should be accepted (gating passes).
    vh = WireHeader(
        type=MsgType.BFT_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef"
    )
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

    pubkey, _sk = deterministic_mldsa_keypair(label="alice")
    ledger = _ledger_for_validator("alice", pubkey)

    # max_strikes=1 so first violation bans
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_strikes=1, ban_cooldown_ms=10_000, strike_handshake_rejected=1),
        ledger_provider=lambda: ledger,
    )

    _complete_inbound_identity_handshake(
        node, transport_peer="tcp://9.9.9.9:7777", account_id="alice", pubkey=pubkey, label="alice"
    )

    # Send a vote with wrong signer.
    vh = WireHeader(
        type=MsgType.BFT_VOTE, chain_id="test", schema_version="1", tx_index_hash="deadbeef"
    )
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
