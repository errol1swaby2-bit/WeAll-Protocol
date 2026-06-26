from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from weall.net.codec import decode_message, encode_message
from weall.net.gossip import (
    PeerAddrGossipConfig,
    filter_peer_addr_records,
    make_peer_addr_record,
    verify_peer_addr_record,
)
from weall.net.messages import MsgType, PeerAddrMsg, PeerGetAddrMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.testing.sigtools import deterministic_ed25519_keypair


class _DummyMempool:
    pass


class _SimpleExecutor:
    chain_id = "chain-A"
    tx_index = None

    def read_state(self):
        return self.snapshot()
    def snapshot(self) -> dict[str, Any]:
        return {}

    def tx_index_hash(self) -> str:
        return "hash-A"


def _priv_hex(label: str) -> tuple[str, str]:
    pub, sk = deterministic_ed25519_keypair(label=label)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    return pub, priv


def _cfg() -> NetConfig:
    return NetConfig(
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        peer_id="node-a",
        advertise_uri="tcp://node-a.example:30303",
    )


def _header(t: MsgType) -> WireHeader:
    return WireHeader(type=t, chain_id="chain-A", schema_version="1", tx_index_hash="hash-A")


def test_peer_addr_codec_round_trips_batch313() -> None:
    rec = make_peer_addr_record(
        uri="tcp://node-b.example:30303",
        peer_id="node-b",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        now_ms=1000,
    )
    msg = PeerAddrMsg(header=_header(MsgType.PEER_ADDR), addrs=(rec,))

    decoded = decode_message(encode_message(msg))

    assert isinstance(decoded, PeerAddrMsg)
    assert decoded.header.type == MsgType.PEER_ADDR
    assert decoded.addrs[0]["uri"] == "tcp://node-b.example:30303"


def test_signed_peer_addr_record_verifies_and_tampering_fails_batch313() -> None:
    pub, priv = _priv_hex("node-b")
    cfg = PeerAddrGossipConfig(
        chain_id="chain-A", schema_version="1", tx_index_hash="hash-A", allow_unsigned=False
    )
    rec = make_peer_addr_record(
        uri="tls://node-b.example:30303",
        peer_id="node-b",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        now_ms=1000,
        ttl_ms=60_000,
        pubkey=pub,
        privkey=priv,
    )

    assert verify_peer_addr_record(rec, cfg=cfg, now_ms=2000) is True

    tampered = dict(rec)
    tampered["uri"] = "tls://evil.example:30303"
    assert verify_peer_addr_record(tampered, cfg=cfg, now_ms=2000) is False

    wrong_chain = dict(rec)
    wrong_chain["chain_id"] = "chain-B"
    assert verify_peer_addr_record(wrong_chain, cfg=cfg, now_ms=2000) is False

    expired = dict(rec)
    expired["expires_at_ms"] = 1500
    assert verify_peer_addr_record(expired, cfg=cfg, now_ms=2000) is False


def test_filter_peer_addr_records_dedupes_bounds_and_rejects_incompatible_batch313() -> None:
    cfg = PeerAddrGossipConfig(
        chain_id="chain-A", schema_version="1", tx_index_hash="hash-A", max_addrs_per_message=2
    )
    good_a = make_peer_addr_record(
        uri="tcp://node-a.example:30303",
        peer_id="node-a",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        now_ms=1000,
    )
    duplicate_a = dict(good_a)
    good_b = make_peer_addr_record(
        uri="tls://node-b.example:30303",
        peer_id="node-b",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        now_ms=1000,
    )
    good_c = make_peer_addr_record(
        uri="tcp://node-c.example:30303",
        peer_id="node-c",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        now_ms=1000,
    )
    bad_scheme = dict(good_a)
    bad_scheme["uri"] = "http://node-x.example"
    bad_hash = dict(good_a)
    bad_hash["uri"] = "tcp://node-y.example:30303"
    bad_hash["tx_index_hash"] = "other"

    out = filter_peer_addr_records(
        [good_a, duplicate_a, bad_scheme, bad_hash, good_b, good_c], cfg=cfg, now_ms=2000
    )

    assert [rec["uri"] for rec in out] == [
        "tcp://node-a.example:30303",
        "tls://node-b.example:30303",
    ]


def test_netnode_getaddr_returns_bounded_compatible_records_batch313() -> None:
    provider_records = [
        "tcp://node-b.example:30303",
        "http://not-supported.example",
        make_peer_addr_record(
            uri="tcp://wrong-chain.example:30303",
            peer_id="wrong",
            chain_id="chain-B",
            schema_version="1",
            tx_index_hash="hash-A",
            now_ms=1000,
        ),
    ]
    node = NetNode(
        cfg=_cfg(),
        peer_policy=PeerPolicy(max_addr_records_per_message=2),
        peer_addr_provider=lambda: provider_records,
    )

    resp = node._handle_peer_getaddr(
        "peer-x", PeerGetAddrMsg(header=_header(MsgType.PEER_GETADDR), max_addrs=10)
    )

    assert isinstance(resp, PeerAddrMsg)
    assert len(resp.addrs) == 2
    assert [r["uri"] for r in resp.addrs] == [
        "tcp://node-a.example:30303",
        "tcp://node-b.example:30303",
    ]


def test_netnode_accepts_peer_addr_records_via_callback_batch313() -> None:
    accepted: list[tuple[str, tuple[dict[str, Any], ...]]] = []
    good = make_peer_addr_record(
        uri="tcp://node-b.example:30303",
        peer_id="node-b",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
    )
    bad = dict(good)
    bad["uri"] = "http://node-c.example"
    node = NetNode(
        cfg=_cfg(),
        on_peer_addr_records=lambda peer_id, records: accepted.append((peer_id, records)),
    )
    node._ensure_peer("peer-x")

    node._handle_peer_addr("peer-x", PeerAddrMsg(header=_header(MsgType.PEER_ADDR), addrs=(good, bad)))

    assert accepted == [("peer-x", (good,))]
    dbg = node.peers_debug()
    peer = {p["peer_id"]: p for p in dbg["peers"]}["peer-x"]
    assert peer["addr_records_received"] == 2
    assert peer["addr_records_accepted"] == 1
    assert peer["addr_records_rejected"] == 1


def test_net_loop_merges_learned_addr_records_into_peer_store_batch313(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    peers_file = tmp_path / "peers.txt"
    monkeypatch.setenv("WEALL_PEERS_FILE", str(peers_file))
    loop = NetMeshLoop(
        executor=_SimpleExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(
            enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"
        ),
    )
    rec = make_peer_addr_record(
        uri="tcp://learned.example:30303",
        peer_id="learned",
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
    )

    loop._on_peer_addr_records("peer-x", (rec,))

    assert "tcp://learned.example:30303" in peers_file.read_text(encoding="utf-8")
