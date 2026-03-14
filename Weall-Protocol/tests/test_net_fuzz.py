# File: tests/test_net_fuzz.py
from __future__ import annotations

import os
import random

from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.transport import WirePacket


def _cfg() -> NetConfig:
    return NetConfig(chain_id="test", schema_version="1", tx_index_hash="deadbeef", peer_id="me")


def test_fuzz_decode_never_crashes_and_can_ban_on_repeated_decode_fail() -> None:
    # Keep packets under max_packet_bytes but still invalid often.
    pol = PeerPolicy(
        max_strikes=3,
        ban_cooldown_ms=10_000,
        max_packet_bytes=2048,
        strike_decode_fail=1,
    )
    node = NetNode(cfg=_cfg(), peer_policy=pol)

    peer = "tcp://8.8.8.8:1234"

    # Deterministic fuzz seed so CI is stable.
    rng = random.Random(1337)

    # Send many random payloads; node must not raise.
    for _ in range(20):
        n = rng.randint(0, 512)
        payload = bytes(rng.getrandbits(8) for _ in range(n))
        pkt = WirePacket(peer_id=peer, payload=payload, received_at_ms=0, meta=None)
        node._handle_packet(pkt)

        # Once banned, remaining packets should be ignored; still must not crash.
        if node.is_banned(peer):
            break

    # With max_strikes=3 and strike_decode_fail=1, enough bad payloads should ban eventually.
    assert node.is_banned(peer)


def test_fuzz_oversize_is_rejected_without_decode_attempt_and_can_ban() -> None:
    pol = PeerPolicy(
        max_strikes=2,
        ban_cooldown_ms=10_000,
        max_packet_bytes=32,
        strike_decode_fail=1,
    )
    node = NetNode(cfg=_cfg(), peer_policy=pol)

    peer = "tcp://1.1.1.1:9999"

    # Oversize payloads should trigger strikes via oversize gate (not decode).
    pkt = WirePacket(peer_id=peer, payload=b"x" * 33, received_at_ms=0, meta=None)
    node._handle_packet(pkt)
    assert not node.is_banned(peer)

    node._handle_packet(pkt)
    assert node.is_banned(peer)
