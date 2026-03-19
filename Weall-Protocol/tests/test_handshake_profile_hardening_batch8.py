from __future__ import annotations

from weall.net.handshake import (
    HandshakeConfig,
    HandshakeState,
    build_hello,
    process_inbound_hello,
)
from weall.runtime.protocol_profile import runtime_startup_fingerprint


def _cfg(**kwargs):
    base = dict(
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="abc123",
        peer_id="node-a",
        protocol_version="2026.03",
        protocol_profile_hash="profile-1",
        bft_enabled=True,
        validator_epoch=7,
        validator_set_hash="sethash-7",
        require_protocol_profile_match=True,
        require_validator_epoch_match_for_bft=True,
    )
    base.update(kwargs)
    return HandshakeConfig(**base)


def test_handshake_rejects_missing_protocol_profile_metadata_when_required() -> None:
    state = HandshakeState(config=_cfg())
    hello = build_hello(_cfg(peer_id="node-b", protocol_version="", protocol_profile_hash=""))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason in {"protocol_version_missing", "protocol_profile_hash_missing"}


def test_handshake_rejects_missing_validator_metadata_when_bft_required() -> None:
    state = HandshakeState(config=_cfg())
    hello = build_hello(_cfg(peer_id="node-b", validator_epoch=0, validator_set_hash=""))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason in {"validator_epoch_missing", "validator_set_hash_missing"}


def test_runtime_startup_fingerprint_changes_with_validator_metadata() -> None:
    a = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
        bft_enabled=True,
        validator_epoch=7,
        validator_set_hash="sethash-7",
    )
    b = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
        bft_enabled=True,
        validator_epoch=8,
        validator_set_hash="sethash-8",
    )
    assert a["fingerprint"] != b["fingerprint"]
    assert a["validator_epoch"] == 7
    assert a["validator_set_hash"] == "sethash-7"
