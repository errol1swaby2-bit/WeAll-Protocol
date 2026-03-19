from __future__ import annotations

from weall.net.handshake import HandshakeConfig, HandshakeState, build_hello, process_inbound_hello


def _cfg(**kwargs):
    base = dict(
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="abc123",
        peer_id="node-a",
        protocol_version="2026.03-prod.4",
        protocol_profile_hash="profile-1",
        bft_enabled=True,
        validator_epoch=7,
        validator_set_hash="sethash-7",
        require_protocol_profile_match=True,
        require_validator_epoch_match_for_bft=True,
    )
    base.update(kwargs)
    return HandshakeConfig(**base)


def test_handshake_rejects_bft_rejoin_when_local_epoch_metadata_missing() -> None:
    state = HandshakeState(config=_cfg(validator_epoch=0))
    hello = build_hello(_cfg(peer_id="node-b"))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason == "local_validator_epoch_missing"


def test_handshake_rejects_bft_rejoin_when_local_set_hash_metadata_missing() -> None:
    state = HandshakeState(config=_cfg(validator_set_hash=""))
    hello = build_hello(_cfg(peer_id="node-b"))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason == "local_validator_set_hash_missing"


def test_handshake_rejects_bft_rejoin_when_both_sides_omit_validator_metadata() -> None:
    state = HandshakeState(config=_cfg(validator_epoch=0, validator_set_hash=""))
    hello = build_hello(_cfg(peer_id="node-b", validator_epoch=0, validator_set_hash=""))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason == "local_validator_epoch_missing"
