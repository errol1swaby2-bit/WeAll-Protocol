from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict | None = None, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="sig",
        parent=f"p:{max(0, nonce - 1)}" if system else None,
        system=system,
    )


def _registered_node_state() -> dict:
    return {
        "accounts": {
            "@alice": {
                "nonce": 2,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "devices": {
                    "by_id": {
                        "node:@alice:node-pub-1": {
                            "device_id": "node:@alice:node-pub-1",
                            "device_type": "node",
                            "pubkey": "node-pub-1",
                            "revoked": False,
                        }
                    }
                },
            }
        }
    }


def test_peer_advertise_requires_registered_node_device() -> None:
    st = {"accounts": {"@alice": {"nonce": 0, "poh_tier": 0, "devices": {"by_id": {}}}}}
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            st,
            _env(
                "PEER_ADVERTISE",
                "@alice",
                1,
                {"peer_id": "@alice", "endpoint": "https://node.example"},
            ),
        )
    assert excinfo.value.reason == "node_device_required_for_peer_advertise"


def test_peer_advertise_rejects_spoofed_peer_id() -> None:
    st = _registered_node_state()
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            st,
            _env(
                "PEER_ADVERTISE",
                "@alice",
                3,
                {
                    "peer_id": "genesis-node",
                    "device_id": "node:@alice:node-pub-1",
                    "node_pubkey": "node-pub-1",
                    "endpoint": "https://node.example",
                },
            ),
        )
    assert excinfo.value.reason == "peer_id_not_bound_to_node_key"


def test_peer_advertise_accepts_account_bound_node_peer_id() -> None:
    st = _registered_node_state()
    meta = apply_tx(
        st,
        _env(
            "PEER_ADVERTISE",
            "@alice",
            3,
            {
                "peer_id": "node:@alice:node-pub-1",
                "device_id": "node:@alice:node-pub-1",
                "node_pubkey": "node-pub-1",
                "endpoint": "https://node.example",
            },
        ),
    )
    assert meta["applied"] == "PEER_ADVERTISE"
    assert meta["device_id"] == "node:@alice:node-pub-1"
    assert meta["node_pubkey"] == "node-pub-1"
    assert st["peers"]["ads"]["@alice"]["peer_id"] == "node:@alice:node-pub-1"


def test_peer_advertise_rejects_unregistered_node_pubkey() -> None:
    st = _registered_node_state()
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            st,
            _env(
                "PEER_ADVERTISE",
                "@alice",
                3,
                {
                    "peer_id": "@alice",
                    "device_id": "node:@alice:node-pub-1",
                    "node_pubkey": "other-node-pub",
                    "endpoint": "https://node.example",
                },
            ),
        )
    assert excinfo.value.reason == "node_key_not_registered_for_peer_advertise"


def test_peer_advertise_rejects_implausible_endpoint() -> None:
    st = _registered_node_state()
    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            st,
            _env(
                "PEER_ADVERTISE",
                "@alice",
                3,
                {
                    "peer_id": "node:@alice:node-pub-1",
                    "device_id": "node:@alice:node-pub-1",
                    "node_pubkey": "node-pub-1",
                    "endpoint": "not-a-dialable-endpoint",
                },
            ),
        )
    assert excinfo.value.reason == "endpoint_not_plausible"
