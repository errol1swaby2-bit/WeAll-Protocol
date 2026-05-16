from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=f"p:{max(0, nonce - 1)}" if system else None,
        system=system,
    )


def _state() -> dict:
    return {
        "accounts": {
            "@alice": {
                "poh_tier": 0,
                "devices": {
                    "by_id": {
                        "node:alice": {
                            "device_id": "node:alice",
                            "device_type": "node",
                            "pubkey": "node-pub-alice",
                            "revoked": False,
                        }
                    }
                },
            },
            "@plain": {"poh_tier": 0, "devices": {"by_id": {}}},
        },
        "peers": {
            "ads": {
                "@genesis": {
                    "account_id": "@genesis",
                    "peer_id": "genesis-node",
                    "endpoint": "https://genesis.example.test",
                }
            }
        },
    }


def test_peer_request_connect_requires_registered_node_device_batch347() -> None:
    st = _state()

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("PEER_REQUEST_CONNECT", "@plain", 1, {"endpoint": "https://genesis.example.test"}))

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "peer_request_connect_requires_registered_node_device"


def test_peer_request_connect_accepts_endpoint_bootstrap_with_node_binding_batch347() -> None:
    st = _state()

    out = apply_tx(st, _env("PEER_REQUEST_CONNECT", "@alice", 1, {"peer_id": "genesis-node", "endpoint": "https://genesis.example.test"}))

    assert out["applied"] == "PEER_REQUEST_CONNECT"
    rec = st["peers"]["connect_requests"][0]
    assert rec["from"] == "@alice"
    assert rec["from_node_pubkeys"] == ["node-pub-alice"]
    assert rec["to_peer_id"] == "genesis-node"


def test_peer_request_connect_rejects_unadvertised_peer_without_endpoint_or_ticket_batch347() -> None:
    st = _state()

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("PEER_REQUEST_CONNECT", "@alice", 1, {"peer_id": "unknown-peer"}))

    assert exc.value.code == "forbidden"
    assert exc.value.reason == "peer_request_connect_target_not_advertised"


def test_peer_request_connect_rejects_invalid_endpoint_batch347() -> None:
    st = _state()

    with pytest.raises(ApplyError) as exc:
        apply_tx(st, _env("PEER_REQUEST_CONNECT", "@alice", 1, {"endpoint": "not-a-network-endpoint"}))

    assert exc.value.code == "invalid_payload"
    assert exc.value.reason == "invalid_endpoint"
