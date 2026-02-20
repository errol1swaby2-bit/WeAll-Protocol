from __future__ import annotations

from typing import Any, Dict

import pytest

from weall.net.messages import MsgType, PeerHello, WireHeader
from weall.net.peer_identity import verify_peer_hello_identity
from weall.runtime.domain_apply import apply_tx


Json = Dict[str, Any]


def _env(
    tx_type: str,
    payload: Json | None = None,
    *,
    signer: str = "acc1",
    nonce: int = 1,
    sig: str = "",
    system: bool = False,
) -> Json:
    # Matches the project’s existing test style: apply_tx(st, _env(...))
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": int(nonce),
        "payload": dict(payload or {}),
        "sig": sig,
        "system": bool(system),
    }


def _hello(*, account_id: str, pubkey: str, sig: str, chain_id: str = "weall", schema: str = "1", tx_index_hash: str = "txindex") -> PeerHello:
    return PeerHello(
        header=WireHeader(
            type=MsgType.PEER_HELLO,
            chain_id=chain_id,
            schema_version=schema,
            tx_index_hash=tx_index_hash,
            sent_ts_ms=123,
            corr_id=None,
        ),
        peer_id=account_id,
        agent="test-agent",
        nonce="n1",
        caps=(),
        identity={"pubkey": pubkey, "sig": sig},
    )


def test_account_device_register_enforces_one_node_device() -> None:
    st: Json = {}

    # Register account with an initial key
    apply_tx(st, _env("ACCOUNT_REGISTER", {"pubkey": "pk1"}, signer="acc1", nonce=1))

    # Register first node device
    apply_tx(
        st,
        _env(
            "ACCOUNT_DEVICE_REGISTER",
            {"device_id": "node:acc1", "device_type": "node", "label": "node", "pubkey": "pk1"},
            signer="acc1",
            nonce=2,
        ),
    )

    # Attempt to register a second node device for same account -> MUST fail
    with pytest.raises(Exception) as e:
        apply_tx(
            st,
            _env(
                "ACCOUNT_DEVICE_REGISTER",
                {"device_id": "node:acc1:alt", "device_type": "node", "label": "node-alt", "pubkey": "pk1"},
                signer="acc1",
                nonce=3,
            ),
        )

    # Fail-closed reason should be visible in error string
    assert "one_node_per_account" in str(e.value)


def test_peer_identity_requires_node_device_then_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    st: Json = {}

    # Create account with active pubkey, but NO node device yet
    apply_tx(st, _env("ACCOUNT_REGISTER", {"pubkey": "pk1"}, signer="acc1", nonce=1))

    # Patch signature verification to True so this test isolates the node-device gate.
    # We only want to validate the new gating rule, not crypto plumbing.
    import weall.net.peer_identity as peer_identity_mod

    monkeypatch.setattr(peer_identity_mod, "verify_ed25519_sig", lambda pubkey, msg_bytes, sig: True)

    hello = _hello(account_id="acc1", pubkey="pk1", sig="sig1")

    ok, reason, account_id, pubkey = verify_peer_hello_identity(hello=hello, ledger=st)
    assert ok is False
    assert reason == "node_device_required"
    assert account_id == "acc1"
    assert pubkey == "pk1"

    # Now register the node device on-chain
    apply_tx(
        st,
        _env(
            "ACCOUNT_DEVICE_REGISTER",
            {"device_id": "node:acc1", "device_type": "node", "label": "node", "pubkey": "pk1"},
            signer="acc1",
            nonce=2,
        ),
    )

    ok2, reason2, account_id2, pubkey2 = verify_peer_hello_identity(hello=hello, ledger=st)
    assert ok2 is True
    assert reason2 == "ok"
    assert account_id2 == "acc1"
    assert pubkey2 == "pk1"
