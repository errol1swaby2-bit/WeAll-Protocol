from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import NetMeshLoop
from weall.runtime.executor import WeAllExecutor


def _canon_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "generated" / "tx_index.json")


def test_on_tx_passes_state_to_sigverify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )
    loop = NetMeshLoop(executor=ex, mempool=ex._mempool, cfg=None)

    seen = {}

    def fake_verify(state, tx):
        seen["state"] = state
        seen["tx"] = tx
        return False

    monkeypatch.setattr("weall.net.net_loop.verify_tx_signature", fake_verify)

    tx = {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {"email": "a@example.com"}, "sig": "00", "chain_id": "test-chain"}
    msg = TxEnvelopeMsg(header=WireHeader(type=MsgType.TX_ENVELOPE, chain_id="test-chain", schema_version="1", tx_index_hash=""), nonce=1, tx=tx)
    loop._on_tx("peer1", msg)

    assert seen["tx"] == tx
    assert isinstance(seen["state"], dict)
