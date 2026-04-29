from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import NetMeshLoop
from weall.runtime.executor import WeAllExecutor


def _canon_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "generated" / "tx_index.json")


def test_net_on_tx_rejects_missing_chain_id_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)
    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )
    loop = NetMeshLoop(executor=ex, mempool=ex._mempool, cfg=None)

    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"email": "a@example.com"},
        "sig": "00",
    }
    msg = TxEnvelopeMsg(
        header=WireHeader(
            type=MsgType.TX_ENVELOPE, chain_id="test-chain", schema_version="1", tx_index_hash=""
        ),
        nonce=1,
        tx=tx,
    )
    before = ex._mempool.size()
    loop._on_tx("peer1", msg)
    after = ex._mempool.size()
    assert after == before


def test_net_on_tx_rejects_chain_id_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_ALLOW_LEGACY_SIG_DOMAIN", raising=False)
    ex = WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )
    loop = NetMeshLoop(executor=ex, mempool=ex._mempool, cfg=None)

    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"email": "a@example.com"},
        "sig": "00",
        "chain_id": "other-chain",
    }
    msg = TxEnvelopeMsg(
        header=WireHeader(
            type=MsgType.TX_ENVELOPE, chain_id="test-chain", schema_version="1", tx_index_hash=""
        ),
        nonce=1,
        tx=tx,
    )
    before = ex._mempool.size()
    loop._on_tx("peer1", msg)
    after = ex._mempool.size()
    assert after == before
