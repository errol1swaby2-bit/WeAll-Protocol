from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_producer_progresses_only_with_applicable_txs(tmp_path: Path) -> None:
    """Old self-attest/finality test replaced with apply semantics smoke:

    - invalid txs do not advance height
    - valid txs advance height
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="apply-smoke", tx_index_path=tx_index_path)

    # Invalid (missing signer) is rejected at mempool.add time.
    bad = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "nonce": 1, "payload": {}})
    assert bad["ok"] is False

    st0 = ex.read_state()
    h0 = int(st0.get("height", 0))

    meta0 = ex.produce_block(max_txs=10)
    assert meta0.ok is True
    assert meta0.height == h0

    # Valid tx => height increases when produced.
    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "u1", "nonce": 1, "payload": {}})["ok"] is True
    meta1 = ex.produce_block(max_txs=1)
    assert meta1.ok is True
    assert meta1.height == h0 + 1
