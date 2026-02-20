from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_multiple_signers_can_apply_in_one_chain(tmp_path: Path) -> None:
    """Replaces old validator finality threshold test with a basic multi-signer apply invariant."""
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="multi-signer", tx_index_path=tx_index_path)

    # Queue 3 independent signers, then produce 3 blocks (one per tx).
    for i in range(3):
        assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": f"v{i}", "nonce": 1, "payload": {}})["ok"] is True

    for i in range(3):
        meta = ex.produce_block(max_txs=1)
        assert meta.ok is True
        assert meta.height == i + 1

    st = ex.read_state()
    assert int(st.get("height", 0)) == 3
    accounts = st.get("accounts", {})
    assert isinstance(accounts, dict)
    assert "v0" in accounts and "v1" in accounts and "v2" in accounts
