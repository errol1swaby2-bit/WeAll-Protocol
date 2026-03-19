# tests/test_e2e_three_node_convergence_apply_blocks.py
from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_three_node_convergence_by_applying_blocks(tmp_path: Path) -> None:
    """E2E smoke: 1 producer node, 2 follower nodes.

    Goal:
      - Node A produces a sequence of blocks with user txs.
      - Node B applies blocks as they arrive ("near real-time").
      - Node C lags behind ("partition/delay") then catches up by applying the same blocks.

    Success criteria:
      - All nodes end at the same height and tip hash.
      - The latest block's receipts_root/state_root match across nodes.

    Note:
      - This test focuses on deterministic execution + apply_block validity checks.
      - It does not attempt reorg/fork-choice; followers never produce conflicting blocks.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")

    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")
    db_c = str(tmp_path / "c.db")

    ex_a = WeAllExecutor(
        db_path=db_a, node_id="@alice", chain_id="conv3", tx_index_path=tx_index_path
    )
    ex_b = WeAllExecutor(
        db_path=db_b, node_id="@bob", chain_id="conv3", tx_index_path=tx_index_path
    )
    ex_c = WeAllExecutor(
        db_path=db_c, node_id="@carol", chain_id="conv3", tx_index_path=tx_index_path
    )

    lagged_blocks: list[dict] = []

    # Produce a short chain with deterministic user txs.
    for i in range(1, 11):
        signer = f"@user{i}"
        ok = ex_a.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
        )
        assert ok["ok"] is True

        meta = ex_a.produce_block(max_txs=1)
        assert meta.ok is True

        blk = ex_a.get_latest_block()
        assert isinstance(blk, dict)

        # Node B applies immediately.
        m_b = ex_b.apply_block(blk)
        assert m_b.ok is True

        # Node C lags; it will apply later.
        lagged_blocks.append(blk)

    # Now node C "catches up" by applying the same blocks in order.
    for blk in lagged_blocks:
        m_c = ex_c.apply_block(blk)
        assert m_c.ok is True

    a_latest = ex_a.get_latest_block()
    b_latest = ex_b.get_latest_block()
    c_latest = ex_c.get_latest_block()

    assert isinstance(a_latest, dict)
    assert isinstance(b_latest, dict)
    assert isinstance(c_latest, dict)

    # Height/tip convergence.
    assert int(a_latest.get("header", {}).get("height") or 0) == int(
        b_latest.get("header", {}).get("height") or 0
    )
    assert int(a_latest.get("header", {}).get("height") or 0) == int(
        c_latest.get("header", {}).get("height") or 0
    )
    assert str(a_latest.get("block_id") or "") == str(b_latest.get("block_id") or "")
    assert str(a_latest.get("block_id") or "") == str(c_latest.get("block_id") or "")

    # Root convergence (if present in headers).
    a_hdr = a_latest.get("header") or {}
    b_hdr = b_latest.get("header") or {}
    c_hdr = c_latest.get("header") or {}

    for root_key in ("receipts_root", "state_root"):
        a_val = str(a_hdr.get(root_key) or "")
        b_val = str(b_hdr.get(root_key) or "")
        c_val = str(c_hdr.get(root_key) or "")
        if a_val or b_val or c_val:
            assert a_val == b_val
            assert a_val == c_val
