from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_canonical_mempool_selection_orders_candidate_independently_of_arrival(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id="batch108-canonical",
        tx_index_path=tx_index_path,
    )

    for signer in ["@carol", "@alice", "@bob"]:
        sub = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
        )
        assert sub["ok"] is True

    blk, _st2, applied_ids, _invalid_ids, err = ex.build_block_candidate(max_txs=10)
    assert err == ""
    assert blk is not None
    assert [str(tx.get("signer") or "") for tx in list(blk.get("txs") or [])[:3]] == [
        "@alice",
        "@bob",
        "@carol",
    ]
    assert len(applied_ids) == 3

    diag = ex.mempool_selection_diagnostics(preview_limit=10)
    assert diag["policy"] == "canonical"
    assert diag["last_candidate"]["selected_count"] == 3
    assert diag["last_candidate"]["requested_limit"] == 10
    assert len(diag["last_candidate"]["selected_tx_ids"]) == 3


def test_canonical_policy_is_default_for_plain_mempool_reads(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("WEALL_MEMPOOL_SELECTION_POLICY", raising=False)
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id="batch108-fifo",
        tx_index_path=tx_index_path,
    )

    for signer in ["@carol", "@alice", "@bob"]:
        sub = ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
        )
        assert sub["ok"] is True

    items = ex.read_mempool(limit=10)
    assert [str(tx.get("signer") or "") for tx in items[:3]] == ["@alice", "@bob", "@carol"]
    diag = ex.mempool_selection_diagnostics(preview_limit=10)
    assert diag["policy"] == "canonical"
