from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_canonical_mempool_selection_last_candidate_survives_restart_batch111(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / "node.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch111-selection-restart",
        tx_index_path=tx_index_path,
    )

    for signer in ["@carol", "@alice", "@bob"]:
        sub = ex1.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": signer,
                "nonce": 1,
                "payload": {"pubkey": f"k:{signer}"},
            }
        )
        assert sub["ok"] is True

    meta = ex1.produce_block(max_txs=10)
    assert meta.ok is True
    assert meta.height == 1

    diag1 = ex1.mempool_selection_diagnostics(preview_limit=10)
    assert diag1["policy"] == "canonical"
    assert diag1["last_candidate"]["selected_count"] == 3
    assert diag1["last_candidate"]["selected_tx_ids"]

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch111-selection-restart",
        tx_index_path=tx_index_path,
    )

    diag2 = ex2.mempool_selection_diagnostics(preview_limit=10)
    assert diag2["policy"] == "canonical"
    assert diag2["last_candidate"]["policy"] == "canonical"
    assert diag2["last_candidate"]["selected_count"] == 3
    assert diag2["last_candidate"]["invalid_count"] == 0
    assert diag2["last_candidate"]["rejected_count"] == 0
    assert len(diag2["last_candidate"]["selected_tx_ids"]) == 3

    state_meta = (ex2.read_state().get("meta") or {}) if isinstance(ex2.read_state(), dict) else {}
    assert isinstance(state_meta.get("mempool_selection_last"), dict)
    assert state_meta["mempool_selection_last"]["policy"] == "canonical"


def test_default_canonical_selection_persistence_survives_restart_without_overwriting_policy_batch111(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("WEALL_MEMPOOL_SELECTION_POLICY", raising=False)
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / "node.db")

    ex1 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch111-selection-default",
        tx_index_path=tx_index_path,
    )
    sub = ex1.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:@alice"},
        }
    )
    assert sub["ok"] is True
    meta = ex1.produce_block(max_txs=1)
    assert meta.ok is True

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch111-selection-default",
        tx_index_path=tx_index_path,
    )
    diag = ex2.mempool_selection_diagnostics(preview_limit=10)
    assert diag["policy"] == "canonical"
    assert diag["last_candidate"]["policy"] == "canonical"
    assert diag["last_candidate"]["selected_count"] == 1
