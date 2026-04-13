from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _register_account(ex: WeAllExecutor, signer: str) -> None:
    res = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert res["ok"] is True


def test_restart_rejects_mempool_selection_policy_mismatch_batch109(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")

    db_path = str(tmp_path / "policy.db")
    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch109-policy",
        tx_index_path=_tx_index_path(),
    )
    assert ex.read_state().get("meta", {}).get("mempool_selection_policy") == "canonical"

    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "fifo")
    with pytest.raises(ExecutorError, match="mempool_selection_policy mismatch"):
        WeAllExecutor(
            db_path=db_path,
            node_id="@node",
            chain_id="batch109-policy",
            tx_index_path=_tx_index_path(),
        )


def test_apply_block_rejects_remote_mempool_selection_policy_mismatch_batch109(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")

    leader = WeAllExecutor(
        db_path=str(tmp_path / "leader.db"),
        node_id="@leader",
        chain_id="batch109-remote",
        tx_index_path=_tx_index_path(),
    )
    follower = WeAllExecutor(
        db_path=str(tmp_path / "follower.db"),
        node_id="@follower",
        chain_id="batch109-remote",
        tx_index_path=_tx_index_path(),
    )

    _register_account(leader, "@alice")
    block, _new_state, _applied_ids, _invalid_ids, err = leader.build_block_candidate(max_txs=10)
    assert err == ""
    assert block is not None
    block["mempool_selection"] = dict(block.get("mempool_selection") or {})
    block["mempool_selection"]["policy"] = "fifo"

    meta = follower.apply_block(block)
    assert meta.ok is False
    assert meta.error == "bad_block:mempool_selection_policy_mismatch"


def test_build_block_candidate_uses_pinned_policy_when_runtime_policy_drifts_batch109(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "drift.db"),
        node_id="@node",
        chain_id="batch109-drift",
        tx_index_path=_tx_index_path(),
    )
    _register_account(ex, "@alice")

    ex.state.setdefault("meta", {})["mempool_selection_policy"] = "fifo"
    block, _new_state, _applied_ids, _invalid_ids, err = ex.build_block_candidate(max_txs=10)
    assert err == ""
    assert block is not None
    assert block.get("mempool_selection", {}).get("policy") == "fifo"
