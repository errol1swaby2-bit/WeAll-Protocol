from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "votecheck-dos") -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    ex = WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    if not hasattr(ex, "_pending_missing_fetches"):
        ex._pending_missing_fetches = {}  # type: ignore[attr-defined]
    return ex


def _produce_register_block(ex: WeAllExecutor, signer: str, nonce: int) -> dict:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}:{nonce}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    blk = ex.get_latest_block()
    assert isinstance(blk, dict)
    return blk


def test_votecheck_per_proposer_budget_window_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_PEER_MAX_PER_WINDOW", "1")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_PEER_WINDOW_MS", "60000")

    leader = _make_executor(tmp_path, "leader", chain_id="votecheck-budget")
    follower = _make_executor(tmp_path, "follower", chain_id="votecheck-budget")

    blk1 = _produce_register_block(leader, "@u1", 1)
    blk2 = _produce_register_block(leader, "@u2", 1)
    blk3 = _produce_register_block(leader, "@u3", 1)

    meta = follower.apply_block(blk1)
    assert meta.ok is True

    blk2["proposer"] = "peer-A"
    blk3["proposer"] = "peer-A"

    assert follower._validate_remote_proposal_for_vote(blk2) is True
    assert follower._validate_remote_proposal_for_vote(blk3) is False

    diag = follower.bft_diagnostics()
    assert diag["votecheck_peer_budget_entries"] >= 1


def test_votecheck_global_limiter_fails_closed_when_all_slots_busy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_CONCURRENT", "1")

    leader = _make_executor(tmp_path, "leader", chain_id="votecheck-limit")
    follower = _make_executor(tmp_path, "follower", chain_id="votecheck-limit")

    blk = _produce_register_block(leader, "@u1", 1)
    blk["proposer"] = "peer-B"

    acquired = follower._proposal_validation_semaphore.acquire(blocking=False)
    assert acquired is True
    try:
        assert follower._validate_remote_proposal_for_vote(blk) is False
    finally:
        follower._proposal_validation_semaphore.release()

    diag = follower.bft_diagnostics()
    assert diag["votecheck_concurrency_limit"] == 1


def test_votecheck_reuses_spec_exec_pool_slots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_CONCURRENT", "2")
    monkeypatch.setenv("WEALL_BFT_SPEC_EXEC_POOL_SIZE", "2")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_PEER_MAX_PER_WINDOW", "10")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_PEER_WINDOW_MS", "60000")

    leader = _make_executor(tmp_path, "leader", chain_id="votecheck-pool")
    follower = _make_executor(tmp_path, "follower", chain_id="votecheck-pool")

    blk1 = _produce_register_block(leader, "@u1", 1)
    blk2 = _produce_register_block(leader, "@u2", 1)
    blk3 = _produce_register_block(leader, "@u3", 1)

    meta = follower.apply_block(blk1)
    assert meta.ok is True

    blk2["proposer"] = "peer-C"
    blk3["proposer"] = "peer-C"

    assert follower._validate_remote_proposal_for_vote(blk2) is True
    diag1 = follower.bft_diagnostics()
    assert diag1["votecheck_spec_exec_pool_size"] == 1

    # Make blk3's parent locally known while keeping blk3 itself remote.
    meta2 = follower.apply_block(blk2)
    assert meta2.ok is True

    assert follower._validate_remote_proposal_for_vote(blk3) is True
    diag2 = follower.bft_diagnostics()
    assert diag2["votecheck_spec_exec_pool_size"] == 1
    assert diag2["votecheck_concurrency_limit"] == 2
