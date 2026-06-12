from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str = "batch600-height") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _register_tx(signer: str, nonce: int = 1) -> dict[str, object]:
    return {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": signer,
        "nonce": nonce,
        "payload": {"pubkey": f"k:{signer}"},
    }


def test_block_candidate_selection_uses_protocol_height_not_wall_clock_expiry_batch600(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _executor(tmp_path)

    env = _register_tx("@alice")
    # This row is wall-clock expired immediately, but is still valid for the
    # candidate at height 1. Block construction must therefore include it when
    # fetch_for_block is height-anchored.
    add = ex.mempool.add(env, current_height=0, expires_at_height=1)
    assert add["ok"] is True

    # The old local-time path would treat the row as expired. Keep this as a
    # regression sentinel proving the block path does not depend on it.
    legacy_wall_clock_view = ex.mempool.fetch_for_block(limit=10, now_ms=int(add["expires_ms"]) + 1)
    assert legacy_wall_clock_view == []

    height_view = ex.mempool.fetch_for_block(limit=10, candidate_height=1)
    assert [str(tx.get("signer") or "") for tx in height_view] == ["@alice"]

    blk, _st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=10)
    assert err == ""
    assert blk is not None
    assert invalid_ids == []
    assert len(applied_ids) == 1
    assert [str(tx.get("signer") or "") for tx in list(blk.get("txs") or [])] == ["@alice"]


def test_mempool_candidate_height_expiry_boundary_is_deterministic_batch600(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _executor(tmp_path, chain_id="batch600-height-boundary")
    add = ex.mempool.add(_register_tx("@alice"), current_height=0, expires_at_height=1)
    assert add["ok"] is True

    assert [str(tx.get("signer") or "") for tx in ex.mempool.fetch_for_block(candidate_height=1)] == [
        "@alice"
    ]
    assert ex.mempool.fetch_for_block(candidate_height=2) == []


def test_mempool_candidate_height_selection_survives_restart_batch600(
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
        chain_id="batch600-height-restart",
        tx_index_path=tx_index_path,
    )
    for signer in ["@carol", "@alice", "@bob"]:
        add = ex1.mempool.add(_register_tx(signer), current_height=0, expires_at_height=1)
        assert add["ok"] is True

    selected1 = [str(tx.get("signer") or "") for tx in ex1.mempool.fetch_for_block(candidate_height=1)]
    assert selected1 == ["@alice", "@bob", "@carol"]

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@node",
        chain_id="batch600-height-restart",
        tx_index_path=tx_index_path,
    )
    selected2 = [str(tx.get("signer") or "") for tx in ex2.mempool.fetch_for_block(candidate_height=1)]
    assert selected2 == selected1
    assert ex2.mempool.fetch_for_block(candidate_height=2) == []
