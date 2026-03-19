from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import MAX_BLOCK_TIME_ADVANCE_MS, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str, chain_id: str) -> WeAllExecutor:
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(
        db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path
    )


def test_apply_block_rejects_timestamp_beyond_chain_time_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    leader = _make_executor(tmp_path, node_id="@leader", chain_id="ts-rx")
    follower = _make_executor(tmp_path, node_id="@follower", chain_id="ts-rx")

    sub = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user000",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True

    future_ts_ms = MAX_BLOCK_TIME_ADVANCE_MS + 60_000
    blk, _st2, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=1, force_ts_ms=future_ts_ms
    )
    assert err == "invalid_block_ts:beyond_chain_time_window"
    assert blk is None

    forced_ts_ms = future_ts_ms
    blk = {
        "block_id": "",
        "height": 1,
        "prev_block_id": "",
        "prev_block_hash": "",
        "block_ts_ms": forced_ts_ms,
        "header": {
            "chain_id": "ts-rx",
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": forced_ts_ms,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "",
        },
        "txs": [],
        "receipts": [],
    }

    meta = follower.apply_block(blk)
    assert meta.ok is False
    assert meta.error == "bad_block:ts_beyond_chain_time_window"
    assert int(follower.read_state().get("height", 0) or 0) == 0


def test_apply_block_rejects_timestamp_before_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    leader = _make_executor(tmp_path, node_id="@leader", chain_id="ts-rx-2")
    follower = _make_executor(tmp_path, node_id="@follower", chain_id="ts-rx-2")

    sub = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user000",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True

    blk1, _st1, _applied1, _invalid1, err1 = leader.build_block_candidate(
        max_txs=1, force_ts_ms=1_000
    )
    assert err1 == ""
    assert blk1 is not None

    meta1 = follower.apply_block(blk1)
    assert meta1.ok is True
    tip_ts_ms = int(follower.read_state().get("tip_ts_ms", 0) or 0)
    assert tip_ts_ms > 0

    blk2 = {
        "block_id": "",
        "height": 2,
        "prev_block_id": str(follower.read_state().get("tip") or ""),
        "prev_block_hash": str(follower.read_state().get("tip_hash") or ""),
        "block_ts_ms": tip_ts_ms - 1,
        "header": {
            "chain_id": "ts-rx-2",
            "height": 2,
            "prev_block_hash": str(follower.read_state().get("tip_hash") or ""),
            "block_ts_ms": tip_ts_ms - 1,
            "tx_ids": [],
            "receipts_root": "",
            "state_root": "",
        },
        "txs": [],
        "receipts": [],
    }

    meta2 = follower.apply_block(blk2)
    assert meta2.ok is False
    assert meta2.error == "bad_block:ts_before_chain_floor"
    assert int(follower.read_state().get("height", 0) or 0) == 1


def test_build_block_candidate_rejects_timestamp_before_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="ts-local")
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user000",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True
    meta1 = ex.produce_block(max_txs=1)
    assert meta1.ok is True

    tip_ts_ms = int(ex.read_state().get("tip_ts_ms", 0) or 0)
    blk2, _st2, _applied2, _invalid2, err2 = ex.build_block_candidate(
        max_txs=1, allow_empty=True, force_ts_ms=tip_ts_ms - 1
    )
    assert blk2 is None
    assert err2 == "invalid_block_ts:before_chain_floor"


def test_build_block_candidate_accepts_timestamp_independent_of_wall_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    ex = _make_executor(tmp_path, node_id="@leader", chain_id="ts-local-2")
    blk, _st2, _applied2, _invalid2, err = ex.build_block_candidate(
        allow_empty=True, force_ts_ms=MAX_BLOCK_TIME_ADVANCE_MS
    )
    assert err == ""
    assert blk is not None
    assert int(blk.get("block_ts_ms") or 0) == MAX_BLOCK_TIME_ADVANCE_MS
