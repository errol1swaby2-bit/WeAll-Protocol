from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_executor_warns_and_forces_observer_mode_when_tip_is_far_ahead_of_local_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prod restart stays chain-time safe and degrades to observer mode on huge skew.

    Normal consensus validity follows chain time. A catastrophically future-skewed tip
    should no longer prevent startup, but it must leave clear diagnostics and block
    automatic validator signing until an operator verifies the node.
    """
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="ts-policy", tx_index_path=tx_index_path
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user000",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    ex.mark_clean_shutdown()
    st1 = ex.read_state()
    assert int(st1.get("height", 0)) == 1

    import time

    canonical_tip = ex.get_block_by_height(1)
    assert isinstance(canonical_tip, dict)
    canonical_tip_ts_ms = int(
        canonical_tip.get("block_ts_ms") or canonical_tip.get("created_ms") or 0
    )
    assert canonical_tip_ts_ms > 0

    poisoned_tip_ts_ms = int(time.time() * 1000) + 10_000_000_000
    st1["tip_ts_ms"] = poisoned_tip_ts_ms
    ex._ledger_store.write_state_snapshot(st1)  # type: ignore[attr-defined]

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_UNSAFE_DEV", raising=False)
    monkeypatch.delenv("WEALL_SIGVERIFY", raising=False)
    ex2 = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="ts-policy", tx_index_path=tx_index_path
    )
    assert ex2.observer_mode() is True
    restarted_state = ex2.read_state()
    assert int(restarted_state.get("tip_ts_ms") or 0) == canonical_tip_ts_ms
    warning = (
        (restarted_state.get("meta") or {}) if isinstance(restarted_state.get("meta"), dict) else {}
    ).get("clock_warning")
    assert isinstance(warning, dict)
    assert int(warning.get("canonical_tip_ts_ms") or 0) == canonical_tip_ts_ms
    assert int(warning.get("persisted_tip_ts_ms") or 0) == poisoned_tip_ts_ms
    assert int(warning.get("diagnostic_tip_ts_ms") or 0) == poisoned_tip_ts_ms
    assert bool(warning.get("tip_ts_rebound", False)) is True
    assert bool(warning.get("observer_mode_forced", False)) is True
    assert bool(warning.get("startup_blocked", True)) is False

    # Canonicalization must not silently clear the operator-safety quarantine on
    # the next clean restart. The persisted warning remains diagnostic authority
    # for observer posture until the operator intentionally overrides it.
    ex2.mark_clean_shutdown()
    ex3 = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="ts-policy",
        tx_index_path=tx_index_path,
    )
    assert int(ex3.read_state().get("tip_ts_ms") or 0) == canonical_tip_ts_ms
    assert ex3.observer_mode() is True
    warning3 = (
        (ex3.read_state().get("meta") or {})
        if isinstance(ex3.read_state().get("meta"), dict)
        else {}
    ).get("clock_warning")
    assert isinstance(warning3, dict)
    assert bool(warning3.get("observer_mode_forced", False)) is True
