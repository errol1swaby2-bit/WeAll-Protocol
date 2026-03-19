from __future__ import annotations

from pathlib import Path

import pytest

from weall.ledger.migrations import migrate_state_dict
from weall.runtime.executor import (
    CLOCK_SKEW_WARN_MS,
    ExecutorError,
    MAX_BLOCK_TIME_ADVANCE_MS,
    STARTUP_CLOCK_HARD_FAIL_MS,
    WeAllExecutor,
)
from weall.runtime.protocol_profile import REPUTATION_SCALE, validate_runtime_consensus_profile


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path)


def test_migration_populates_reputation_milli_from_legacy_float() -> None:
    st = migrate_state_dict(
        {
            "accounts": {
                "@alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": "1.25"}
            }
        }
    )
    acct = st["accounts"]["@alice"]
    assert acct["reputation"] == pytest.approx(1.25)
    assert int(acct["reputation_milli"]) == 1250


def test_prod_rejects_block_time_advance_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_BLOCK_TIME_ADVANCE_MS", str(MAX_BLOCK_TIME_ADVANCE_MS + 1))
    with pytest.raises(ValueError, match="WEALL_MAX_BLOCK_TIME_ADVANCE_MS"):
        validate_runtime_consensus_profile()


def test_restart_rejects_reputation_scale_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _make_executor(tmp_path, node_id="@n1", chain_id="rep-scale")
    ex.mark_clean_shutdown()
    st = ex.read_state()
    st.setdefault("meta", {})["reputation_scale"] = REPUTATION_SCALE + 1
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    with pytest.raises(ExecutorError, match="reputation_scale mismatch"):
        _make_executor(tmp_path, node_id="@n1", chain_id="rep-scale")


def test_prod_restart_warns_but_allows_modest_tip_ahead_of_local_clock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _make_executor(tmp_path, node_id="@n1", chain_id="clock-ahead")
    ex.mark_clean_shutdown()
    st = ex.read_state()
    import time

    st["tip_ts_ms"] = int(time.time() * 1000) + MAX_BLOCK_TIME_ADVANCE_MS + 60_000
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    monkeypatch.setenv("WEALL_MODE", "prod")
    ex2 = _make_executor(tmp_path, node_id="@n1", chain_id="clock-ahead")
    st2 = ex2.read_state()
    clock_warning = ((st2.get("meta") or {}) if isinstance(st2.get("meta"), dict) else {}).get("clock_warning")
    assert isinstance(clock_warning, dict)
    assert int(clock_warning.get("skew_ms") or 0) >= CLOCK_SKEW_WARN_MS
    assert int(clock_warning.get("warning_threshold_ms") or 0) == CLOCK_SKEW_WARN_MS
    assert int(clock_warning.get("startup_hard_fail_threshold_ms") or 0) == STARTUP_CLOCK_HARD_FAIL_MS
    assert bool(clock_warning.get("startup_blocked", False)) is False
    assert ex2.observer_mode() is False


def test_prod_restart_warns_and_forces_observer_mode_when_tip_is_far_ahead_of_local_clock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _make_executor(tmp_path, node_id="@n1", chain_id="clock-ahead-catastrophic")
    ex.mark_clean_shutdown()
    st = ex.read_state()
    import time

    st["tip_ts_ms"] = int(time.time() * 1000) + STARTUP_CLOCK_HARD_FAIL_MS + 60_000
    ex._store.write_state_snapshot(st)  # type: ignore[attr-defined]

    monkeypatch.setenv("WEALL_MODE", "prod")
    ex2 = _make_executor(tmp_path, node_id="@n1", chain_id="clock-ahead-catastrophic")
    st2 = ex2.read_state()
    warning = ((st2.get("meta") or {}) if isinstance(st2.get("meta"), dict) else {}).get("clock_warning")
    assert isinstance(warning, dict)
    assert bool(warning.get("observer_mode_forced", False)) is True
    assert ex2.observer_mode() is True
