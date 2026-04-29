from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_runtime_open_tracks_previous_shutdown_cleanliness(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_DIRTY_SIGNING", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_SIGNING_ENABLED", raising=False)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex1 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    state1 = ex1.read_state()
    assert ex1.validator_signing_enabled() is True
    assert ex1.observer_mode() is False
    assert state1.get("meta", {}).get("last_shutdown_clean") is True
    assert state1.get("meta", {}).get("runtime_open") is True

    ex2 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    state2 = ex2.read_state()
    assert ex2.validator_signing_enabled() is False
    assert ex2.observer_mode() is True
    assert state2.get("meta", {}).get("last_shutdown_clean") is False
    assert state2.get("meta", {}).get("runtime_open") is True

    ex2.mark_clean_shutdown()
    state2b = ex2.read_state()
    assert state2b.get("meta", {}).get("last_shutdown_clean") is True
    assert state2b.get("meta", {}).get("runtime_open") is False

    ex3 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    state3 = ex3.read_state()
    assert ex3.validator_signing_enabled() is True
    assert ex3.observer_mode() is False
    assert state3.get("meta", {}).get("last_shutdown_clean") is True
    assert state3.get("meta", {}).get("runtime_open") is True
