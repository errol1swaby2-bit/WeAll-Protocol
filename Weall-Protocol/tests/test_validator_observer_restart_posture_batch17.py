from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_unclean_restart_forces_observer_mode_until_clean_shutdown(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_DIRTY_SIGNING", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_SIGNING_ENABLED", raising=False)

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex1 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    assert ex1.validator_signing_enabled() is True
    assert ex1.observer_mode() is False

    ex2 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    assert ex2.validator_signing_enabled() is False
    assert ex2.observer_mode() is True
    diag2 = ex2.bft_diagnostics()
    assert diag2["observer_mode"] is True
    assert diag2["validator_signing_enabled"] is False
    assert diag2["signing_block_reason"] == "unclean_shutdown"

    ex2.mark_clean_shutdown()

    ex3 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    assert ex3.validator_signing_enabled() is True
    assert ex3.observer_mode() is False
