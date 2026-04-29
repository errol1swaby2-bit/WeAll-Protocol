from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def _make_executor(tmp_path: Path, monkeypatch) -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_DIRTY_SIGNING", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_SIGNING_ENABLED", raising=False)

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)
    return WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )


def test_prod_runtime_forces_observer_when_validator_count_drops_below_bft_minimum(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = [
        "@v1",
        "@v2",
        "@v3",
    ]
    ex.state.setdefault("consensus", {}).setdefault("phase", {})["current"] = "bft_active"

    assert ex.validator_signing_enabled() is False
    assert ex.observer_mode() is True

    diag = ex.bft_diagnostics()
    assert diag["validator_signing_enabled"] is False
    assert diag["observer_mode"] is True
    assert diag["signing_block_reason"] == "validator_count_below_bft_minimum:3/4"


def test_prod_runtime_forces_observer_until_committed_phase_is_bft_active(
    tmp_path: Path, monkeypatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    ex.state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = [
        "@v1",
        "@v2",
        "@v3",
        "@v4",
    ]
    ex.state.setdefault("consensus", {}).setdefault("phase", {})["current"] = (
        "multi_validator_bootstrap"
    )

    assert ex.validator_signing_enabled() is False
    assert ex.observer_mode() is True

    diag = ex.bft_diagnostics()
    assert diag["signing_block_reason"] == (
        "consensus_phase_not_bft_active:multi_validator_bootstrap"
    )

    ex.state.setdefault("consensus", {}).setdefault("phase", {})["current"] = "bft_active"
    assert ex.validator_signing_enabled() is True
    assert ex.observer_mode() is False
    diag2 = ex.bft_diagnostics()
    assert diag2["validator_signing_enabled"] is True
    assert diag2["observer_mode"] is False
    assert diag2["signing_block_reason"] == ""
