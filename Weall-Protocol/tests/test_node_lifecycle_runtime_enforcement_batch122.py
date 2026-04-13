from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_helper_requested_but_not_effective_disables_runtime_helper_profile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "helper")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@helper")

    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="node-1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert lifecycle["helper_enabled_requested"] is True
    assert lifecycle["helper_enabled_effective"] is False

    state = ex.read_state()
    meta = state.get("meta") if isinstance(state.get("meta"), dict) else {}
    helper_profile = meta.get("helper_execution_profile") if isinstance(meta.get("helper_execution_profile"), dict) else {}
    assert helper_profile["helper_mode_enabled"] is False
    assert helper_profile["helper_fast_path_enabled"] is False


def test_validator_requested_but_not_effective_forces_observer_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")

    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@validator",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert lifecycle["bft_enabled_requested"] is True
    assert lifecycle["bft_enabled_effective"] is False
    assert ex.observer_mode() is True
    assert ex.validator_signing_enabled() is False
    assert ex._effective_signing_block_reason() == "node_lifecycle_not_validator_ready"
