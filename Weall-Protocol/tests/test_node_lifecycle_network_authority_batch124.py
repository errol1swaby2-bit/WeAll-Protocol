from __future__ import annotations

import json
from pathlib import Path

from weall.net.net_loop import NetMeshLoop
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_prod_lifecycle_not_validator_disables_network_bft_authority_batch124(tmp_path: Path, monkeypatch) -> None:
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

    loop = NetMeshLoop(executor=ex, mempool=ex.mempool)
    assert loop._bft_enabled is False
    node = loop._build_node()
    assert node._bft_enabled() is False

    sync = ex._state_sync_service()
    assert sync.enforce_finalized_anchor is False


def test_bootstrap_dev_keeps_network_bft_request_batch124(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="node-1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )

    loop = NetMeshLoop(executor=ex, mempool=ex.mempool)
    assert loop._bft_enabled is True
    node = loop._build_node()
    assert node._bft_enabled() is True
