from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.block_loop import BlockProducerLoop, block_loop_config_from_env
from weall.runtime.executor import WeAllExecutor


class _DummyPool:
    def size(self) -> int:
        return 0


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_prod_lifecycle_not_validator_disables_block_loop_bft_authority_batch126(
    tmp_path: Path, monkeypatch
) -> None:
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

    cfg = block_loop_config_from_env()
    assert cfg.bft_enabled is True

    loop = BlockProducerLoop(
        executor=ex,
        mempool=_DummyPool(),
        attestation_pool=_DummyPool(),
        cfg=cfg,
    )
    assert loop._cfg.bft_enabled is False



def test_bootstrap_dev_keeps_block_loop_bft_request_batch126(tmp_path: Path, monkeypatch) -> None:
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

    cfg = block_loop_config_from_env()
    assert cfg.bft_enabled is True

    loop = BlockProducerLoop(
        executor=ex,
        mempool=_DummyPool(),
        attestation_pool=_DummyPool(),
        cfg=cfg,
    )
    assert loop._cfg.bft_enabled is True
