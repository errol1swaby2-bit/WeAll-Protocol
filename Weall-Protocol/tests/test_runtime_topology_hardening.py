from __future__ import annotations

import pytest

from weall.api.app import _enforce_prod_runtime_topology
from weall.runtime.chain_config import ChainConfig, production_bootstrap_issues


def _cfg() -> ChainConfig:
    return ChainConfig(
        chain_id="test",
        node_id="node-1",
        mode="prod",
        db_path="./data/test.db",
        tx_index_path="./generated/tx_index.json",
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="0.0.0.0",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def test_production_bootstrap_reports_trusted_anchor_alias_conflict(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    txi = tmp_path / "tx_index.json"
    txi.write_text("{}", encoding="utf-8")
    cfg = _cfg()
    cfg = ChainConfig(**{**cfg.__dict__, "tx_index_path": str(txi), "db_path": str(tmp_path / 'test.db')})
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "0")
    issues = production_bootstrap_issues(cfg)
    assert any("trusted-anchor env aliases conflict" in issue for issue in issues)


def test_enforce_prod_runtime_topology_rejects_bft_plus_block_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "1")
    with pytest.raises(RuntimeError, match="cannot be combined"):
        _enforce_prod_runtime_topology()


def test_enforce_prod_runtime_topology_requires_single_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("GUNICORN_WORKERS", "2")
    with pytest.raises(RuntimeError, match="GUNICORN_WORKERS must be 1"):
        _enforce_prod_runtime_topology()
