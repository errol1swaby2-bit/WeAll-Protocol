from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.chain_config import ChainConfig, production_bootstrap_issues, production_bootstrap_report


def _cfg(tmp_path: Path) -> ChainConfig:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    return ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "data" / "weall.db"),
        tx_index_path=str(tx_index),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def _set_prod_network_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "1")
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example,https://peer-b.example")
    monkeypatch.setenv("WEALL_PEER_ID", "validator-node-1")
    monkeypatch.delenv("WEALL_SIGVERIFY", raising=False)


def test_production_bootstrap_rejects_invalid_boolean_envs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "maybe")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "sometimes")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert "invalid_boolean_env:WEALL_NET_REQUIRE_IDENTITY" in issues
    assert "invalid_boolean_env:WEALL_BFT_FETCH_ENABLED" in issues


def test_production_bootstrap_rejects_invalid_trusted_anchor_alias_bool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "definitely")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert "invalid_boolean_env:WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR/WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR" in issues


def test_production_bootstrap_rejects_invalid_gunicorn_workers_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "1")
    monkeypatch.setenv("GUNICORN_WORKERS", "many")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert "invalid_integer_env:GUNICORN_WORKERS" in issues


def test_production_bootstrap_report_exposes_invalid_env_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_network_env(monkeypatch)
    monkeypatch.setenv("WEALL_NET_ENABLED", "bogus")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "bogus")
    report = production_bootstrap_report(_cfg(tmp_path))
    assert report["network_enabled"] is False
    assert report["network_enabled_env_invalid"] is True
    assert report["trusted_anchor_env_invalid"] is True
    assert report["ok"] is False
