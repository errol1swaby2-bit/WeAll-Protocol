from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from weall.runtime.chain_config import ChainConfig, production_bootstrap_issues, validate_runtime_env


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


def _clear_prod_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "WEALL_BFT_ENABLED",
        "WEALL_OBSERVER_MODE",
        "WEALL_VALIDATOR_SIGNING_ENABLED",
        "WEALL_NODE_LIFECYCLE_STATE",
        "WEALL_SERVICE_ROLES",
        "WEALL_VALIDATOR_ACCOUNT",
        "WEALL_VALIDATOR_ACCOUNT_FILE",
        "WEALL_NET_ENABLED",
        "WEALL_NODE_PUBKEY",
        "WEALL_NODE_PRIVKEY",
        "WEALL_NODE_PUBKEY_FILE",
        "WEALL_NODE_PRIVKEY_FILE",
        "WEALL_CHAIN_MANIFEST_PATH",
        "WEALL_REQUIRE_CHAIN_MANIFEST",
        "WEALL_RELEASE_MANIFEST_PATH",
        "WEALL_RELEASE_PUBKEY",
        "WEALL_RELEASE_PUBKEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_production_validator_service_requires_bft_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_prod_env(monkeypatch)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")

    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("production validator intent requires WEALL_BFT_ENABLED=1" in item for item in issues)

    with pytest.raises(RuntimeError, match="production validator intent requires WEALL_BFT_ENABLED=1"):
        validate_runtime_env()


def test_validator_signing_requires_bft_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_prod_env(monkeypatch)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "1")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")

    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("production validator intent requires WEALL_BFT_ENABLED=1" in item for item in issues)

    with pytest.raises(RuntimeError, match="production validator intent requires WEALL_BFT_ENABLED=1"):
        validate_runtime_env()


def test_explicit_observer_without_validator_intent_may_run_without_bft(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_prod_env(monkeypatch)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "0")

    validate_runtime_env()


def test_prod_node_preflight_rejects_validator_service_without_bft(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "configs" / "chains" / "weall-genesis.json"
    env = {
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(manifest),
        "WEALL_NODE_LIFECYCLE_STATE": "production_service",
        "WEALL_SERVICE_ROLES": "validator",
        "WEALL_BFT_ENABLED": "0",
    }
    proc = subprocess.run(
        ["bash", "scripts/prod_node_preflight.sh"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "production validator service requires WEALL_BFT_ENABLED=1" in proc.stderr


def test_run_node_rejects_validator_signing_without_bft(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    env = {
        "PATH": "/usr/bin:/bin",
        "WEALL_MODE": "prod",
        "WEALL_CHAIN_MANIFEST_PATH": str(root / "configs" / "chains" / "weall-genesis.json"),
        "WEALL_CHAIN_ID": "weall-prod",
        "WEALL_CORS_ORIGINS": "https://client.example",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
        "WEALL_BFT_ENABLED": "0",
    }
    proc = subprocess.run(
        ["bash", "scripts/run_node.sh"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "validator signing requires WEALL_BFT_ENABLED=1 in production" in proc.stderr
