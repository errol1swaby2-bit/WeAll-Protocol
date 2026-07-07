from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read(path: str) -> str:
    return (OUTER / path).read_text(encoding="utf-8")


def test_runtime_env_overrides_local_paths_without_forking_chain_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_config = tmp_path / "prod.chain.json"
    env_db_path = tmp_path / "runtime" / "operator.db"
    env_db_path.parent.mkdir()
    env_tx_index = tmp_path / "generated" / "tx_index.json"
    _write_json(env_tx_index, {"by_id": {}, "by_name": {}, "tx_types": []})

    _write_json(
        chain_config,
        {
            "chain_id": "weall-prod",
            "node_id": "config-node",
            "mode": "prod",
            "db_path": "./data/weall.db",
            "tx_index_path": "./generated/tx_index.json",
            "block_interval_ms": 600000,
            "max_txs_per_block": 1000,
            "block_reward": 0,
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "allow_unsigned_txs": False,
            "log_level": "INFO",
        },
    )

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-prod")
    monkeypatch.setenv("WEALL_CHAIN_CONFIG_PATH", str(chain_config))
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(ROOT / "configs/chains/weall-genesis.json"))
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_DB_PATH", str(env_db_path))
    monkeypatch.setenv("WEALL_NODE_ID", "env-node")
    monkeypatch.setenv("WEALL_TX_INDEX_PATH", str(env_tx_index))
    monkeypatch.setenv("WEALL_API_HOST", "0.0.0.0")
    monkeypatch.setenv("WEALL_API_PORT", "8800")
    monkeypatch.setenv("WEALL_LOG_LEVEL", "WARNING")

    cfg = load_chain_config()

    assert cfg.chain_id == "weall-prod"
    assert cfg.chain_manifest_path.endswith("configs/chains/weall-genesis.json")
    assert cfg.db_path == str(env_db_path)
    assert cfg.node_id == "env-node"
    assert cfg.tx_index_path == str(env_tx_index)
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8800
    assert cfg.log_level == "WARNING"

    issues = production_bootstrap_issues(cfg)
    assert not [issue for issue in issues if "db_path parent is not writable" in issue]


def test_runtime_env_db_path_does_not_override_chain_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain_config = tmp_path / "prod.chain.json"
    db_path = tmp_path / "db" / "operator.db"
    db_path.parent.mkdir()
    _write_json(
        chain_config,
        {
            "chain_id": "wrong-chain",
            "node_id": "config-node",
            "mode": "prod",
            "db_path": "./data/weall.db",
            "tx_index_path": "./generated/tx_index.json",
            "block_interval_ms": 600000,
            "max_txs_per_block": 1000,
            "block_reward": 0,
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "allow_unsigned_txs": False,
            "log_level": "INFO",
        },
    )

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_CONFIG_PATH", str(chain_config))
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(ROOT / "configs/chains/weall-genesis.json"))
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_DB_PATH", str(db_path))
    monkeypatch.delenv("WEALL_CHAIN_ID", raising=False)

    cfg = load_chain_config()
    issues = production_bootstrap_issues(cfg)

    assert cfg.db_path == str(db_path)
    assert cfg.chain_id == "wrong-chain"
    assert any("chain_manifest" in issue and "chain_id" in issue for issue in issues)


def test_docker_genesis_compose_uses_canonical_manifest_and_runtime_volume() -> None:
    compose = _read("Weall-Protocol/docker-compose.genesis.yml")
    manifest = _read("Weall-Protocol/configs/chains/weall-genesis.json")

    assert "WEALL_MODE=prod" in compose
    assert "WEALL_CHAIN_MANIFEST_PATH=./configs/chains/weall-genesis.json" in compose
    assert "weall-genesis-docker.json" not in compose
    assert "WEALL_DB_PATH=/var/lib/weall/genesis.db" in compose
    assert "weall-genesis-data:/var/lib/weall" in compose
    assert "./data:/app/data" not in compose
    assert '"db_path"' not in manifest


def test_dockerfile_prepares_runtime_volume_mountpoint() -> None:
    dockerfile = _read("Weall-Protocol/Dockerfile")
    assert "mkdir -p /var/lib/weall" in dockerfile
    assert "chown -R appuser:appuser /var/lib/weall" in dockerfile


def test_docker_genesis_boot_gate_is_tracked() -> None:
    gate = _read("Weall-Protocol/scripts/docker_genesis_api_boot_gate.sh")
    reviewer = _read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh")

    assert 'docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" config' in gate
    assert "/v1/genesis/observer/readiness" in gate
    assert "WEALL_DOCKER_GENESIS_BOOT_GATE=1" in reviewer
    assert "tests/test_runtime_config_env_precedence.py" in reviewer
