from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from weall.api import config as api_config
from weall.runtime.block_loop import block_loop_config_from_env


def test_read_nodes_registry_returns_empty_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    assert api_config.read_nodes_registry(None) == {"version": 1, "nodes": []}


def test_read_nodes_registry_prod_fails_closed_on_bad_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "nodes_registry.json"
    reg.write_text("{bad json", encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "prod")

    with pytest.raises(api_config.NodesRegistryConfigError, match="nodes_registry_bad_json"):
        api_config.read_nodes_registry(str(reg))


def test_read_nodes_registry_dev_degrades_on_bad_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "nodes_registry.json"
    reg.write_text("{bad json", encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "dev")

    assert api_config.read_nodes_registry(str(reg)) == {"version": 1, "nodes": []}


def test_read_nodes_registry_prod_fails_closed_on_bad_node_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "nodes_registry.json"
    reg.write_text(json.dumps({"version": 1, "nodes": ["not-a-dict"]}), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "prod")

    with pytest.raises(api_config.NodesRegistryConfigError, match="nodes_registry_bad_node_entry"):
        api_config.read_nodes_registry(str(reg))


def test_load_api_config_prod_rejects_empty_explicit_registry_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODES_REGISTRY_PATH", "   ")

    with pytest.raises(api_config.ApiConfigError, match="api_nodes_registry_path_empty"):
        api_config.load_api_config()


def test_block_loop_config_prod_rejects_invalid_integer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BLOCK_INTERVAL_MS", "nope")

    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_BLOCK_INTERVAL_MS"):
        block_loop_config_from_env()


def test_block_loop_config_dev_defaults_invalid_integer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_BLOCK_INTERVAL_MS", "nope")

    cfg = block_loop_config_from_env()
    assert cfg.interval_ms == 20_000


def test_load_dotenv_if_present_prod_fails_closed_for_missing_explicit_path(monkeypatch: pytest.MonkeyPatch) -> None:
    import weall.env as env_mod

    env_mod = importlib.reload(env_mod)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_DOTENV_PATH", "/tmp/definitely_missing_weall.env")

    with pytest.raises(env_mod.DotenvConfigError, match="dotenv_path_missing"):
        env_mod.load_dotenv_if_present()


def test_load_dotenv_if_present_default_missing_is_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import weall.env as env_mod

    env_mod = importlib.reload(env_mod)
    monkeypatch.delenv("WEALL_DOTENV_PATH", raising=False)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.chdir(tmp_path)

    assert env_mod.load_dotenv_if_present() is False
