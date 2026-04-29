from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI


def test_api_main_invalid_port_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_API_PORT", "not-an-int")
    mod = importlib.import_module("weall.api.__main__")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_API_PORT"):
        mod._env_int("WEALL_API_PORT", 8080)


def test_structured_logging_invalid_log_level_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_LOG_LEVEL", "LOUD")
    mod = importlib.import_module("weall.api.structured_logging")
    with pytest.raises(ValueError, match="invalid_log_level_env:WEALL_LOG_LEVEL"):
        mod.configure_structured_logging()


def test_structured_logging_invalid_request_flag_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_LOG_REQUESTS", "maybe")
    mod = importlib.import_module("weall.api.structured_logging")
    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_LOG_REQUESTS"):
        mod.RequestLogMiddleware(FastAPI())


def test_structured_logging_invalid_request_flag_falls_back_in_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WEALL_MODE", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests::x")
    monkeypatch.setenv("WEALL_LOG_REQUESTS", "maybe")
    mod = importlib.import_module("weall.api.structured_logging")
    mw = mod.RequestLogMiddleware(FastAPI())
    assert mw._enabled is True


def test_ipfs_cfg_invalid_explicit_api_base_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_API_BASE", "not-a-url")
    mod = importlib.import_module("weall.api.ipfs")
    with pytest.raises(ValueError, match="invalid_url_env:WEALL_IPFS_API_BASE"):
        mod._cfg()


def test_ipfs_cfg_invalid_explicit_gateway_base_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_GATEWAY_BASE", "ftp://gateway.local")
    mod = importlib.import_module("weall.api.ipfs")
    with pytest.raises(ValueError, match="invalid_url_env:WEALL_IPFS_GATEWAY_BASE"):
        mod._cfg()


def test_ipfs_pin_worker_invalid_bool_env_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_ENABLED", "maybe")
    mod = importlib.import_module("weall.storage.ipfs_pin_worker")
    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_IPFS_ENABLED"):
        mod.IpfsPinWorkerConfig(db_path=str(tmp_path / "x.db"), operator_account="op1")


def test_ipfs_pin_worker_invalid_int_env_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_MAX_ATTEMPTS", "NaN")
    mod = importlib.import_module("weall.storage.ipfs_pin_worker")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_IPFS_MAX_ATTEMPTS"):
        mod.IpfsPinWorkerConfig(db_path=str(tmp_path / "x.db"), operator_account="op1")


def test_ipfs_pin_worker_invalid_url_env_fails_closed_in_prod(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_API_URL", "kubo:5001")
    mod = importlib.import_module("weall.storage.ipfs_pin_worker")
    with pytest.raises(ValueError, match="invalid_url_env:WEALL_IPFS_API_URL"):
        mod.IpfsPinWorkerConfig(db_path=str(tmp_path / "x.db"), operator_account="op1")


def test_ipfs_pin_worker_invalid_envs_fall_back_in_test(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.delenv("WEALL_MODE", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests::x")
    monkeypatch.setenv("WEALL_IPFS_ENABLED", "maybe")
    monkeypatch.setenv("WEALL_IPFS_MAX_ATTEMPTS", "NaN")
    monkeypatch.setenv("WEALL_IPFS_API_URL", "kubo:5001")
    mod = importlib.import_module("weall.storage.ipfs_pin_worker")
    cfg = mod.IpfsPinWorkerConfig(db_path=str(tmp_path / "x.db"), operator_account="op1")
    assert cfg.ipfs_enabled is False
    assert cfg.max_attempts == 12
    assert cfg.ipfs_api_url == "http://127.0.0.1:5001"
