from __future__ import annotations

import importlib

import pytest


def test_common_invalid_http_json_limit_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_HTTP_TX_BYTES", "NaN")
    mod = importlib.import_module("weall.api.routes_public_parts.common")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_MAX_HTTP_TX_BYTES"):
        mod._env_int("WEALL_MAX_HTTP_TX_BYTES", 256 * 1024)


def test_common_invalid_http_json_limit_falls_back_in_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_MODE", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests::x")
    monkeypatch.setenv("WEALL_MAX_HTTP_TX_BYTES", "NaN")
    mod = importlib.import_module("weall.api.routes_public_parts.common")
    assert mod._env_int("WEALL_MAX_HTTP_TX_BYTES", 256 * 1024) == 256 * 1024


def test_media_invalid_explicit_max_upload_bytes_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_MAX_UPLOAD_BYTES", "NaN")
    mod = importlib.import_module("weall.api.routes_public_parts.media")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_IPFS_MAX_UPLOAD_BYTES"):
        mod._env_int("WEALL_IPFS_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)


def test_media_invalid_boolean_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_AUTO_PIN_REQUEST", "maybe")
    mod = importlib.import_module("weall.api.routes_public_parts.media")
    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_MEDIA_AUTO_PIN_REQUEST"):
        mod._env_bool("WEALL_MEDIA_AUTO_PIN_REQUEST", False)


def test_storage_ops_invalid_replication_factor_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_REPLICATION_FACTOR", "NaN")
    mod = importlib.import_module("weall.api.routes_public_parts.storage_ops")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_IPFS_REPLICATION_FACTOR"):
        mod._env_int("WEALL_IPFS_REPLICATION_FACTOR", 0)


def test_partition_config_invalid_cap_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_PARTITION_CAP_BYTES", "NaN")
    mod = importlib.import_module("weall.storage.ipfs_partition")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_IPFS_PARTITION_CAP_BYTES"):
        mod.read_partition_config()


def test_partition_config_invalid_env_falls_back_in_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_MODE", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests::x")
    monkeypatch.setenv("WEALL_IPFS_PARTITION_CAP_BYTES", "NaN")
    mod = importlib.import_module("weall.storage.ipfs_partition")
    path, cap, reserve = mod.read_partition_config()
    assert path == ""
    assert cap == 0
    assert reserve == 512 * 1024 * 1024
