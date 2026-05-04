from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def test_media_route_imports_storage_package_on_fresh_clone() -> None:
    media = importlib.import_module("weall.api.routes_public_parts.media")
    assert callable(media.read_partition_config)
    assert callable(media.can_accept_bytes)


def test_ipfs_partition_disabled_when_path_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_IPFS_PARTITION_PATH", raising=False)
    monkeypatch.delenv("WEALL_IPFS_PARTITION_CAP_BYTES", raising=False)
    monkeypatch.delenv("WEALL_IPFS_PARTITION_RESERVE_BYTES", raising=False)
    mod = importlib.import_module("weall.storage.ipfs_partition")

    path, cap, reserve = mod.read_partition_config()
    assert path == ""
    assert cap == 0
    assert reserve == 512 * 1024 * 1024

    ok, reason, details = mod.can_accept_bytes(
        partition_path=path,
        cap_bytes=cap,
        reserve_bytes=reserve,
        need_bytes=123,
    )
    assert ok is True
    assert reason == "disabled"
    assert details["enforced"] is False


def test_ipfs_partition_missing_configured_path_fails_closed(tmp_path: Path) -> None:
    mod = importlib.import_module("weall.storage.ipfs_partition")
    missing = tmp_path / "missing"

    ok, reason, details = mod.can_accept_bytes(
        partition_path=str(missing),
        cap_bytes=0,
        reserve_bytes=0,
        need_bytes=1,
    )
    assert ok is False
    assert reason == "partition_missing"
    assert details["enforced"] is True


def test_ipfs_partition_cap_is_enforced(tmp_path: Path) -> None:
    mod = importlib.import_module("weall.storage.ipfs_partition")
    (tmp_path / "existing.bin").write_bytes(b"x" * 8)

    ok, reason, details = mod.can_accept_bytes(
        partition_path=str(tmp_path),
        cap_bytes=10,
        reserve_bytes=0,
        need_bytes=3,
    )
    assert ok is False
    assert reason == "cap_exceeded"
    assert details["used_bytes"] >= 8


def test_ipfs_partition_invalid_cap_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_IPFS_PARTITION_CAP_BYTES", "NaN")
    mod = importlib.import_module("weall.storage.ipfs_partition")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_IPFS_PARTITION_CAP_BYTES"):
        mod.read_partition_config()
