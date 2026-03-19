from __future__ import annotations

from pathlib import Path
import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_health_invalid_net_enabled_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_ENABLED", "maybe")
    mod = importlib.import_module("weall.api.routes_public_parts.health")
    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_NET_ENABLED"):
        mod._env_bool("WEALL_NET_ENABLED", True)


def test_health_invalid_readyz_require_block_loop_env_breaks_readyz_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_READYZ_REQUIRE_BLOCK_LOOP", "definitely")
    mod = importlib.import_module("weall.api.routes_public_parts.health")

    app = FastAPI()
    app.include_router(mod.router, prefix="/v1")
    client = TestClient(app, raise_server_exceptions=True)

    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_READYZ_REQUIRE_BLOCK_LOOP"):
        client.get("/v1/readyz")


def test_poh_invalid_tier2_video_max_bytes_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_POH_TIER2_VIDEO_MAX_BYTES", "NaN")
    mod = importlib.import_module("weall.api.routes_public_parts.poh")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_POH_TIER2_VIDEO_MAX_BYTES"):
        mod._env_int("WEALL_POH_TIER2_VIDEO_MAX_BYTES", 25 * 1024 * 1024)


def test_poh_invalid_enable_operator_poh_env_fails_closed_in_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_OPERATOR_POH", "sometimes")
    mod = importlib.import_module("weall.api.routes_public_parts.poh")
    with pytest.raises(ValueError, match="invalid_boolean_env:WEALL_ENABLE_OPERATOR_POH"):
        mod._env_bool("WEALL_ENABLE_OPERATOR_POH", False)
