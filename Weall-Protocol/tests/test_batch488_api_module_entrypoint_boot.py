from __future__ import annotations

import pytest


def test_api_module_help_exits_before_runtime_boot_batch488() -> None:
    from weall.api import __main__ as api_main

    with pytest.raises(SystemExit) as excinfo:
        api_main.main(["--help"])

    assert excinfo.value.code == 0


def test_api_module_main_passes_boot_runtime_to_create_app_batch488(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import __main__ as api_main
    from weall.api import app as api_app

    calls: dict[str, object] = {}

    def fake_create_app(*, boot_runtime: bool):
        calls["boot_runtime"] = boot_runtime
        return object()

    def fake_default() -> bool:
        calls["default_called"] = True
        return False

    def fake_run(app, *, host: str, port: int, log_level: str) -> None:
        calls["app"] = app
        calls["host"] = host
        calls["port"] = port
        calls["log_level"] = log_level

    monkeypatch.setattr(api_app, "create_app", fake_create_app)
    monkeypatch.setattr(api_app, "_module_app_boot_runtime_default", fake_default)
    monkeypatch.setattr(api_main.uvicorn, "run", fake_run)

    api_main.main(["--host", "127.0.0.1", "--port", "8765"])

    assert calls["default_called"] is True
    assert calls["boot_runtime"] is False
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8765
    assert calls["log_level"] == "info"


def test_api_module_cli_can_force_runtime_boot_batch488(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import __main__ as api_main
    from weall.api import app as api_app

    calls: dict[str, object] = {}

    def fake_create_app(*, boot_runtime: bool):
        calls["boot_runtime"] = boot_runtime
        return object()

    def fake_run(app, *, host: str, port: int, log_level: str) -> None:
        calls["app"] = app
        calls["host"] = host
        calls["port"] = port
        calls["log_level"] = log_level

    monkeypatch.setattr(api_app, "create_app", fake_create_app)
    monkeypatch.setattr(api_main.uvicorn, "run", fake_run)

    api_main.main(["--boot-runtime", "--port", "8766"])

    assert calls["boot_runtime"] is True
    assert calls["port"] == 8766
