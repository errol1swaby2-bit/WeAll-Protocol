from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"


def read(rel: str) -> str:
    return (WEB / rel).read_text(encoding="utf-8")


def test_frontend_prod_build_cannot_enable_demo_or_dev_surfaces() -> None:
    config = read("src/lib/config.ts")
    app = read("src/App.tsx")
    settings = read("src/pages/Settings.tsx")

    assert "enableDevTools: !isProd &&" in config
    assert "enableDevBootstrap: !isProd &&" in config
    assert "isProduction: isProd" in config
    assert 'return isProd ? "/" : "http://127.0.0.1:8000";' in config

    assert "const showAdvancedMode = config.enableDevTools && settings.showAdvancedMode;" in app
    assert "if (!config.enableDevBootstrap)" in app

    assert "{config.enableDevTools ? (" in settings
    assert "Advanced and tester surfaces are disabled in this production build." in settings
    assert "Normal users will not see demo tools, technical consoles, or developer routes." in settings


def test_frontend_api_base_validation_supports_remote_genesis_without_unsafe_targets() -> None:
    api = read("src/api/weall.ts")
    settings = read("src/pages/Settings.tsx")

    assert "export function validateApiBaseInput" in api
    assert "Only http:// and https:// backend URLs are supported." in api
    assert "Use an absolute http(s) URL, or / for same-origin." in api
    assert "if (!validation.ok) throw new Error(validation.reason);" in api
    assert "parsed.hash = \"\";" in api
    assert "parsed.search = \"\";" in api

    assert "validateApiBaseInput(trimmed)" in settings
    assert "Remote genesis APIs are supported" in settings
    assert "https://genesis.example.org" in settings
    assert "Use local backend" in settings
    assert "!config.isProduction" in settings


def test_frontend_production_safety_guard_is_packaged() -> None:
    package_json = read("package.json")
    guard = read("scripts/guard_production_ux_safety.mjs")

    assert '"production-safety-check": "node scripts/guard_production_ux_safety.mjs"' in package_json
    assert "production fail-closed dev-tools flag" in guard
    assert "production same-origin API default" in guard
    assert "settings validates API base before saving" in guard
