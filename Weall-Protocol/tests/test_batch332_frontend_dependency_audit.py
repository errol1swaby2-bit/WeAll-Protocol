from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_frontend_dependency_audit_script_is_available_and_exact_versions_are_pinned() -> None:
    package = _read_json(WEB / "package.json")

    scripts = package.get("scripts", {})
    assert scripts.get("dependency-audit") == "npm audit --audit-level=moderate"

    assert package.get("engines", {}).get("node") == ">=20.19.0"
    assert package.get("engines", {}).get("npm") == ">=10.0.0"

    dependencies = package.get("dependencies", {})
    dev_dependencies = package.get("devDependencies", {})

    # Exact pins only: no semver ranges for the audited frontend security-critical stack.
    assert dependencies.get("react-router-dom") == "6.30.3"
    assert dev_dependencies.get("vite") == "7.3.3"
    assert dev_dependencies.get("@vitejs/plugin-react") == "5.1.2"
    for name in ("react-router-dom",):
        assert not dependencies[name].startswith(("^", "~", ">", "<"))
    for name in ("vite", "@vitejs/plugin-react"):
        assert not dev_dependencies[name].startswith(("^", "~", ">", "<"))


def test_frontend_package_lock_matches_audited_dependency_versions() -> None:
    lock = _read_json(WEB / "package-lock.json")
    root = lock["packages"][""]

    assert root["dependencies"]["react-router-dom"] == "6.30.3"
    assert root["devDependencies"]["vite"] == "7.3.3"
    assert root["devDependencies"]["@vitejs/plugin-react"] == "5.1.2"

    packages = lock["packages"]
    assert packages["node_modules/react-router-dom"]["version"] == "6.30.3"
    assert packages["node_modules/react-router"]["version"] == "6.30.3"
    assert packages["node_modules/vite"]["version"] == "7.3.3"
    assert packages["node_modules/@vitejs/plugin-react"]["version"] == "5.1.2"


def test_frontend_lockfile_no_longer_contains_known_vulnerable_ranges() -> None:
    lock = _read_json(WEB / "package-lock.json")
    packages = lock["packages"]

    # Prior audit findings were fixed by moving react-router-dom/react-router to 6.30.3.
    assert packages["node_modules/@remix-run/router"]["version"] == "1.23.2"
    assert packages["node_modules/react-router"]["version"] == "6.30.3"

    # Prior Vite/esbuild findings were fixed by moving to Vite 7.3.3.
    vite = packages["node_modules/vite"]
    esbuild = packages["node_modules/esbuild"]
    assert vite["version"] == "7.3.3"
    assert esbuild["version"] >= "0.25.0"

def test_frontend_package_lock_uses_public_registry_urls_only() -> None:
    lock_text = (WEB / "package-lock.json").read_text(encoding="utf-8")

    assert "packages.applied-caas" not in lock_text
    assert "artifactory/api/npm/npm-public" not in lock_text
    assert "registry.npmjs.org" in lock_text

