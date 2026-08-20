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

    # The application uses its own hash router. Keep react-router* out of the
    # production dependency graph unless source code intentionally adopts it.
    assert "react-router-dom" not in dependencies

    # Exact pins only: no semver ranges for the audited frontend security-critical stack.
    assert dependencies.get("@noble/post-quantum") == "0.6.1"
    assert dev_dependencies.get("vite") == "8.0.16"
    assert dev_dependencies.get("@vitejs/plugin-react") == "5.2.0"
    for name in ("@noble/post-quantum",):
        assert not dependencies[name].startswith(("^", "~", ">", "<"))
    for name in ("vite", "@vitejs/plugin-react"):
        assert not dev_dependencies[name].startswith(("^", "~", ">", "<"))


def test_frontend_package_lock_matches_audited_dependency_versions() -> None:
    lock = _read_json(WEB / "package-lock.json")
    root = lock["packages"][""]

    assert "react-router-dom" not in root.get("dependencies", {})
    assert root["dependencies"]["@noble/post-quantum"] == "0.6.1"
    assert root["devDependencies"]["vite"] == "8.0.16"
    assert root["devDependencies"]["@vitejs/plugin-react"] == "5.2.0"

    packages = lock["packages"]
    assert "node_modules/react-router-dom" not in packages
    assert "node_modules/react-router" not in packages
    assert "node_modules/@remix-run/router" not in packages
    assert packages["node_modules/vite"]["version"] == "8.0.16"
    assert packages["node_modules/@vitejs/plugin-react"]["version"] == "5.2.0"

    # Transitive build-tool security floor. These exact lock versions close the
    # reviewed 2026 Babel/PostCSS/Nano ID advisories without widening direct
    # application dependencies or weakening the hard npm-audit release gate.
    assert packages["node_modules/@babel/core"]["version"] == "7.29.6"
    assert packages["node_modules/@babel/generator"]["version"] == "7.29.7"
    assert packages["node_modules/@babel/parser"]["version"] == "7.29.7"
    assert packages["node_modules/@babel/types"]["version"] == "7.29.7"
    assert packages["node_modules/@babel/helper-string-parser"]["version"] == "7.29.7"
    assert packages["node_modules/@babel/helper-validator-identifier"]["version"] == "7.29.7"
    assert packages["node_modules/postcss"]["version"] == "8.5.26"
    assert packages["node_modules/nanoid"]["version"] == "3.3.18"


def test_frontend_lockfile_no_longer_contains_known_vulnerable_router_chain() -> None:
    lock = _read_json(WEB / "package-lock.json")
    packages = lock["packages"]

    # react-router-dom was unused by source but kept a vulnerable production
    # dependency chain alive. Its removal is intentional and regression-tested.
    assert all(
        name not in packages
        for name in (
            "node_modules/react-router-dom",
            "node_modules/react-router",
            "node_modules/@remix-run/router",
        )
    )

    # Vite/esbuild remain pinned at the already-audited fixed versions.
    vite = packages["node_modules/vite"]
    esbuild = packages["node_modules/esbuild"]
    assert vite["version"] == "8.0.16"
    assert esbuild["version"] >= "0.25.0"


def test_frontend_dependency_audit_is_a_hard_release_verification_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "web-ci.yml").read_text(encoding="utf-8")
    golden = (ROOT / "scripts" / "golden_path_regression.sh").read_text(encoding="utf-8")
    clean_clone = (ROOT / "scripts" / "run_clean_clone_go_gate_v1_5.sh").read_text(
        encoding="utf-8"
    )
    reviewer = (ROOT / "Weall-Protocol" / "scripts" / "reviewer_check.sh").read_text(
        encoding="utf-8"
    )

    for gate in (workflow, golden, clean_clone, reviewer):
        assert "npm run dependency-audit" in gate

    assert "npm audit || true" not in golden
    assert "npm audit fix" not in golden


def test_frontend_package_lock_uses_public_registry_urls_only() -> None:
    lock_text = (WEB / "package-lock.json").read_text(encoding="utf-8")

    assert "packages.applied-caas" not in lock_text
    assert "artifactory/api/npm/npm-public" not in lock_text
    assert "registry.npmjs.org" in lock_text
