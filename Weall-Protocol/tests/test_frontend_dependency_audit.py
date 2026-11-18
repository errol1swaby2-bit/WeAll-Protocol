from __future__ import annotations

import json
from pathlib import Path

import yaml

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
    assert dev_dependencies.get("esbuild") == "0.28.1"
    assert "vite" not in dev_dependencies
    assert "@vitejs/plugin-react" not in dev_dependencies
    for name in ("@noble/post-quantum",):
        assert not dependencies[name].startswith(("^", "~", ">", "<"))
    for name in ("esbuild",):
        assert not dev_dependencies[name].startswith(("^", "~", ">", "<"))


def test_frontend_package_lock_matches_audited_dependency_versions() -> None:
    lock = _read_json(WEB / "package-lock.json")
    root = lock["packages"][""]

    assert "react-router-dom" not in root.get("dependencies", {})
    assert root["dependencies"]["@noble/post-quantum"] == "0.6.1"
    assert root["devDependencies"]["esbuild"] == "0.28.1"
    assert "vite" not in root["devDependencies"]
    assert "@vitejs/plugin-react" not in root["devDependencies"]

    packages = lock["packages"]
    assert "node_modules/react-router-dom" not in packages
    assert "node_modules/react-router" not in packages
    assert "node_modules/@remix-run/router" not in packages
    assert packages["node_modules/esbuild"]["version"] == "0.28.1"

    # Removal supersedes the prior Babel/PostCSS/Nano ID patch pins. None of
    # those packages or any member of the advisory chain may return unnoticed.
    forbidden = {
        "vite",
        "@vitejs/plugin-react",
        "picomatch",
        "tinyglobby",
        "fdir",
        "@babel/core",
        "@babel/generator",
        "@babel/parser",
        "@babel/types",
        "@babel/helper-string-parser",
        "@babel/helper-validator-identifier",
        "postcss",
        "nanoid",
    }
    for path, metadata in packages.items():
        assert path.split("node_modules/")[-1] not in forbidden
        assert metadata.get("name") not in forbidden


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

    assert packages["node_modules/esbuild"]["version"] == "0.28.1"


def test_frontend_dependency_audit_is_a_hard_release_verification_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "web-ci.yml").read_text(encoding="utf-8")
    golden = (ROOT / "scripts" / "golden_path_regression.sh").read_text(encoding="utf-8")
    clean_clone = (ROOT / "scripts" / "run_clean_clone_go_gate_v1_5.sh").read_text(encoding="utf-8")
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


def test_pr93_regeneration_has_one_generated_only_writer_and_keeps_web_audit() -> None:
    workflows = ROOT / ".github" / "workflows"
    branch = "integration/unified-baseline-all-open-prs-20261114"
    legacy = (workflows / "v2-spec-refresh.yml").read_text(encoding="utf-8")
    strict = (workflows / "pr93-approved-derivative-refresh.yml").read_text(encoding="utf-8")
    web = (workflows / "web-ci.yml").read_text(encoding="utf-8")

    assert f"branches-ignore:\n      - {branch}" in legacy
    assert f"if: github.ref_name != '{branch}'" in legacy
    assert f"github.ref_name == '{branch}'" in strict
    assert "git diff --exit-code" in strict
    assert "web/package.json web/package-lock.json" in strict
    assert "git push origin HEAD:" in strict
    assert "npm install --package-lock-only" not in strict
    jobs = yaml.safe_load(web)["jobs"]
    security = jobs["dependency-security"]
    steps = {step["name"]: step for step in security["steps"]}
    audit = steps["Dependency audit"]
    regression = steps["Isolated Picomatch vulnerability regression (GHSA-fc5q-39xc-vjpf)"]
    assert audit["run"].strip() == "npm run dependency-audit"
    assert "if" not in audit
    assert regression["run"] == "node scripts/test_picomatch_security_regression.mjs"
    assert regression["if"] == (
        "${{ !cancelled() && steps.install_web_dependencies.outcome == 'success' }}"
    )
    assert "continue-on-error:" not in web

    # Functional evidence remains independently observable, but the original
    # required web check cannot succeed unless every prerequisite succeeds.
    functional = jobs["frontend-functional"]
    assert "needs" not in functional
    assert "if" not in functional
    functional_steps = {step["name"]: step for step in functional["steps"]}
    assert functional_steps["Build"]["run"].strip() == "npm run build"
    assert "Production deployment Chromium smoke" in functional_steps
    aggregate = jobs["web"]
    assert set(aggregate["needs"]) == {
        "dependency-security",
        "frontend-functional",
        "governance-ui",
    }
    assert aggregate["if"] == "always()"
    gate = aggregate["steps"][0]
    assert gate["env"] == {
        "SECURITY_RESULT": "${{ needs.dependency-security.result }}",
        "FUNCTIONAL_RESULT": "${{ needs.frontend-functional.result }}",
        "GOVERNANCE_RESULT": "${{ needs.governance-ui.result }}",
    }
    for result in gate["env"]:
        assert f'test "${result}" = success' in gate["run"]
    assert yaml.safe_load(web)["permissions"] == {"contents": "read"}
    for job in (security, functional, jobs["governance-ui"]):
        checkout = next(step for step in job["steps"] if step.get("uses") == "actions/checkout@v4")
        assert checkout["with"]["persist-credentials"] is False
