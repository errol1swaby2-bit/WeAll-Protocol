from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "Weall-Protocol"


def run(*args: str, cwd: Path = PROTO, env: dict[str, str] | None = None) -> None:
    import os

    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=merged, check=True)


def patch_sources() -> None:
    executor_path = PROTO / "src/weall/runtime/executor.py"
    text = executor_path.read_text(encoding="utf-8")
    anchor = (
        "    def build_state_sync_trusted_anchor(self) -> Json:\n"
        "        return build_snapshot_anchor(self.state)\n\n"
        "    def _state_sync_service(self) -> StateSyncService:\n"
    )
    replacement = (
        "    def build_state_sync_trusted_anchor(self) -> Json:\n"
        "        return build_snapshot_anchor(self.state)\n\n"
        "    def state_sync_requires_trusted_anchor(self) -> bool:\n"
        "        \"\"\"Return the effective trusted-anchor requirement for state installation.\"\"\"\n\n"
        "        return bool(self._state_sync_service().require_trusted_anchor)\n\n"
        "    def _state_sync_service(self) -> StateSyncService:\n"
    )
    if "def state_sync_requires_trusted_anchor" not in text:
        if anchor not in text:
            raise SystemExit("executor trusted-anchor insertion anchor missing")
        text = text.replace(anchor, replacement, 1)

    old = (
        "        svc = self._state_sync_service()\n"
        "        try:\n"
        "            svc.verify_response(resp, trusted_anchor=trusted_anchor)\n"
    )
    new = (
        "        svc = self._state_sync_service()\n"
        "        if svc.require_trusted_anchor and trusted_anchor is None:\n"
        "            raise ExecutorError(\"state_sync_verify_failed:trusted_anchor_required\")\n"
        "        try:\n"
        "            svc.verify_response(resp, trusted_anchor=trusted_anchor)\n"
    )
    if new not in text:
        if old not in text:
            raise SystemExit("executor verify-response anchor missing")
        text = text.replace(old, new, 1)
    executor_path.write_text(text, encoding="utf-8")

    route_path = PROTO / "src/weall/api/routes_public_parts/state.py"
    route = route_path.read_text(encoding="utf-8")
    old = (
        '    trusted_anchor = body.get("trusted_anchor")\n'
        "    if trusted_anchor is not None and not isinstance(trusted_anchor, dict):\n"
        "        raise HTTPException(\n"
        '            status_code=400, detail={"code": "bad_request", "message": "trusted_anchor"}\n'
        "        )\n"
        '    allow_snapshot = bool(body.get("allow_snapshot_bootstrap"))\n'
    )
    new = (
        '    trusted_anchor = body.get("trusted_anchor")\n'
        "    if trusted_anchor is not None and not isinstance(trusted_anchor, dict):\n"
        "        raise HTTPException(\n"
        '            status_code=400, detail={"code": "bad_request", "message": "trusted_anchor"}\n'
        "        )\n"
        '    requires_anchor = getattr(ex, "state_sync_requires_trusted_anchor", None)\n'
        "    if callable(requires_anchor) and bool(requires_anchor()) and trusted_anchor is None:\n"
        "        raise HTTPException(\n"
        "            status_code=400,\n"
        "            detail={\n"
        '                "code": "trusted_anchor_required",\n'
        '                "message": "state-sync installation requires a trusted anchor",\n'
        "            },\n"
        "        )\n"
        '    allow_snapshot = bool(body.get("allow_snapshot_bootstrap"))\n'
    )
    if new not in route:
        if old not in route:
            raise SystemExit("HTTP sync-apply trusted-anchor insertion anchor missing")
        route = route.replace(old, new, 1)
    route_path.write_text(route, encoding="utf-8")

    test_path = PROTO / "tests/test_p2_state_sync_hardening.py"
    tests = test_path.read_text(encoding="utf-8")
    if "from fastapi.testclient import TestClient" not in tests:
        tests = tests.replace(
            "import pytest\n\n",
            "import pytest\nfrom fastapi.testclient import TestClient\n\nfrom weall.api.app import create_app\n",
            1,
        )
    if "from weall.runtime.executor import ExecutorError, WeAllExecutor" not in tests:
        marker = "from weall.runtime.commitments import validator_set_hash\n"
        if marker not in tests:
            raise SystemExit("state-sync test import anchor missing")
        tests = tests.replace(
            marker,
            marker + "from weall.runtime.executor import ExecutorError, WeAllExecutor\n",
            1,
        )

    addition = '''


def test_p2_sync001_executor_install_boundary_rejects_missing_required_anchor() -> None:
    class _RequiredAnchorService:
        require_trusted_anchor = True

        def verify_response(self, *_args, **_kwargs) -> None:
            raise AssertionError("verification must not run without the required anchor")

    executor = object.__new__(WeAllExecutor)
    executor._state_sync_service = lambda: _RequiredAnchorService()  # type: ignore[method-assign]

    with pytest.raises(ExecutorError, match="state_sync_verify_failed:trusted_anchor_required"):
        executor.apply_state_sync_response(_response(), trusted_anchor=None)


def test_p2_sync001_http_apply_rejects_missing_required_anchor_before_install(monkeypatch) -> None:
    class _Executor:
        applied = False

        @staticmethod
        def state_sync_requires_trusted_anchor() -> bool:
            return True

        def apply_state_sync_response(self, *_args, **_kwargs):
            self.applied = True
            raise AssertionError("HTTP adapter must reject before state installation")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_APPLY_REQUIRE_OPERATOR_TOKEN", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "sync-secret")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")

    executor = _Executor()
    app = create_app(boot_runtime=False)
    app.state.executor = executor
    app.state.net_node = None
    response = {
        "header": {
            "type": "STATE_SYNC_RESPONSE",
            "chain_id": "chain",
            "schema_version": "1",
            "tx_index_hash": "tx-index",
            "corr_id": "p2-sync-http",
        },
        "ok": True,
        "reason": None,
        "height": 0,
        "snapshot": None,
        "snapshot_hash": None,
        "snapshot_anchor": None,
        "blocks": [],
    }
    with TestClient(app, raise_server_exceptions=False) as client:
        res = client.post(
            "/v1/sync/apply",
            headers={"X-WeAll-State-Sync-Operator-Token": "sync-secret"},
            json={"response": response, "allow_snapshot_bootstrap": False},
        )

    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "trusted_anchor_required"
    assert executor.applied is False
'''
    if "test_p2_sync001_http_apply_rejects_missing_required_anchor_before_install" not in tests:
        tests += addition
    test_path.write_text(tests, encoding="utf-8")


def main() -> None:
    run(
        "git",
        "rm",
        ".github/workflows/p2-sync001.yml",
        ".github/p2-sync001-closure.py",
        cwd=ROOT,
    )
    patch_sources()

    touched = [
        "src/weall/runtime/executor.py",
        "src/weall/api/routes_public_parts/state.py",
        "tests/test_p2_state_sync_hardening.py",
    ]
    run("ruff", "format", *touched)
    run("ruff", "format", "--check", *touched)
    run("ruff", "check", *touched)
    run(
        "pytest",
        "-q",
        "tests/test_p2_state_sync_hardening.py",
        "tests/test_executor_state_sync.py",
        "tests/test_priority2_state_sync_anchor_coverage.py",
        "tests/test_devnet_join_anchor_safety.py",
    )

    run(sys.executable, "scripts/gen_api_contract_map.py")
    run(sys.executable, "scripts/gen_failure_code_registry_v1_5.py")
    run(sys.executable, "scripts/gen_release_evidence_manifest_v1_5.py", env={"PYTHONPATH": "src"})
    run(
        sys.executable,
        "scripts/gen_public_beta_blocker_report_v1_5.py",
        env={"PYTHONPATH": "src:scripts"},
    )
    run(sys.executable, "scripts/gen_current_verified_claims.py")

    run(sys.executable, "scripts/gen_api_contract_map.py", "--check")
    run(sys.executable, "scripts/gen_failure_code_registry_v1_5.py", "--check")
    run(
        sys.executable,
        "scripts/gen_release_evidence_manifest_v1_5.py",
        "--check",
        env={"PYTHONPATH": "src"},
    )
    run(
        sys.executable,
        "scripts/gen_public_beta_blocker_report_v1_5.py",
        "--check",
        env={"PYTHONPATH": "src:scripts"},
    )
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")

    run(sys.executable, "scripts/compile_v2_spec.py", env={"PYTHONPATH": "src"})
    run(sys.executable, "scripts/compile_v2_spec.py", "--check", env={"PYTHONPATH": "src"})
    run(
        sys.executable,
        "scripts/check_v15_public_readiness_artifacts.py",
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    run(sys.executable, "scripts/check_public_claim_freshness.py")
    run(sys.executable, "scripts/gen_current_verified_claims.py", "--check")
    run("git", "diff", "--check", cwd=ROOT)

    run("git", "config", "user.name", "github-actions[bot]", cwd=ROOT)
    run(
        "git",
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
        cwd=ROOT,
    )
    run("git", "add", "-A", cwd=ROOT)
    run("git", "diff", "--cached", "--check", cwd=ROOT)
    run("git", "commit", "-m", "Close P2 SYNC001 trusted-anchor installation boundary", cwd=ROOT)
    run("git", "push", "origin", "HEAD:p2-complete-remediation-20260927", cwd=ROOT)


if __name__ == "__main__":
    main()
