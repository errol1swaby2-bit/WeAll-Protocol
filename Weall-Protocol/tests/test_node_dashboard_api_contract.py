from __future__ import annotations

from pathlib import Path


def test_helper_readiness_surface_has_ok_flag() -> None:
    src = Path("src/weall/api/routes_public_parts/helper_readiness.py").read_text()
    assert 'report["ok"] = True' in src
    assert "helper readiness endpoint aligned" in src


def test_api_main_passes_explicit_boot_runtime_contract() -> None:
    src = Path("src/weall/api/__main__.py").read_text()
    assert "_module_app_boot_runtime_default" in src
    assert "create_app(boot_runtime=_module_app_boot_runtime_default())" in src


def test_frontend_contract_harness_starts_backend_before_contract_check() -> None:
    src = Path("../scripts/run_frontend_contract_check_with_backend.sh").read_text()
    assert "python3 -m weall.api" in src
    assert 'WEALL_API_BOOT_RUNTIME="${WEALL_API_BOOT_RUNTIME:-1}"' in src
    assert 'API_BASE="${API_BASE}" npm run contract-check' in src
