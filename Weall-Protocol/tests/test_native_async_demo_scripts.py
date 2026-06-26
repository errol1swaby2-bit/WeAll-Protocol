from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_native_async_demo_script_exercises_full_tier1_flow() -> None:
    script = _read(ROOT / "scripts/demo_native_async_tier1_e2e.sh")

    assert "POH_ASYNC_REQUEST_OPEN" in script
    assert "POH_ASYNC_EVIDENCE_DECLARE" in script
    assert "POH_ASYNC_EVIDENCE_BIND" in script
    assert "POH_ASYNC_JUROR_ACCEPT" in script
    assert "POH_ASYNC_REVIEW_SUBMIT" in script
    assert "Waiting for native async finalization" in script
    assert "/v1/poh/async/case/" in script
    assert "poh_tier" in script
    assert "devnet_prepare_live_jurors.sh" in script
    assert "normal public tx submission" in script
    assert "seed" not in script.lower()


def test_full_onboarding_e2e_invokes_native_async_verification() -> None:
    script = _read(ROOT / "scripts/devnet_full_onboarding_e2e.sh")

    assert "demo_native_async_tier1_e2e.sh" in script
    assert "WEALL_RUN_NATIVE_ASYNC_TIER1_E2E" in script
    assert "Completing native async Tier-1 verification" in script
