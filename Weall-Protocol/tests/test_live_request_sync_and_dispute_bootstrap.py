from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_live_request_waits_for_confirmed_synced_case_before_routing() -> None:
    src = _read(WEB / "src" / "pages" / "AccountVerificationPage.tsx")

    live_fn = src.split("async function reconcileLiveCaseVisible", 1)[1].split("async function waitForLiveCaseIdVisible", 1)[0]
    assert "return reconcileVerificationLevel(account, 1, base);" not in live_fn
    assert "return null;" in live_fn
    assert "Live verification request was not confirmed on genesis and synced back to the observer yet" in src
    assert "requireLocalStateSynced: true" in src
    assert "return { skeleton: skel, commitments, submit, case_id: visibleCaseId };" in src
    assert 'String((r as any)?.case_id || "") || await waitForLiveCaseIdVisible' in src


def test_dispute_frontend_has_bootstrap_single_reviewer_fallback() -> None:
    src = _read(WEB / "src" / "lib" / "disputeSurface.ts")

    assert "bootstrap_single_reviewer_fallback" in src
    assert 'disputeId.startsWith("dispute:SYSTEM:")' in src
    assert "backend apply layer remains authoritative" in src


def test_dispute_accept_materializes_committed_bootstrap_eligible_record() -> None:
    src = _read(ROOT / "src" / "weall" / "runtime" / "apply" / "dispute.py")

    assert "eligible_now = _dispute_eligible_juror_ids(state, d, env.signer)" in src
    assert "signer_variants = set(_identity_variants(env.signer))" in src
    assert "before the queued assignment receipt has" in src
