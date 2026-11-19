from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_live_request_matches_its_own_case_without_claiming_pending_as_final() -> None:
    src = _read(WEB / "src" / "pages" / "AccountVerificationPage.tsx")
    routes = _read(WEB / "src" / "lib" / "pohGuidedRoutes.ts")

    live_fn = src.split("async function reconcileLiveCaseVisible", 1)[1].split(
        "async function waitForLiveCaseIdVisible", 1
    )[0]
    assert "return reconcileVerificationLevel(account, 1, base);" not in live_fn
    assert "return null;" in live_fn
    assert "mine?.ok === true" in live_fn
    assert "findExpectedLivePohCaseId(mine.cases, account, expectedCaseId)" in live_fn
    assert "record.case_id === expected && record.account_id === owner" in routes
    assert "reconcileLiveCaseVisible(acct, submittedLiveCaseId, base, headers)" in src
    assert "requireLocalStateSynced: false" in src
    assert "acceptAccepted: true" in src
    assert "pending_case_visibility: !visibleCaseId" in src
    assert "case_id: visibleCaseId || expectedCaseId" in src
    assert "resultCaseId && resultCaseId === expectedCaseId" in src
    assert "return visible[visible.length - 1]" not in src


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
