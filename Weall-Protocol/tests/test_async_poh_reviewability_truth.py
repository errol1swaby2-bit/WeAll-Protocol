from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web"
ROUTE = ROOT / "src/weall/api/routes_public_parts/poh.py"
RECONCILE = ROOT / "scripts/devnet_observer_tx_queue_reconcile_loop.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _submit_async_body() -> str:
    src = _read(WEB / "src/pages/AccountVerificationPage.tsx")
    return src.split("async function submitAsyncEvidence()", 1)[1].split("async function submitLiveRequest()", 1)[0]


def test_async_submit_waits_for_nonce_dependencies_before_next_poh_tx_batch408() -> None:
    body = _submit_async_body()

    assert "Batch 408: node admission is still sequential-nonce based" in body
    assert "waitForAccountNonceAtLeast(acct, Number(open?.env?.nonce || 0)" in body
    assert "waitForAccountNonceAtLeast(acct, Number(declare?.env?.nonce || 0)" in body
    assert body.index('tx_type: "POH_ASYNC_REQUEST_OPEN"') < body.index('tx_type: "POH_ASYNC_EVIDENCE_DECLARE"') < body.index('tx_type: "POH_ASYNC_EVIDENCE_BIND"')
    assert "Evidence was not submitted" in body
    assert "Evidence binding was not submitted" in body


def test_async_success_requires_evidence_bound_reviewable_case_batch408() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")
    body = _submit_async_body()

    assert "function asyncCaseReviewability" in page
    assert "evidenceDeclared && evidenceBound" in page
    assert "waitForAsyncCaseReviewable" in page
    # Batch 413: keep the older waitForAsyncCaseVisible compatibility wrapper,
    # but ensure it delegates to the stricter reviewable-case helper instead of
    # treating mere request-open visibility as success.
    assert "async function waitForAsyncCaseVisible" in page
    assert "const reviewability = await waitForAsyncCaseReviewable" in page
    assert "reviewability.reviewable" in body
    assert "Missing: ${missing}" in body
    assert "case is not reviewable yet" in body


def test_async_case_api_exposes_reviewability_diagnostics_batch408() -> None:
    route = _read(ROUTE)

    assert "evidence_declared: bool = False" in route
    assert "evidence_bound: bool = False" in route
    assert "reviewable: bool = False" in route
    assert "missing_steps: list[str]" in route
    assert "reviewer_queue_reason" in route
    assert '"case_opened_not_reviewable"' in route
    assert '"case_reviewable_not_assigned"' in route
    assert '"empty_queue_reason"' in route


def test_observer_reconcile_loop_backs_off_unconfirmed_rows_batch408() -> None:
    script = _read(RECONCILE)

    assert "next_reconcile_at" in script
    assert "reconcile_attempts" in script
    assert "upstream_not_confirmed" in script
    assert "rate_limited" in script
    assert "backoff = min(30.0" in script
