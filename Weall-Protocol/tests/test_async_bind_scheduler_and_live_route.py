from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
WEB = OUTER / "web" / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_async_scheduler_waits_for_evidence_bind_before_assignment_batch422() -> None:
    scheduler = _read(ROOT / "src/weall/runtime/poh/async_scheduler.py")
    apply_poh = _read(ROOT / "src/weall/runtime/apply/poh.py")

    assert "POH_ASYNC_EVIDENCE_BIND has succeeded" in scheduler
    assert "POH_ASYNC_EVIDENCE_BIND has succeeded" in apply_poh
    scheduler_fn = scheduler.split("def _case_has_evidence", 1)[1].split("def _case_needs_assign", 1)[0]
    assert "evidence_binds" in scheduler_fn
    assert "evidence_commitments" not in scheduler_fn


def test_async_case_diagnostics_do_not_stick_finalized_cases_on_missing_bind_batch422() -> None:
    route = _read(ROOT / "src/weall/api/routes_public_parts/poh.py")
    page = _read(WEB / "pages/AccountVerificationPage.tsx")

    assert "final_or_reviewed" in route
    assert 'reviewer_queue_reason = "finalized"' in route
    assert "reviewer_restricted_raw" in route
    assert "finalOrReviewed" in page
    assert "This verification case has been finalized on-chain." in page


def test_live_request_routes_to_expected_room_when_tx_status_lags_batch422() -> None:
    page = _read(WEB / "pages/AccountVerificationPage.tsx")
    body = page.split("async function submitLiveRequest()", 1)[1].split("const asyncSubmitCheck", 1)[0]

    assert "expectedLiveCaseIdFromNonce" in body
    assert "maxWaitMs: txVisible ? 30_000 : 5_000" in body
    assert "!txVisible && !visibleCaseId && !expectedCaseId" in body
    assert "case_id: visibleCaseId || expectedCaseId" in body
    assert 'nav(`/verification/live/${encodeURIComponent(visibleCaseId)}`)' in body


def test_live_juror_cases_alias_removed_for_direct_protocol_batch626() -> None:
    route = _read(ROOT / "src/weall/api/routes_public_parts/poh.py")
    api = _read(WEB / "api/weall.ts")

    assert '"/poh/live/juror-cases"' in route
    assert "legacy_endpoint_removed" in route
    assert "pohLiveJurorCases" not in api
    assert "'/v1/poh/live/assigned'" in api
