from __future__ import annotations

from pathlib import Path

OUTER = Path(__file__).resolve().parents[2]
WEB = OUTER / "web"
BACKEND = OUTER / "Weall-Protocol"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_native_async_api_routes_exist_batch286() -> None:
    route = _read(BACKEND / "src/weall/api/routes_public_parts/poh.py")

    assert '"/poh/async/my-cases"' in route
    assert '"/poh/async/juror-cases"' in route
    assert '"/poh/async/case/{case_id}"' in route
    assert '"/poh/async/tx/juror-accept"' in route
    assert '"/poh/async/tx/juror-decline"' in route
    assert '"/poh/async/tx/review"' in route
    assert 'tx_type="POH_ASYNC_REVIEW_SUBMIT"' in route
    assert 'tx_type="POH_TIER2_REVIEW_SUBMIT"' in route  # legacy compatibility remains isolated


def test_account_verification_tracks_native_async_cases_batch286() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")

    assert "weall.pohAsyncMyCases" in page
    assert "Your async verification case is visible." in page
    assert "basic human review evidence" in page
    assert "Tier 1 evidence" not in page


def test_reviewer_dashboard_uses_native_async_routes_batch286() -> None:
    page = _read(WEB / "src/pages/JurorDashboard.tsx")

    assert "weall.pohAsyncJurorCases" in page
    assert "weall.pohAsyncCase" in page
    assert "weall.pohAsyncTxJurorAccept" in page
    assert "weall.pohAsyncTxJurorDecline" in page
    assert "weall.pohAsyncTxReview" in page
    assert "weall.pohTier2JurorCases" not in page
    assert "weall.pohTier2Case" not in page
    assert "weall.pohTier2TxReview" not in page
