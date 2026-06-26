from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
WEB = WORKSPACE / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dispute_review_fetches_detail_with_session_headers_batch390() -> None:
    src = _read(WEB / "src" / "pages" / "DisputeReview.tsx")

    assert "const headers = account ? getAuthHeaders(account) : undefined;" in src
    assert "weall.dispute(id, apiBase, headers)" in src
    assert "weall.disputeVotes(id, apiBase, headers)" in src
    assert "current_juror" in _read(WEB / "src" / "lib" / "disputeSurface.ts")
    assert "viewer_juror" in _read(WEB / "src" / "lib" / "disputeSurface.ts")
    assert "juror_self" in _read(WEB / "src" / "lib" / "disputeSurface.ts")


def test_account_verification_opens_visible_live_room_after_request_batch390() -> None:
    src = _read(WEB / "src" / "pages" / "AccountVerificationPage.tsx")

    assert "waitForLiveCaseIdVisible" in src
    assert "weall.pohLiveMyCases(acct, base, headers)" in src
    assert "nav(`/verification/live/${encodeURIComponent(visibleCaseId)}`)" in src


def test_local_rehearsal_sets_one_reviewer_live_quorum_batch390() -> None:
    src = _read(ROOT / "scripts" / "devnet_local_two_frontend_rehearsal.sh")

    assert src.count("WEALL_POH_LIVE_MIN_REP_MILLI") >= 2
    assert src.count("WEALL_POH_LIVE_PASS_THRESHOLD_NUM") >= 2
    assert src.count("WEALL_POH_LIVE_PASS_THRESHOLD_DEN") >= 2
    assert src.count("WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED") >= 2
    assert src.count("WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT") >= 2


def test_executor_maps_live_rehearsal_env_into_genesis_params_batch390() -> None:
    src = _read(ROOT / "src" / "weall" / "runtime" / "executor.py")

    assert '"live_min_rep_milli": "WEALL_POH_LIVE_MIN_REP_MILLI"' in src
    assert '"live_pass_threshold_num": "WEALL_POH_LIVE_PASS_THRESHOLD_NUM"' in src
    assert '"live_pass_threshold_den": "WEALL_POH_LIVE_PASS_THRESHOLD_DEN"' in src
    assert '"live_partial_until_height": "WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT"' in src
    assert "WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED" in src
    assert 'poh_params["live_partial_panels_enabled"] = True' in src
