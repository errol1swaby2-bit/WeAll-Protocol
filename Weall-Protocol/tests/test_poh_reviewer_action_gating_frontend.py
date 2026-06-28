from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"


def _read(rel: str) -> str:
    return (WEB / rel).read_text(encoding="utf-8")


def test_reviewer_dashboard_hides_async_decisions_until_acceptance() -> None:
    page = _read("pages/JurorDashboard.tsx")

    assert "showAsyncAcceptControls" in page
    assert "showAsyncDecisionControls" in page
    assert "asyncCaseAcceptedBy" in page
    assert "asyncCaseReviewedBy" in page
    assert "Decision controls appear after you accept the review assignment." in page

    accept_gate_idx = page.index("showAsyncAcceptControls ?")
    decision_gate_idx = page.index("showAsyncDecisionControls ?")
    assert accept_gate_idx < decision_gate_idx


def test_reviewer_dashboard_hides_live_verdicts_until_check_in() -> None:
    page = _read("pages/JurorDashboard.tsx")

    assert "showLiveAcceptControls" in page
    assert "showLiveCheckInControl" in page
    assert "showLiveDecisionControls" in page
    assert "Open WebRTC room to check in" in page
    assert "Verdict controls appear after you join the live review and attendance is recorded on-chain." in page
    assert "Mark absent" not in page

    join_idx = page.index("showLiveAcceptControls ?")
    checkin_idx = page.index("showLiveCheckInControl ?")
    decision_idx = page.index("showLiveDecisionControls ?")
    assert join_idx < checkin_idx < decision_idx


def test_live_room_hides_verdict_buttons_until_can_vote() -> None:
    page = _read("pages/LiveVerificationRoom.tsx")

    assert "Approve/reject controls appear only after the join action is reflected as accepted attendance on-chain" in page
    assert page.count("{canVote ? (") >= 2
    assert "disabled={!canVote || !!busy}" not in page


def test_feed_finish_setup_keeps_signed_user_on_setup_path() -> None:
    feed = _read("pages/Feed.tsx")
    onboarding = _read("lib/onboarding.ts")

    assert "weall.account(acct, base)" in feed
    assert "weall.accountRegistered(acct, base)" in feed
    assert "accountView," in feed
    assert "registrationView," in feed
    assert 'route: "/verification"' in onboarding
    assert 'label: "Finish account setup"' in onboarding
    not_registered_idx = onboarding.index('stage = "not_registered"')
    verification_route_idx = onboarding.index('route: "/verification"', not_registered_idx)
    next_stage_idx = onboarding.index('stage = "tier0"')
    assert not_registered_idx < verification_route_idx < next_stage_idx
