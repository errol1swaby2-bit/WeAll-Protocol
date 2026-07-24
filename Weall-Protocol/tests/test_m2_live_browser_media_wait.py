from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent
HELPERS = OUTER / "web/tests/e2e/m2_actor_helpers.ts"
LIVE_SPEC = OUTER / "web/tests/e2e/poh_live_independent_browsers.spec.ts"
LAUNCHER = OUTER / "scripts/run_m2_live_browser_e2e.sh"


def test_live_media_wait_has_dedicated_bounded_default() -> None:
    text = HELPERS.read_text(encoding="utf-8")
    assert "DEFAULT_M2_LOCAL_MEDIA_TIMEOUT_MS = 120_000" in text
    assert "WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS" in text
    assert "Math.max(30_000, Math.floor(parsed))" in text


def test_live_media_wait_uses_local_video_src_object() -> None:
    text = HELPERS.read_text(encoding="utf-8")
    assert "export async function waitForLiveLocalMedia" in text
    assert 'getByTestId("live-local-video")' in text
    assert "Boolean(node.srcObject)" in text
    assert "expect.poll" in text
    assert "timeout: timeoutMs" in text


def test_live_media_wait_reports_p2p_and_room_diagnostics() -> None:
    text = HELPERS.read_text(encoding="utf-8")
    assert 'getByTestId("live-p2p-status")' in text
    assert 'locator(".errorText").last()' in text
    assert "local media did not become ready within" in text
    assert "status=${" in text
    assert "error=${" in text


def test_live_browser_spec_uses_wait_for_applicant() -> None:
    text = LIVE_SPEC.read_text(encoding="utf-8")
    assert "waitForLiveLocalMedia" in text
    assert 'waitForLiveLocalMedia(applicant.page, "applicant")' in text


def test_live_browser_spec_uses_wait_for_each_reviewer() -> None:
    text = LIVE_SPEC.read_text(encoding="utf-8")
    assert "waitForLiveLocalMedia(actor.page, `reviewer ${reviewer.account}`)" in text
    assert text.count("waitForLiveLocalMedia(") == 2


def test_live_launcher_exports_media_timeout_to_playwright() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    assert 'WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS="${WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS:-120000}"' in text
    assert "npm run test:m2-live-independent-browsers" in text
    assert text.index("WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS") < text.index("npm run test:m2-live-independent-browsers")
