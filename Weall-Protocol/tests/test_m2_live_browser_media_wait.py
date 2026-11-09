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
    # A stream object alone is insufficient evidence of live camera video.
    assert "stream instanceof MediaStream" in text
    assert 'stream.getVideoTracks().some((track) => track.readyState === "live")' in text
    assert "Boolean(node.srcObject)" not in text
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


def test_reciprocal_live_media_requires_specific_connected_peer_and_decoded_frame() -> None:
    helpers = HELPERS.read_text(encoding="utf-8")
    spec = LIVE_SPEC.read_text(encoding="utf-8")
    room = (OUTER / "web/src/pages/LiveVerificationRoom.tsx").read_text(encoding="utf-8")

    assert "data-remote-account={peer}" in room
    assert (
        'data-peer-connection-state={peerConnectionsRef.current.get(peer)?.connectionState || "unknown"}'
        in room
    )
    assert "if (!p2pRemoteAccounts.includes(from)) return;" in room
    assert "const refreshCanonicalCase = async" in room
    assert "nextCase?.case_id === caseId" in room
    assert "if (!allowedPeers.has(peer)) resetPeerConnection(peer);" in room
    assert "if (!isFinal) return;" in room
    assert 'setP2pStatus("Verification concluded; live media stopped")' in room
    assert "window.setInterval(() => void refreshCanonicalCase(), 4000)" in room
    peer_source = room.split("const p2pParticipantAccounts = useMemo", 1)[1].split(
        "const p2pRemoteAccounts = useMemo", 1
    )[0]
    assert "chainParticipants.forEach" not in peer_source
    assert "presence.forEach" not in peer_source

    assert 'tile?.getAttribute("data-peer-connection-state") !== "connected"' in helpers
    assert 'item.getAttribute("data-remote-account") === account' in helpers
    assert 'track.readyState === "live" && !track.muted' in helpers
    assert "element.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA" in helpers
    assert "element.videoWidth > 0" in helpers
    assert "element.videoHeight > 0" in helpers
    assert 'waitForLiveRemoteMedia(applicant.page, "applicant", reviewer.account)' in spec
    assert "waitForLiveRemoteMedia(actor.page" in spec
    assert spec.index(
        "All independent browsers receive peer video before reviewers vote"
    ) < spec.index("Reviewer submits verdict after two-way live media")


def test_live_launcher_exports_media_timeout_to_playwright() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    assert 'WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS="${WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS:-120000}"' in text
    assert "npm run test:m2-live-independent-browsers" in text
    assert text.index("WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS") < text.index(
        "npm run test:m2-live-independent-browsers"
    )
