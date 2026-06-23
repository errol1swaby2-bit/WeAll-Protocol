from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web" / "src"


def _read(rel: str) -> str:
    return (WEB / rel).read_text(encoding="utf-8")


def test_live_room_check_in_starts_p2p_media_and_surfaces_remote_diagnostics_batch426() -> None:
    page = _read("pages/LiveVerificationRoom.tsx")

    assert "async function ensureP2PRoomStarted" in page
    assert "Join / check in + start media" in page
    assert "await ensureP2PRoomStarted();" in page
    assert "Expected participants:" in page
    assert "Remote feeds:" in page
    assert "p2pSignalsSent" in page
    assert "p2pSignalsReceived" in page
    assert "chainParticipants.forEach" in page
    assert "presence.forEach" in page


def test_create_post_has_group_destination_selector_and_group_payload_batch426() -> None:
    page = _read("pages/CreatePostPage.tsx")

    assert "type ComposerGroupOption" in page
    assert "normalizeComposerGroup" in page
    assert "refreshGroupOptions" in page
    assert "api.groups.list({ limit: 250 }" in page
    assert "<select" in page
    assert "Public feed" in page
    assert "setVisibility(nextGroupId ? \"group\" : \"public\")" in page
    assert "visibility: composerGroupId ? \"group\" : visibility" in page
    assert "group_id: composerGroupId || null" in page
    assert "Choose a group above to route it into a group feed." in page


def test_messaging_surface_is_public_only_redirect_batch426() -> None:
    page = _read("pages/Messaging.tsx")

    assert "PRIVATE_MESSAGING_UNSUPPORTED" in page
    assert "Open activity" in page
    assert "loadMessages(opts?: { silent?: boolean })" not in page
    assert "window.setInterval" not in page


def test_batch447_live_room_renders_waiting_remote_tiles_and_fast_polls() -> None:
    page = _read("pages/LiveVerificationRoom.tsx")

    assert "missingRemoteAccounts" in page
    assert "Waiting for media from" in page
    assert "window.setTimeout(() => void pollWebRTCSignals(), 750)" in page
    assert "waiting {missingRemoteAccounts.length}" in page


def test_batch447_messaging_key_autopublish_removed_by_public_only_rule() -> None:
    page = _read("pages/Messaging.tsx")

    assert "PRIVATE_MESSAGING_UNSUPPORTED" in page
    assert "autoPublishAttemptedRef" not in page
    assert "publishMessagingEncryptionKey({ silent: true })" not in page
    assert "Retry key setup" not in page


def test_batch447_appeal_controls_are_creator_only_in_dispute_detail() -> None:
    page = _read("pages/DisputeDetail.tsx")

    assert "appealActorEligible" in page
    assert "Creator-only action" in page
    assert "Reviewers can inspect appeal history" in page
    assert "reviewer accounts do not get the filing control" in page
