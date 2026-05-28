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


def test_messaging_thread_auto_refreshes_and_polls_after_send_batch426() -> None:
    page = _read("pages/Messaging.tsx")

    assert "loadMessages(opts?: { silent?: boolean })" in page
    assert "loadingMessagesRef" in page
    assert "window.setInterval" in page
    assert "mode === \"thread\" ? 2500 : 5000" in page
    assert "entityTypes: [\"account\", \"message\"]" in page
    assert "await sleep(650)" in page
    assert "await loadMessages({ silent: true })" in page
    assert "Auto-refresh" in page


def test_batch447_live_room_renders_waiting_remote_tiles_and_fast_polls() -> None:
    page = _read("pages/LiveVerificationRoom.tsx")

    assert "missingRemoteAccounts" in page
    assert "Waiting for media from" in page
    assert "window.setTimeout(() => void pollWebRTCSignals(), 750)" in page
    assert "waiting {missingRemoteAccounts.length}" in page


def test_batch447_messaging_auto_publishes_encryption_key_before_send() -> None:
    page = _read("pages/Messaging.tsx")

    assert "autoPublishAttemptedRef" in page
    assert "publishMessagingEncryptionKey({ silent: true })" in page
    assert "Encrypted messaging is being prepared" in page
    assert "Retry key setup" in page


def test_batch447_appeal_controls_are_creator_only_in_dispute_detail() -> None:
    page = _read("pages/DisputeDetail.tsx")

    assert "appealActorEligible" in page
    assert "Creator-only action" in page
    assert "Reviewers can inspect appeal history" in page
    assert "reviewer accounts do not get the filing control" in page
