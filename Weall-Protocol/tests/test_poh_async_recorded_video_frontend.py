from __future__ import annotations

from pathlib import Path

OUTER = Path(__file__).resolve().parents[2]
WEB = OUTER / "web"
BACKEND = OUTER / "Weall-Protocol"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_tier1_async_frontend_requires_fresh_recorded_video_batch285() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")
    helpers = _read(WEB / "src/lib/verificationEvidence.ts")

    assert "Fresh video required" in page
    assert "ordinary file upload is not allowed for basic human review evidence" in page
    assert "Record inside WeAll" in page
    assert "MediaRecorder" in page
    assert "navigator.mediaDevices?.getUserMedia" in page
    assert "ASYNC_VIDEO_MIN_SECONDS = 60" in helpers
    assert "ASYNC_VIDEO_MAX_SECONDS = 120" in helpers
    assert "The verification video must be at least 1 minute long." in helpers
    assert "The verification video must be no more than 2 minutes long." in helpers


def test_tier1_async_frontend_uses_challenge_phrase_and_required_speech_batch285() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")
    helpers = _read(WEB / "src/lib/verificationEvidence.ts")

    assert "Challenge phrase" in page
    assert "Read aloud" in page
    assert "Something about yourself" in page
    assert "Why are you joining WeAll?" in page
    assert "My handle is" in helpers
    assert "I am recording this for async human review" in helpers
    assert "Start a fresh verification challenge before recording." in helpers


def test_tier1_async_frontend_submits_native_poh_async_tx_sequence_batch285() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")

    assert 'tx_type: "POH_ASYNC_REQUEST_OPEN"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_DECLARE"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_BIND"' in page
    assert "challenge_commitment" in page
    assert "response_commitment" in page
    assert "evidence_commitment" in page
    assert "fresh_recorded_video_v1" in page


def test_tier1_async_video_upload_is_dedicated_and_fail_closed_batch285() -> None:
    api = _read(WEB / "src/api/weall.ts")
    route = _read(BACKEND / "src/weall/api/routes_public_parts/poh.py")

    assert "pohAsyncVideoUpload" in api
    assert "/v1/poh/async/evidence/video/upload" in api
    assert '"/poh/async/evidence/video/upload"' in route
    assert "WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD" in route
    assert "WEALL_POH_ASYNC_VIDEO_MAX_BYTES" in route
    assert "video_file_required" in route
    assert "endpoint_disabled" in route


def test_tier1_async_chain_state_avoids_raw_video_submission_batch285() -> None:
    page = _read(WEB / "src/pages/AccountVerificationPage.tsx")

    open_payload_block = page.split('tx_type: "POH_ASYNC_REQUEST_OPEN"', 1)[1].split("parent:", 1)[0]
    declare_payload_block = page.split('tx_type: "POH_ASYNC_EVIDENCE_DECLARE"', 1)[1].split("parent:", 1)[0]

    assert "video_cid" not in open_payload_block
    assert "gateway_url" not in open_payload_block
    assert "video_cid" not in declare_payload_block
    assert "gateway_url" not in declare_payload_block
    assert "Assigned reviewers may view this evidence only for account verification" in page
    assert "Public chain state should store commitments and receipts, not raw video." in page
