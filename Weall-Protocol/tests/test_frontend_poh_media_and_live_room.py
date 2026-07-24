from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def test_frontend_has_decentralized_p2p_live_room_transport_only_copy() -> None:
    live_room = (OUTER / "web/src/lib/liveRoom.ts").read_text(encoding="utf-8")
    account_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_page = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")
    env_example = (OUTER / "web/.env.example").read_text(encoding="utf-8")

    assert "VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE" in live_room
    assert "p2p-webrtc" in live_room
    assert "weall-live-" in live_room
    assert "transport only" in live_room
    assert "liveRoomUrlFromCommitment" in account_page
    assert "liveRoomUrlFromCommitment" in juror_page
    assert "VITE_WEALL_LIVE_ROOM_BASE_URL" in env_example


def test_frontend_async_evidence_payload_includes_reviewable_video_reference() -> None:
    account_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_page = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")
    encrypted_viewer = (OUTER / "web/src/components/EncryptedEvidenceViewer.tsx").read_text(encoding="utf-8")
    evidence_crypto = (OUTER / "web/src/auth/evidenceCrypto.ts").read_text(encoding="utf-8")
    api = (OUTER / "web/src/api/weall.ts").read_text(encoding="utf-8")

    for marker in (
        "encryptEvidenceBlob",
        "ciphertext_cid",
        "ciphertext_commitment",
        "key_envelope_commitments",
        "encrypted_fresh_recorded_video_v1",
    ):
        assert marker in account_page

    assert "reviewable_evidence" in juror_page
    assert "evidence_commitments" in juror_page
    assert "ciphertext_cid" in juror_page
    assert 'item.ciphertext_cid || item.encrypted_blob_cid' in juror_page
    assert 'item.ciphertext_commitment || item.encrypted_blob_commitment || item.evidence_commitment' in juror_page
    assert 'item?.ciphertext_cid || item?.encrypted_blob_cid' in juror_page
    assert "EncryptedEvidenceViewer" in juror_page
    for marker in (
        "unwrapEvidenceKeyForRecipient",
        "decryptEvidenceCiphertext",
        "evidence_ciphertext_commitment_mismatch",
        "evidence_key_envelope_commitment_mismatch",
    ):
        assert marker in evidence_crypto
    for marker in (
        "ciphertextCid",
        "key_envelope_commitments",
        "Decrypt restricted evidence",
        "URL.revokeObjectURL",
    ):
        assert marker in encrypted_viewer
    assert "pohLiveMyCases" in api
    assert "/v1/poh/live/my-cases" in api
