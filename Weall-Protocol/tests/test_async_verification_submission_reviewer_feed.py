from __future__ import annotations

from pathlib import Path

from weall.runtime.tx_schema import validate_tx_envelope


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"
BACKEND = ROOT / "Weall-Protocol" / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_async_evidence_declare_schema_accepts_encrypted_video_metadata() -> None:
    env = {
        "chain_id": "weall-controlled-devnet",
        "tx_type": "POH_ASYNC_EVIDENCE_DECLARE",
        "signer": "@errol",
        "nonce": 6,
        "payload": {
            "case_id": "pohasync:errol:challenge1",
            "evidence_id": "async-evidence:challenge1",
            "evidence_commitment": "commit:video",
            "response_commitment": "commit:response",
            "encrypted": True,
            "encryption_algorithm": "aes-256-gcm",
            "ciphertext_cid": "bafyvideo",
            "ciphertext_commitment": "a" * 64,
            "encryption_context_commitment": "b" * 64,
            "provider_ids": ["@provider"],
            "ciphertext_size": 12345,
            "kind": "encrypted_fresh_recorded_video_v1",
            "note": "fresh_1_to_2_minute_in_app_recording",
            "ts_ms": 0,
        },
        "parent": "tx:open",
        "sig": "sig",
    }

    envelope, payload = validate_tx_envelope(env)

    assert envelope.tx_type == "POH_ASYNC_EVIDENCE_DECLARE"
    assert payload is not None
    assert getattr(payload, "encrypted") is True
    assert getattr(payload, "encryption_algorithm") == "aes-256-gcm"
    assert getattr(payload, "ciphertext_cid") == "bafyvideo"
    assert getattr(payload, "ciphertext_commitment") == "a" * 64
    assert getattr(payload, "provider_ids") == ["@provider"]


def test_account_verification_submits_native_async_tx_sequence() -> None:
    page = _read(WEB / "pages" / "AccountVerificationPage.tsx")

    assert "beginNonceSequence" in page
    assert "submitSignedTxInSequence" in page
    assert 'tx_type: "POH_ASYNC_REQUEST_OPEN"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_DECLARE"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_BIND"' in page
    assert "encrypted_fresh_recorded_video_v1" in page
    assert "ciphertext_cid" in page
    assert "ciphertext_commitment" in page
    assert "encryption_context_commitment" in page
    assert "reconcileVerificationLevel(account, 1, base)" in page


def test_reviewer_feed_surfaces_native_async_reviewable_evidence() -> None:
    page = _read(WEB / "pages" / "JurorDashboard.tsx")
    api = _read(WEB / "api" / "weall.ts")
    route = _read(BACKEND / "weall" / "api" / "routes_public_parts" / "poh.py")

    assert "weall.pohAsyncJurorCases" in page
    assert "weall.pohAsyncCase" in page
    assert "reviewable_evidence" in page
    assert "MediaGallery" in page
    assert '"/v1/poh/async/juror-cases"' in api
    assert '"/poh/async/case/{case_id}"' in route
    assert "reviewable_evidence" in route
