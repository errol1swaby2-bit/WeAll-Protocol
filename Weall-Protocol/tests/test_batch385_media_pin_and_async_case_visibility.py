from __future__ import annotations

import re
from pathlib import Path

from weall.runtime.tx_schema import validate_tx_envelope


ROOT = Path(__file__).resolve().parents[2]
NESTED = ROOT / "Weall-Protocol"
WEB = ROOT / "web" / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_ipfs_pin_request_payload_rejects_file_hash_commitment_batch385() -> None:
    """IPFS_PIN_REQUEST must stay schema-clean; media hash commits belong elsewhere."""

    env = {
        "chain_id": "weall-controlled-devnet",
        "tx_type": "IPFS_PIN_REQUEST",
        "signer": "@devnet-genesis",
        "nonce": 7,
        "payload": {
            "cid": "bafybeigdyrzt5sfp7udm7hu76p3m5zzm7wqpy2q6ol4edlm43xa5m5a7zu",
            "size_bytes": 1234,
        },
        "parent": None,
        "sig": "sig",
    }

    envelope, payload = validate_tx_envelope(env)

    assert envelope.tx_type == "IPFS_PIN_REQUEST"
    assert getattr(payload, "cid") == env["payload"]["cid"]
    assert getattr(payload, "size_bytes") == 1234


def test_media_upload_suggested_pin_envelope_does_not_put_sha256_in_pin_payload_batch385() -> None:
    media = _read(NESTED / "src" / "weall" / "api" / "routes_public_parts" / "media.py")
    suggested = re.search(r"suggested_env\s*=\s*\{(?P<body>.*?)\n\s*\}\n\s*pin_request\[\"envelope\"\]", media, re.S)
    assert suggested, "media upload should build a suggested pin envelope"
    body = suggested.group("body")
    payload = re.search(r'"payload"\s*:\s*\{(?P<payload>.*?)\n\s*\}', body, re.S)
    assert payload, "suggested IPFS_PIN_REQUEST should contain a payload object"
    assert '"cid"' in payload.group("payload")
    assert '"size_bytes"' in payload.group("payload")
    assert "sha256" not in payload.group("payload")


def test_create_post_sanitizes_legacy_pin_payload_before_submit_batch385() -> None:
    page = _read(WEB / "pages" / "CreatePostPage.tsx")

    assert "function schemaSafePinRequestPayload" in page
    assert "const pinPayload = schemaSafePinRequestPayload(pinEnvelope.payload || {}, cid);" in page
    assert "sha256" not in re.search(
        r"function schemaSafePinRequestPayload\(.*?\n\}",
        page,
        re.S,
    ).group(0)


def test_async_verification_waits_for_case_visibility_between_tx_steps_batch385() -> None:
    page = _read(WEB / "pages" / "AccountVerificationPage.tsx")

    assert "async function waitForSubmittedTxVisible" in page
    assert "async function waitForAsyncCaseVisible" in page
    assert "Batch 400: keep the native async evidence sequence contiguous" in page
    assert 'tx_type: "POH_ASYNC_REQUEST_OPEN"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_DECLARE"' in page
    assert 'tx_type: "POH_ASYNC_EVIDENCE_BIND"' in page
    assert "const boundCaseVisible = await waitForAsyncCaseVisible(acct, caseId, base, headers" in page
    assert "Async verification evidence was submitted, but the reviewable case is not visible yet" in page
