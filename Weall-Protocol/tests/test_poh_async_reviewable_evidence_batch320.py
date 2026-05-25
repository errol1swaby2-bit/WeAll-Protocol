from __future__ import annotations

from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, payload: dict, signer: str, nonce: int) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=None,
        system=False,
    )


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 12,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
        },
        "poh": {},
        "params": {"poh": {"async_expiry_window_blocks": 100}},
    }


def test_async_evidence_declare_stores_reviewable_video_reference_without_granting_tier() -> None:
    st = _state()
    opened = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": "@alice",
                "case_id": "case:@alice:1",
                "challenge_id": "prompt:1",
                "challenge_commitment": "commit:challenge",
                "response_commitment": "commit:response",
            },
            signer="@alice",
            nonce=1,
        ),
    )
    assert opened["applied"] == "POH_ASYNC_REQUEST_OPEN"

    declared = apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            {
                "case_id": "case:@alice:1",
                "evidence_id": "evidence:video:1",
                "evidence_commitment": "commit:video",
                "response_commitment": "commit:response",
                "kind": "fresh_recorded_video_v1",
                "public_evidence_id": "ipfs://bafyvideo",
                "evidence_cid": "bafyvideo",
                "uri": "ipfs://bafyvideo",
                "mime": "video/webm",
                "name": "poh_async_video.webm",
                "size": 12345,
                "video_commitment": "commit:video",
            },
            signer="@alice",
            nonce=2,
        ),
    )
    assert declared["applied"] == "POH_ASYNC_EVIDENCE_DECLARE"

    case = st["poh"]["async_cases"]["case:@alice:1"]
    rec = case["evidence_commitments"]["evidence:video:1"]
    assert rec["kind"] == "fresh_recorded_video_v1"
    assert "evidence_cid" not in rec
    assert "mime" not in rec
    assert case["public_evidence_ids"] == []
    assert case["reviewable_evidence"] == {}
    private = case["reviewer_private_evidence"]["evidence:video:1"]
    assert private["evidence_cid"] == "bafyvideo"
    assert private["mime"] == "video/webm"
    assert private["uri"] == "ipfs://bafyvideo"
    assert st["accounts"]["@alice"]["poh_tier"] == 0
