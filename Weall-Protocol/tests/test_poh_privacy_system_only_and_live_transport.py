from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent="p:0" if system else None,
        system=system,
    )


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False},
            "@juror": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "poh": {},
        "params": {
            "poh": {
                "async_n_jurors": 1,
                "async_min_reviews": 1,
                "async_approval_threshold": 1,
                "async_rejection_threshold": 1,
                "live_pass_threshold_num": 1,
                "live_pass_threshold_den": 1,
            }
        },
    }


def _open_async(st: dict) -> str:
    result = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            "@alice",
            1,
            {"account_id": "@alice", "challenge_commitment": "a" * 64, "response_commitment": "b" * 64},
        ),
    )
    return str(result["case_id"])


def test_async_restricted_evidence_option_b_public_state_redacts_uri_batch404() -> None:
    st = _state()
    case_id = _open_async(st)

    apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            "@alice",
            2,
            {
                "case_id": case_id,
                "evidence_id": "ev1",
                "evidence_commitment": "c" * 64,
                "response_commitment": "d" * 64,
                "uri": "ipfs://bafybeigdyrzt",
                "video_commitment": "e" * 64,
            },
        ),
    )

    case = st["poh"]["async_cases"][case_id]
    assert case["public_evidence_ids"] == []
    assert case["reviewable_evidence"] == {}
    assert case["evidence_commitments"]["ev1"]["evidence_commitment"] == "c" * 64
    assert "uri" not in case["evidence_commitments"]["ev1"]
    assert case["reviewer_restricted_evidence"]["ev1"]["uri"] == "ipfs://bafybeigdyrzt"


@pytest.mark.parametrize(
    "tx_type,payload",
    [
        ("POH_ASYNC_JUROR_ASSIGN", {"case_id": "case-1", "jurors": ["@juror"]}),
        ("POH_ASYNC_FINALIZE", {"case_id": "case-1"}),
        ("POH_ASYNC_RECEIPT", {"case_id": "case-1"}),
        ("POH_LIVE_SESSION_INIT", {"case_id": "case-1", "account_id": "@alice", "session_commitment": "a" * 64}),
        ("POH_LIVE_FINALIZE", {"case_id": "case-1"}),
        ("POH_LIVE_RECEIPT", {"case_id": "case-1"}),
    ],
)
def test_poh_scheduler_lifecycle_txs_are_system_only_batch404(tx_type: str, payload: dict) -> None:
    st = _state()
    with pytest.raises(ApplyError) as raised:
        apply_tx(st, _env(tx_type, "@alice", 99, payload, system=False))
    assert raised.value.reason == "system_only"


def test_bad_commitment_format_is_rejected_batch404() -> None:
    st = _state()
    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_REQUEST_OPEN",
                "@alice",
                1,
                {"account_id": "@alice", "challenge_commitment": "https://example.test/raw-video"},
            ),
        )
    assert raised.value.reason == "bad_commitment_format"


def test_live_session_init_schema_has_case_binding_fields_batch404() -> None:
    from weall.runtime.tx_schema import PohLiveSessionInitPayload

    payload = PohLiveSessionInitPayload(
        case_id="poh_live:@alice:1",
        account_id="@alice",
        session_commitment="a" * 64,
        room_commitment="b" * 64,
        prompt_commitment="c" * 64,
        device_pairing_commitment="d" * 64,
        relay_commitment="e" * 64,
    )
    assert payload.case_id == "poh_live:@alice:1"
    assert payload.room_commitment == "b" * 64
