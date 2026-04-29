from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def _state() -> dict:
    return {
        "chain_id": "test",
        "params": {
            "poh": {
                "tier2_n_jurors": 3,
                "tier2_min_total_reviews": 3,
                "tier2_pass_threshold": 2,
                "tier2_fail_max": 1,
            }
        },
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0},
            "bob": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0},
            "charlie": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "reputation": 0},
            "j1": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1},
            "j2": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1},
            "j3": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1},
            "j_bad": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 1},
        },
    }


def _reason(exc: BaseException) -> str:
    return str(getattr(exc, "reason", ""))


def test_tier2_request_is_subject_owned() -> None:
    st = _state()

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REQUEST_OPEN",
                {"account_id": "bob", "video_commitment": "cmt:bob"},
                signer="alice",
                nonce=1,
            ),
        )

    assert _reason(raised.value) == "subject_signer_mismatch"
    assert "poh" not in st or not st.get("poh", {}).get("tier2_cases")


def test_tier2_request_requires_existing_tier1_subject() -> None:
    st = _state()

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REQUEST_OPEN",
                {"account_id": "charlie", "video_commitment": "cmt:charlie"},
                signer="charlie",
                nonce=1,
            ),
        )

    assert _reason(raised.value) == "tier2_request_requires_tier1"


def test_tier2_video_commitment_cannot_be_replayed_across_accounts() -> None:
    st = _state()

    m0 = apply_tx(
        st,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:shared"},
            signer="alice",
            nonce=1,
        ),
    )
    assert m0 and m0["case_id"] == "poh2:alice:1"

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REQUEST_OPEN",
                {"account_id": "bob", "video_commitment": "cmt:shared"},
                signer="bob",
                nonce=1,
            ),
        )

    assert _reason(raised.value) == "evidence_commitment_replayed"
    assert st["poh"]["evidence_commitment_index"]["cmt:shared"]["case_id"] == "poh2:alice:1"


def test_tier2_assignment_rejects_self_and_non_tier3_jurors() -> None:
    st = _state()
    m0 = apply_tx(
        st,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:assignment"},
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(m0["case_id"])

    with pytest.raises(Exception) as self_review:
        apply_tx(
            st,
            _env(
                "POH_TIER2_JUROR_ASSIGN",
                {
                    "case_id": case_id,
                    "jurors": ["alice", "j1", "j2"],
                    "n_jurors": 3,
                    "min_total_reviews": 3,
                    "pass_threshold": 2,
                    "fail_max": 1,
                },
                signer="SYSTEM",
                system=True,
                nonce=2,
                parent="POH_TIER2_REQUEST_OPEN",
            ),
        )
    assert _reason(self_review.value) == "juror_self_review_forbidden"

    with pytest.raises(Exception) as bad_juror:
        apply_tx(
            st,
            _env(
                "POH_TIER2_JUROR_ASSIGN",
                {
                    "case_id": case_id,
                    "jurors": ["j1", "j2", "j_bad"],
                    "n_jurors": 3,
                    "min_total_reviews": 3,
                    "pass_threshold": 2,
                    "fail_max": 1,
                },
                signer="SYSTEM",
                system=True,
                nonce=3,
                parent="POH_TIER2_REQUEST_OPEN",
            ),
        )
    assert _reason(bad_juror.value) == "juror_not_tier3"


def test_tier2_review_rechecks_active_tier3_after_assignment() -> None:
    st = _state()
    m0 = apply_tx(
        st,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:review"},
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(m0["case_id"])

    apply_tx(
        st,
        _env(
            "POH_TIER2_JUROR_ASSIGN",
            {
                "case_id": case_id,
                "jurors": ["j1", "j2", "j3"],
                "n_jurors": 3,
                "min_total_reviews": 3,
                "pass_threshold": 2,
                "fail_max": 1,
            },
            signer="SYSTEM",
            system=True,
            nonce=2,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )

    st["accounts"]["j1"]["poh_tier"] = 2

    with pytest.raises(Exception) as raised:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REVIEW_SUBMIT",
                {"case_id": case_id, "verdict": "pass"},
                signer="j1",
                nonce=1,
            ),
        )

    assert _reason(raised.value) == "juror_not_tier3"
