from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str,
    nonce: int,
    *,
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
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False},
            "j1": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j2": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "j3": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "poh": {},
        "params": {
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_expiry_window_blocks": 100,
            }
        },
    }


def _open_async_case(st: dict) -> str:
    opened = apply_tx(
        st,
        _env(
            "POH_ASYNC_REQUEST_OPEN",
            {
                "account_id": "alice",
                "challenge_id": "prompt:1",
                "challenge_commitment": "commit:challenge:1",
            },
            signer="alice",
            nonce=1,
        ),
    )
    assert opened and opened["applied"] == "POH_ASYNC_REQUEST_OPEN"
    return str(opened["case_id"])




def _declare_async_evidence(st: dict, case_id: str, *, nonce: int = 2) -> None:
    declared = apply_tx(
        st,
        _env(
            "POH_ASYNC_EVIDENCE_DECLARE",
            {
                "case_id": case_id,
                "evidence_id": "evi:threshold",
                "evidence_commitment": "commit:evidence:threshold",
                "response_commitment": "commit:response:threshold",
            },
            signer="alice",
            nonce=nonce,
        ),
    )
    assert declared and declared["applied"] == "POH_ASYNC_EVIDENCE_DECLARE"

def test_async_threshold_policy_is_fixed_at_case_open() -> None:
    st = _state()
    case_id = _open_async_case(st)
    case = st["poh"]["async_cases"][case_id]

    assert case["assigned_juror_count"] == 3
    assert case["minimum_reviews"] == 3
    assert case["approval_threshold"] == 2
    assert case["rejection_threshold"] == 2

    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_JUROR_ASSIGN",
                {
                    "case_id": case_id,
                    "jurors": ["j1", "j2", "j3"],
                    "min_reviews": 1,
                    "approval_threshold": 1,
                    "rejection_threshold": 1,
                },
                signer="SYSTEM",
                nonce=2,
                system=True,
                parent="POH_ASYNC_REQUEST_OPEN",
            ),
        )

    assert raised.value.reason == "async_threshold_override_forbidden"
    assert raised.value.details["fields"] == ["min_reviews", "approval_threshold", "rejection_threshold"]
    assert case["minimum_reviews"] == 3
    assert case["approval_threshold"] == 2
    assert case["rejection_threshold"] == 2
    assert case["assigned_jurors"] == []


def test_async_threshold_policy_from_chain_state_must_be_coherent() -> None:
    st = _state()
    st["params"]["poh"]["async_n_jurors"] = 3
    st["params"]["poh"]["async_min_reviews"] = 4

    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_REQUEST_OPEN",
                {"account_id": "alice", "challenge_commitment": "commit:challenge:bad"},
                signer="alice",
                nonce=1,
            ),
        )

    assert raised.value.reason == "invalid_async_poh_threshold_policy"
    assert raised.value.details["assigned_jurors"] == 3
    assert raised.value.details["minimum_reviews"] == 4
    assert "async_cases" not in st.get("poh", {})


def test_async_finalize_revalidates_stored_threshold_policy() -> None:
    st = _state()
    case_id = _open_async_case(st)
    _declare_async_evidence(st, case_id, nonce=2)
    apply_tx(
        st,
        _env(
            "POH_ASYNC_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_ASYNC_EVIDENCE_DECLARE",
        ),
    )

    case = st["poh"]["async_cases"][case_id]
    case["minimum_reviews"] = 4

    with pytest.raises(ApplyError) as raised:
        apply_tx(
            st,
            _env(
                "POH_ASYNC_FINALIZE",
                {"case_id": case_id},
                signer="SYSTEM",
                nonce=4,
                system=True,
                parent="POH_ASYNC_JUROR_ASSIGN",
            ),
        )

    assert raised.value.reason == "invalid_async_poh_threshold_policy"
    assert raised.value.details["case_id"] == case_id
    assert case["status"] == "assigned"
