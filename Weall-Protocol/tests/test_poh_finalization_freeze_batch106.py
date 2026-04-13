from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    *,
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


def _base_accounts() -> dict:
    accounts = {
        "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0},
    }
    for i in range(1, 13):
        accounts[f"j{i}"] = {
            "nonce": 0,
            "poh_tier": 3,
            "banned": False,
            "locked": False,
            "reputation": 0.9,
        }
    return accounts


def _mk_state() -> dict:
    return {"chain_id": "test", "height": 1, "accounts": _base_accounts(), "poh": {}}


def test_tier2_review_submit_rejects_after_finalize() -> None:
    st = _mk_state()
    case_id = "tier2-case"
    st["poh"]["tier2_cases"] = {
        case_id: {
            "case_id": case_id,
            "status": "finalized",
            "jurors": {"j1": {"accepted": True, "verdict": "pass"}},
        }
    }

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "POH_TIER2_REVIEW_SUBMIT",
                {"case_id": case_id, "verdict": "fail", "ts_ms": 10},
                signer="j1",
                nonce=1,
            ),
        )
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "case_finalized"


def test_tier3_attendance_mark_rejects_after_finalize() -> None:
    st = _mk_state()
    case_id = "tier3-case-a"
    st["poh"]["tier3_cases"] = {
        case_id: {
            "case_id": case_id,
            "status": "awarded",
            "session_commitment": "sc:1",
            "jurors": {
                "j1": {"role": "interacting", "accepted": True, "attended": False},
            },
        }
    }

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {
                    "case_id": case_id,
                    "juror_id": "j1",
                    "attended": True,
                    "session_commitment": "sc:1",
                    "ts_ms": 11,
                },
                signer="j1",
                nonce=1,
            ),
        )
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "case_finalized"


def test_tier3_verdict_submit_rejects_after_finalize() -> None:
    st = _mk_state()
    case_id = "tier3-case-b"
    st["poh"]["tier3_cases"] = {
        case_id: {
            "case_id": case_id,
            "status": "rejected",
            "session_commitment": "sc:1",
            "jurors": {
                "j1": {"role": "interacting", "accepted": True, "attended": True, "verdict": "pass"},
            },
        }
    }

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "POH_TIER3_VERDICT_SUBMIT",
                {"case_id": case_id, "verdict": "fail", "session_commitment": "sc:1", "ts_ms": 12},
                signer="j1",
                nonce=1,
            ),
        )
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "case_finalized"
