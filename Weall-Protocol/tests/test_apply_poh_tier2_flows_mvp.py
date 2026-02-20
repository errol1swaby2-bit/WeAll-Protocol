# tests/test_apply_poh_tier2_flows_mvp.py
from __future__ import annotations

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
    # Receipt-only SYSTEM txs must carry a parent. For tests, default to a deterministic stub.
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


def test_poh_tier2_happy_path_majority_pass_upgrades_to_tier2() -> None:
    st = {
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0},
            "j1": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 0.9},
            "j2": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 0.9},
            "j3": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 0.9},
        }
    }

    m0 = apply_tx(st, _env("POH_TIER2_REQUEST_OPEN", {"account_id": "alice", "video_cid": "cid:vid"}, signer="alice", nonce=1))
    assert m0 and m0["applied"] == "POH_TIER2_REQUEST_OPEN"
    case_id = str(m0["case_id"])

    m1 = apply_tx(
        st,
        _env(
            "POH_TIER2_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["j1", "j2", "j3"]},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )
    assert m1 and m1["applied"] == "POH_TIER2_JUROR_ASSIGN"

    apply_tx(st, _env("POH_TIER2_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 1}, signer="j1", nonce=1))
    apply_tx(st, _env("POH_TIER2_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 1}, signer="j2", nonce=1))
    apply_tx(st, _env("POH_TIER2_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 1}, signer="j3", nonce=1))

    apply_tx(st, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "pass"}, signer="j1", nonce=2))
    apply_tx(st, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "pass"}, signer="j2", nonce=2))
    apply_tx(st, _env("POH_TIER2_REVIEW_SUBMIT", {"case_id": case_id, "verdict": "fail"}, signer="j3", nonce=2))

    m2 = apply_tx(
        st,
        _env(
            "POH_TIER2_FINALIZE",
            {"case_id": case_id, "ts_ms": 2},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_TIER2_REVIEW_SUBMIT",
        ),
    )
    assert m2 and m2["applied"] == "POH_TIER2_FINALIZE"
    assert m2["outcome"] == "pass"
    assert int(m2["tier_awarded"]) == 2

    assert int(st["accounts"]["alice"]["poh_tier"]) == 2
    assert st["poh"]["tier2_cases"][case_id]["status"] == "awarded"
