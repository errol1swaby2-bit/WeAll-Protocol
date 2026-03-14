# tests/test_apply_poh_tier3_replacement_e2e_mvp.py
from __future__ import annotations

from weall.runtime.domain_apply import apply_tx
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


def _mk_state() -> dict:
    st = {
        "chain_id": "test",
        "height": 1,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0},
        },
    }
    # 12 Tier-3 jurors so we can replace one.
    for i in range(1, 13):
        st["accounts"][f"j{i}"] = {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 0.9}
    return st


def test_tier3_decline_then_replace_then_finalize_awards_tier3() -> None:
    st = _mk_state()

    # Open request for Tier3 (user tx)
    m0 = apply_tx(
        st,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "target_tier": 3},
            signer="alice",
            nonce=1,
        ),
    )
    assert m0 and m0["applied"] == "POH_TIER2_REQUEST_OPEN"
    case_id = str(m0["case_id"])

    # System init (receipt)
    m1 = apply_tx(
        st,
        _env(
            "POH_TIER3_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "sc:1", "ts_ms": 1},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )
    assert m1 and m1["applied"] == "POH_TIER3_INIT"

    # Assign 10 jurors j1..j10 (system receipt)
    m2 = apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": [f"j{i}" for i in range(1, 11)]},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_TIER3_INIT",
        ),
    )
    assert m2 and m2["applied"] == "POH_TIER3_JUROR_ASSIGN"

    # j1 (interacting) declines
    m3 = apply_tx(st, _env("POH_TIER3_JUROR_DECLINE", {"case_id": case_id, "ts_ms": 10}, signer="j1", nonce=4))
    assert m3 and m3["applied"] == "POH_TIER3_JUROR_DECLINE"

    # System replaces j1 with j11 (preserve role interacting)
    m4 = apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_REPLACE",
            {"case_id": case_id, "old_juror_id": "j1", "new_juror_id": "j11"},
            signer="SYSTEM",
            nonce=5,
            system=True,
            parent="POH_TIER3_JUROR_DECLINE",
        ),
    )
    assert m4 and m4["applied"] == "POH_TIER3_JUROR_REPLACE"

    # All current jurors accept.
    # Interacting: j2, j3, j11
    # Observing: j4..j10
    nonce = 6
    for jid in ["j2", "j3", "j11"] + [f"j{i}" for i in range(4, 11)]:
        m = apply_tx(st, _env("POH_TIER3_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 20}, signer=jid, nonce=nonce))
        assert m and m["applied"] == "POH_TIER3_JUROR_ACCEPT"
        nonce += 1

    # Attendance:
    # - replaced old juror j1 already has attended=False set by replace
    # - everyone else self-marks attended=True
    for jid in ["j2", "j3", "j11"] + [f"j{i}" for i in range(4, 11)]:
        m = apply_tx(
            st,
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {"case_id": case_id, "juror_id": jid, "attended": True, "session_commitment": "sc:1", "ts_ms": 30},
                signer=jid,
                nonce=nonce,
            ),
        )
        assert m and m["applied"] == "POH_TIER3_ATTENDANCE_MARK"
        nonce += 1

    # Interacting jurors submit verdicts (2-of-3 pass => pass)
    for jid in ["j2", "j3", "j11"]:
        m = apply_tx(
            st,
            _env(
                "POH_TIER3_VERDICT_SUBMIT",
                {"case_id": case_id, "verdict": "pass", "session_commitment": "sc:1", "ts_ms": 40},
                signer=jid,
                nonce=nonce,
            ),
        )
        assert m and m["applied"] == "POH_TIER3_VERDICT_SUBMIT"
        nonce += 1

    # System finalize (receipt)
    mfin = apply_tx(
        st,
        _env(
            "POH_TIER3_FINALIZE",
            {"case_id": case_id, "ts_ms": 50},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent="POH_TIER3_VERDICT_SUBMIT",
        ),
    )
    assert mfin and mfin["applied"] == "POH_TIER3_FINALIZE"
    assert mfin["outcome"] == "pass"
    assert int(mfin["tier_awarded"]) == 3
    assert str(mfin.get("token_id") or "")

    # State assertions
    assert int(st["accounts"]["alice"]["poh_tier"]) == 3

    case = st["poh"]["tier3_cases"][case_id]
    assert case["status"] == "awarded"
    assert case["outcome"] == "pass"
    assert int(case["tier_awarded"]) == 3

    # Replacement record was set
    assert case["jurors"]["j1"]["replaced"] is True
    assert case["jurors"]["j1"]["replaced_by"] == "j11"
    assert case["jurors"]["j1"].get("attended") is False
    assert case["jurors"]["j11"]["role"] == "interacting"
