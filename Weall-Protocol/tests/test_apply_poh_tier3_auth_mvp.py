# tests/test_apply_poh_tier3_auth_mvp.py
from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
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


def _mk_state() -> dict:
    st = {
        "chain_id": "test",
        "height": 1,
        "accounts": {
            "alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "reputation": 0.0,
            },
        },
    }
    for i in range(1, 11):
        st["accounts"][f"j{i}"] = {
            "nonce": 0,
            "poh_tier": 3,
            "banned": False,
            "locked": False,
            "reputation": 0.9,
        }
    return st


def _open_tier3_case(st: dict) -> str:
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
    return case_id


def _assign_jurors(st: dict, case_id: str, jurors: list[str]) -> None:
    m2 = apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": jurors},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_TIER3_INIT",
        ),
    )
    assert m2 and m2["applied"] == "POH_TIER3_JUROR_ASSIGN"


def test_tier3_attendance_mark_requires_signer_matches_juror_id() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    # Attendance now requires accept first
    apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ACCEPT",
            {"case_id": case_id, "ts_ms": 9},
            signer="j2",
            nonce=4,
        ),
    )

    # j1 tries to mark attendance for j2 -> forbidden
    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {
                    "case_id": case_id,
                    "juror_id": "j2",
                    "attended": True,
                    "session_commitment": "sc:1",
                    "ts_ms": 10,
                },
                signer="j1",
                nonce=5,
            ),
        )

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "juror_signer_mismatch"

    # Self-mark is allowed (after accept)
    m = apply_tx(
        st,
        _env(
            "POH_TIER3_ATTENDANCE_MARK",
            {
                "case_id": case_id,
                "juror_id": "j2",
                "attended": True,
                "session_commitment": "sc:1",
                "ts_ms": 11,
            },
            signer="j2",
            nonce=6,
        ),
    )
    assert m and m["applied"] == "POH_TIER3_ATTENDANCE_MARK"


def test_tier3_verdict_submit_requires_interacting_juror() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    # j4 is observing (since first 3 are interacting)
    # Attendance now requires accept first
    apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ACCEPT",
            {"case_id": case_id, "ts_ms": 19},
            signer="j4",
            nonce=4,
        ),
    )

    # j4 can attend
    apply_tx(
        st,
        _env(
            "POH_TIER3_ATTENDANCE_MARK",
            {
                "case_id": case_id,
                "juror_id": "j4",
                "attended": True,
                "session_commitment": "sc:1",
                "ts_ms": 20,
            },
            signer="j4",
            nonce=5,
        ),
    )

    # but cannot submit verdict (observing)
    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env(
                "POH_TIER3_VERDICT_SUBMIT",
                {"case_id": case_id, "verdict": "pass", "session_commitment": "sc:1", "ts_ms": 21},
                signer="j4",
                nonce=6,
            ),
        )

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "interacting_juror_required"


def test_tier3_juror_assign_rejects_non_tier3_juror() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)

    st["accounts"]["j7"]["poh_tier"] = 2  # not eligible

    with pytest.raises(ApplyError) as ei:
        _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "juror_not_tier3"


def test_tier3_juror_assign_rejects_banned_or_locked_juror() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)

    st["accounts"]["j5"]["banned"] = True

    with pytest.raises(ApplyError) as ei:
        _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "juror_banned"

    # locked
    st = _mk_state()
    case_id = _open_tier3_case(st)
    st["accounts"]["j5"]["locked"] = True

    with pytest.raises(ApplyError) as ei2:
        _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    assert ei2.value.code == "invalid_tx"
    assert ei2.value.reason == "juror_locked"


def test_tier3_juror_assign_rejects_subject_as_juror() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)

    jurors = [f"j{i}" for i in range(1, 10)] + [
        "alice"
    ]  # subject included (alice is being verified)
    st["accounts"]["alice"]["poh_tier"] = 3  # even if tier3, still disallowed

    with pytest.raises(ApplyError) as ei:
        _assign_jurors(st, case_id, jurors)

    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "subject_cannot_be_juror"
