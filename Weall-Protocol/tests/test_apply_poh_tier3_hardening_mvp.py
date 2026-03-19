# tests/test_apply_poh_tier3_hardening_mvp.py
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
    for i in range(1, 13):
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


def test_tier3_assign_rejects_non_tier3_juror() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    st["accounts"]["j7"]["poh_tier"] = 2

    with pytest.raises(ApplyError) as ei:
        _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])
    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "juror_not_tier3"


def test_tier3_accept_rechecks_banned_locked() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    st["accounts"]["j2"]["locked"] = True
    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st,
            _env("POH_TIER3_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 10}, signer="j2", nonce=4),
        )
    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "juror_locked"


def test_tier3_attendance_requires_signer_match_and_accept() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    # can't mark attendance before accept
    with pytest.raises(ApplyError) as ei0:
        apply_tx(
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
                nonce=4,
            ),
        )
    assert ei0.value.code == "forbidden"
    assert ei0.value.reason == "accept_required"

    apply_tx(
        st, _env("POH_TIER3_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": 12}, signer="j2", nonce=5)
    )

    # signer mismatch forbidden
    with pytest.raises(ApplyError) as ei1:
        apply_tx(
            st,
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {
                    "case_id": case_id,
                    "juror_id": "j2",
                    "attended": True,
                    "session_commitment": "sc:1",
                    "ts_ms": 13,
                },
                signer="j1",
                nonce=6,
            ),
        )
    assert ei1.value.code == "forbidden"
    assert ei1.value.reason == "juror_signer_mismatch"

    # correct self mark ok
    m = apply_tx(
        st,
        _env(
            "POH_TIER3_ATTENDANCE_MARK",
            {
                "case_id": case_id,
                "juror_id": "j2",
                "attended": True,
                "session_commitment": "sc:1",
                "ts_ms": 14,
            },
            signer="j2",
            nonce=7,
        ),
    )
    assert m and m["applied"] == "POH_TIER3_ATTENDANCE_MARK"


def test_tier3_replace_system_only_and_keeps_role() -> None:
    st = _mk_state()
    case_id = _open_tier3_case(st)
    _assign_jurors(st, case_id, [f"j{i}" for i in range(1, 11)])

    # old juror declines
    apply_tx(
        st, _env("POH_TIER3_JUROR_DECLINE", {"case_id": case_id, "ts_ms": 20}, signer="j1", nonce=4)
    )

    # non-system replace forbidden
    with pytest.raises(ApplyError) as ei0:
        apply_tx(
            st,
            _env(
                "POH_TIER3_JUROR_REPLACE",
                {"case_id": case_id, "old_juror_id": "j1", "new_juror_id": "j11"},
                signer="alice",
                nonce=5,
            ),
        )
    assert ei0.value.code == "forbidden"
    assert ei0.value.reason == "system_only"

    # system replace ok
    m = apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_REPLACE",
            {"case_id": case_id, "old_juror_id": "j1", "new_juror_id": "j11"},
            signer="SYSTEM",
            nonce=6,
            system=True,
            parent="POH_TIER3_JUROR_DECLINE",
        ),
    )
    assert m and m["applied"] == "POH_TIER3_JUROR_REPLACE"

    # role preserved (j1 was interacting)
    case = st["poh"]["tier3_cases"][case_id]
    assert case["jurors"]["j1"]["replaced"] is True
    assert case["jurors"]["j11"]["role"] == "interacting"
