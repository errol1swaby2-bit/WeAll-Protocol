from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "alice",
    nonce: int = 1,
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


def _state(juror_count: int = 12) -> dict:
    accounts = {
        "alice": {
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
            "reputation_milli": 0,
        }
    }
    for i in range(1, juror_count + 1):
        accounts[f"j{i}"] = {
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
            "reputation_milli": 5000,
        }
    return {
        "chain_id": "test",
        "height": 1,
        "tip": "d" * 64,
        "accounts": accounts,
        "params": {
            "poh": {
                "live_min_rep_milli": 0,
                "live_pass_threshold_num": 2,
                "live_pass_threshold_den": 3,
            }
        },
    }


def _open_case(st: dict) -> str:
    m0 = apply_tx(
        st,
        _env(
            "POH_LIVE_REQUEST_OPEN",
            {
                "account_id": "alice",
                "session_commitment": "sc:1",
                "room_commitment": "room:1",
                "prompt_commitment": "prompt:1",
            },
            signer="alice",
            nonce=1,
        ),
    )
    assert m0 and m0["applied"] == "POH_LIVE_REQUEST_OPEN"
    case_id = str(m0["case_id"])
    m1 = apply_tx(
        st,
        _env(
            "POH_LIVE_SESSION_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "sc:1", "ts_ms": 1},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_LIVE_REQUEST_OPEN",
        ),
    )
    assert m1 and m1["applied"] == "POH_LIVE_SESSION_INIT"
    return case_id


def _assign(st: dict, case_id: str, jurors: list[str]) -> dict:
    m = apply_tx(
        st,
        _env(
            "POH_LIVE_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": jurors},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_LIVE_SESSION_INIT",
        ),
    )
    assert m and m["applied"] == "POH_LIVE_JUROR_ASSIGN"
    return dict(m.get("live_quorum") or {})


def _active_vote(st: dict, case_id: str, juror_id: str, verdict: str, nonce: int) -> int:
    apply_tx(
        st,
        _env("POH_LIVE_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": nonce}, signer=juror_id, nonce=nonce),
    )
    nonce += 1
    apply_tx(
        st,
        _env(
            "POH_LIVE_ATTENDANCE_MARK",
            {"case_id": case_id, "juror_id": juror_id, "attended": True, "session_commitment": "sc:1", "ts_ms": nonce},
            signer=juror_id,
            nonce=nonce,
        ),
    )
    nonce += 1
    apply_tx(
        st,
        _env(
            "POH_LIVE_VERDICT_SUBMIT",
            {"case_id": case_id, "verdict": verdict, "session_commitment": "sc:1", "ts_ms": nonce},
            signer=juror_id,
            nonce=nonce,
        ),
    )
    return nonce + 1


def _finalize(st: dict, case_id: str, nonce: int) -> dict:
    m = apply_tx(
        st,
        _env(
            "POH_LIVE_FINALIZE",
            {"case_id": case_id, "ts_ms": nonce},
            signer="SYSTEM",
            nonce=nonce,
            system=True,
            parent="POH_LIVE_VERDICT_SUBMIT",
        ),
    )
    assert m and m["applied"] == "POH_LIVE_FINALIZE"
    return dict(m)


def test_live_quorum_bootstraps_from_one_juror() -> None:
    st = _state(juror_count=1)
    case_id = _open_case(st)
    quorum = _assign(st, case_id, ["j1"])

    assert quorum["juror_count"] == 1
    assert quorum["active_reviewers"] == 1
    assert quorum["watching_observers"] == 0
    assert quorum["required_passes"] == 1

    nonce = _active_vote(st, case_id, "j1", "pass", 4)
    final = _finalize(st, case_id, nonce)

    assert final["outcome"] == "pass"
    assert final["tier_awarded"] == 2
    assert final["live_quorum"]["actual_passes"] == 1


def test_live_quorum_uses_two_of_three_percentile_for_active_reviewers() -> None:
    st = _state(juror_count=3)
    case_id = _open_case(st)
    quorum = _assign(st, case_id, ["j1", "j2", "j3"])

    assert quorum["juror_count"] == 3
    assert quorum["active_reviewers"] == 3
    assert quorum["required_passes"] == 2

    nonce = 4
    nonce = _active_vote(st, case_id, "j1", "pass", nonce)
    nonce = _active_vote(st, case_id, "j2", "pass", nonce)
    nonce = _active_vote(st, case_id, "j3", "fail", nonce)
    final = _finalize(st, case_id, nonce)

    assert final["outcome"] == "pass"
    assert final["tier_awarded"] == 2
    assert final["live_quorum"]["actual_passes"] == 2
    assert final["live_quorum"]["actual_failures"] == 1


def test_live_quorum_rejects_when_percentile_not_met() -> None:
    st = _state(juror_count=3)
    case_id = _open_case(st)
    _assign(st, case_id, ["j1", "j2", "j3"])

    nonce = 4
    nonce = _active_vote(st, case_id, "j1", "pass", nonce)
    nonce = _active_vote(st, case_id, "j2", "fail", nonce)
    nonce = _active_vote(st, case_id, "j3", "fail", nonce)
    final = _finalize(st, case_id, nonce)

    assert final["outcome"] == "fail"
    assert final["tier_awarded"] == 0
    assert st["poh"]["live_cases"][case_id]["status"] == "rejected"


def test_live_quorum_allows_three_active_seven_watching_without_observer_blocking() -> None:
    st = _state(juror_count=10)
    case_id = _open_case(st)
    quorum = _assign(st, case_id, [f"j{i}" for i in range(1, 11)])

    assert quorum["juror_count"] == 10
    assert quorum["active_reviewers"] == 3
    assert quorum["watching_observers"] == 7
    assert quorum["required_passes"] == 2

    nonce = 4
    nonce = _active_vote(st, case_id, "j1", "pass", nonce)
    nonce = _active_vote(st, case_id, "j2", "pass", nonce)
    nonce = _active_vote(st, case_id, "j3", "fail", nonce)

    # Watchers may observe later, but their attendance is not part of the pass gate.
    final = _finalize(st, case_id, nonce)
    assert final["outcome"] == "pass"
    assert final["live_quorum"]["watching_observers"] == 7


def test_live_quorum_rejects_more_than_ten_jurors() -> None:
    st = _state(juror_count=11)
    case_id = _open_case(st)
    with pytest.raises(ApplyError) as ei:
        _assign(st, case_id, [f"j{i}" for i in range(1, 12)])
    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "bad_jurors"


def test_live_scheduler_bootstraps_with_partial_eligible_pool() -> None:
    st = _state(juror_count=1)
    st.setdefault("params", {})["poh"] = {
        "live_partial_panels_enabled": True,
        "live_partial_until_height": 5,
    }
    st["poh"] = {
        "live_cases": {
            "case-live-1": {
                "case_id": "case-live-1",
                "account_id": "alice",
                "status": "open",
                "session_commitment": "sc:1",
                "room_commitment": "room:1",
                "prompt_commitment": "prompt:1",
                "jurors": {},
            }
        }
    }

    enq = schedule_poh_live_system_txs(st, next_height=2)

    assert enq == 1
    queued = (st.get("system_queue") or [])[0]
    assert queued["tx_type"] == "POH_LIVE_JUROR_ASSIGN"
    assert queued["payload"]["jurors"] == ["j1"]
    assert queued["payload"]["live_quorum"]["active_reviewers"] == 1
    assert queued["payload"]["live_quorum"]["required_passes"] == 1



def test_live_scheduler_enqueues_init_and_assignment_for_requested_case_batch424() -> None:
    st = _state(juror_count=1)
    st.setdefault("params", {})["poh"] = {
        "live_partial_panels_enabled": True,
        "live_partial_until_height": 5,
    }
    st["poh"] = {
        "live_cases": {
            "case-live-1": {
                "case_id": "case-live-1",
                "account_id": "alice",
                "status": "requested",
                "session_commitment": "sc:1",
                "room_commitment": "room:1",
                "prompt_commitment": "prompt:1",
                "jurors": {},
            }
        }
    }

    enq = schedule_poh_live_system_txs(st, next_height=2)

    assert enq == 2
    queued = st.get("system_queue") or []
    assert [item["tx_type"] for item in queued] == [
        "POH_LIVE_SESSION_INIT",
        "POH_LIVE_JUROR_ASSIGN",
    ]
    assert queued[1]["parent"] == "POH_LIVE_SESSION_INIT"
    assert queued[1]["payload"]["jurors"] == ["j1"]
    assert queued[1]["payload"]["live_quorum"]["active_reviewers"] == 1


def test_live_scheduler_does_not_assign_requested_case_without_commitments_batch424() -> None:
    st = _state(juror_count=1)
    st.setdefault("params", {})["poh"] = {
        "live_partial_panels_enabled": True,
        "live_partial_until_height": 5,
    }
    st["poh"] = {
        "live_cases": {
            "case-live-1": {
                "case_id": "case-live-1",
                "account_id": "alice",
                "status": "requested",
                "session_commitment": "sc:1",
                "jurors": {},
            }
        }
    }

    enq = schedule_poh_live_system_txs(st, next_height=2)

    assert enq == 1
    queued = st.get("system_queue") or []
    assert [item["tx_type"] for item in queued] == ["POH_LIVE_SESSION_INIT"]


def test_live_scheduler_keeps_legacy_open_case_assignment_without_commitments_batch425() -> None:
    st = _state(juror_count=1)
    st.setdefault("params", {})["poh"] = {
        "live_partial_panels_enabled": True,
        "live_partial_until_height": 5,
    }
    st["poh"] = {
        "live_cases": {
            "case-live-1": {
                "case_id": "case-live-1",
                "account_id": "alice",
                "status": "open",
                "jurors": {},
            }
        }
    }

    enq = schedule_poh_live_system_txs(st, next_height=2)

    assert enq == 1
    queued = st.get("system_queue") or []
    assert [item["tx_type"] for item in queued] == ["POH_LIVE_JUROR_ASSIGN"]

def test_live_scheduler_rejects_partial_panel_after_bootstrap_sunset() -> None:
    st = _state(juror_count=1)
    st.setdefault("params", {})["poh"] = {
        "live_partial_panels_enabled": True,
        "live_partial_until_height": 1,
    }
    st["poh"] = {
        "live_cases": {
            "case-live-1": {
                "case_id": "case-live-1",
                "account_id": "alice",
                "status": "open",
                "session_commitment": "sc:1",
                "room_commitment": "room:1",
                "prompt_commitment": "prompt:1",
                "jurors": {},
            }
        }
    }

    assert schedule_poh_live_system_txs(st, next_height=2) == 0
    assert not st.get("system_queue")
